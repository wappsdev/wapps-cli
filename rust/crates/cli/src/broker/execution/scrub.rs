//! Source-backed heuristic output masking, not execution or generic secret discovery.
//! Full outbound text is never transcript-truncated. No I/O or secret lookup occurs here.

use serde_json::Value;
use std::{error::Error, fmt};

const REDACTED: &str = "[REDACTED]";

/// No rejected input or parser diagnostic is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubError {
    InvalidJson,
}

impl fmt::Display for ScrubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid scrub JSON")
    }
}

impl Error for ScrubError {}

/// Decode structured JSON before masking: literal text matching cannot see JSON escapes.
/// Strings containing another JSON document remain strings, as in the plugin's walker.
pub fn scrub_json(value: &str, known_secrets: &[&str]) -> Result<Value, ScrubError> {
    let value = serde_json::from_str(value).map_err(|_| ScrubError::InvalidJson)?;
    Ok(walk(value, known_secrets, JsonPolicy::Value))
}

/// Source transcript bound: 8,192 UTF-16 code units per string, never finish output.
/// A cut through an astral character becomes U+FFFD; the source keeps a lone surrogate.
pub fn scrub_transcript_json_utf16_8192(
    value: &str,
    known_secrets: &[&str],
) -> Result<Value, ScrubError> {
    let value = serde_json::from_str(value).map_err(|_| ScrubError::InvalidJson)?;
    Ok(walk(value, known_secrets, JsonPolicy::Transcript))
}

/// JSON Value APIs retain scalar types and known-only key masking. Outbound text
/// also applies all five patterns to decoded keys before serialization.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonPolicy {
    Value,
    Transcript,
    OutboundText,
}

fn walk(value: Value, known_secrets: &[&str], policy: JsonPolicy) -> Value {
    match value {
        Value::String(text) => {
            let text = scrub_text(&text, known_secrets).0;
            let units = text.encode_utf16().count();
            if policy == JsonPolicy::Transcript && units > 8192 {
                Value::String(format!(
                    "{}\n[truncated, {units} bytes total]",
                    utf16_prefix(&text, 8192)
                ))
            } else {
                Value::String(text)
            }
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| walk(item, known_secrets, policy))
                .collect(),
        ),
        Value::Object(items) => Value::Object(
            items
                .into_iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    let value = if [
                        "capability",
                        "token",
                        "secret",
                        "password",
                        "authorization",
                        "credential",
                        "api_key",
                        "api-key",
                        "apikey",
                    ]
                    .iter()
                    .any(|marker| lower.contains(marker))
                    {
                        Value::String(REDACTED.to_owned())
                    } else {
                        walk(value, known_secrets, policy)
                    };
                    let key = if policy == JsonPolicy::OutboundText {
                        scrub_text(&key, known_secrets).0
                    } else {
                        mask_known(&key, known_secrets)
                    };
                    (key, value)
                })
                .collect(),
        ),
        other => other,
    }
}

fn utf16_prefix(text: &str, limit: usize) -> String {
    String::from_utf16_lossy(&text.encode_utf16().take(limit).collect::<Vec<_>>())
}

/// Plugin recordProgress's single-line 200-unit operation, after masking, not a cloud ceiling.
/// Empty normalized notes are omitted. JavaScript whitespace excludes NEL and includes BOM.
pub fn scrub_note_line_utf16_200(value: &str, known_secrets: &[&str]) -> Option<ScrubbedText> {
    let text = scrub_text(value, known_secrets);
    let mut normalized = String::with_capacity(text.0.len());
    let mut space = false;
    for c in text.0.chars() {
        if js_space(c) {
            space = !normalized.is_empty();
        } else {
            if space {
                normalized.push(' ');
                space = false;
            }
            normalized.push(c);
        }
    }
    (!normalized.is_empty()).then(|| ScrubbedText(utf16_prefix(&normalized, 200)))
}

/// Constructed only by the scrub gate. Unmatched text is not guaranteed secret-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubbedText(String);

impl ScrubbedText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Only daemon/worker-authored text belongs here, not orchestrator tasks or work items.
pub struct OutboundText<'a> {
    pub note: Option<&'a str>,
    pub finish_output: Option<&'a str>,
    pub finish_error: Option<&'a str>,
}

#[derive(Debug)]
pub struct ScrubbedOutbound {
    pub note: Option<ScrubbedText>,
    pub finish_output: Option<ScrubbedText>,
    pub finish_error: Option<ScrubbedText>,
}

/// The future outbound integration must call this before serializing or logging all three surfaces.
/// Any unsupported JSON-shaped surface rejects the whole batch, without retaining input.
pub fn scrub_outbound(
    text: OutboundText<'_>,
    known_secrets: &[&str],
) -> Result<ScrubbedOutbound, ScrubError> {
    Ok(ScrubbedOutbound {
        note: text
            .note
            .map(|value| scrub_surface(value, known_secrets))
            .transpose()?,
        finish_output: text
            .finish_output
            .map(|value| scrub_surface(value, known_secrets))
            .transpose()?,
        finish_error: text
            .finish_error
            .map(|value| scrub_surface(value, known_secrets))
            .transpose()?,
    })
}

/// The CLI's forward.rs already decodes JSON-bearing text before redaction.
/// Preserve original formatting unless a decoded value needs masking. This is one
/// JSON layer, not recursive decoding of JSON documents hidden inside JSON strings.
/// JSON-shaped means an object, array or quoted string opener after whitespace/BOM.
/// Decoder failures on that path are errors, never a weaker literal-only success.
/// Ordinary text takes the literal gate; every serialized result takes it too.
fn scrub_surface(value: &str, known_secrets: &[&str]) -> Result<ScrubbedText, ScrubError> {
    match serde_json::from_str::<Value>(value) {
        Ok(parsed) => {
            let scrubbed = walk(parsed.clone(), known_secrets, JsonPolicy::OutboundText);
            if scrubbed != parsed {
                // Numeric scalars and serialization must not bypass the full text gate.
                return Ok(scrub_text(&scrubbed.to_string(), known_secrets));
            }
        }
        Err(_)
            if value
                .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
                .starts_with(['{', '[', '"']) =>
        {
            return Err(ScrubError::InvalidJson);
        }
        Err(_) => {}
    }
    Ok(scrub_text(value, known_secrets))
}

fn mask_known(value: &str, known_secrets: &[&str]) -> String {
    let mut text = value.to_owned();
    for secret in known_secrets.iter().filter(|secret| !secret.is_empty()) {
        text = text.replace(secret, REDACTED);
    }
    text
}

/// Literal known-secret masking followed by the plugin's five patterns in source order.
pub fn scrub_text(value: &str, known_secrets: &[&str]) -> ScrubbedText {
    let mut text = mask_known(value, known_secrets);
    text = scan(&text, private_key);
    text = assignments(&text);
    text = scan(&text, bearer);
    text = scan(&text, vendor);
    ScrubbedText(opaque_runs(&text))
}

/// Match indices are byte offsets, but scanning only starts at valid UTF-8 boundaries.
fn scan(text: &str, matcher: fn(&str, usize) -> Option<(usize, String)>) -> String {
    let mut output = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, _) in text.char_indices() {
        if start < copied {
            continue;
        }
        if let Some((end, replacement)) = matcher(text, start) {
            output.push_str(&text[copied..start]);
            output.push_str(&replacement);
            copied = end;
        }
    }
    output.push_str(&text[copied..]);
    output
}

fn private_header(text: &str, start: usize, prefix: &str) -> Option<usize> {
    let rest = text.get(start..)?.strip_prefix(prefix)?;
    let dash = rest.find('-')?;
    if rest[..dash].ends_with("PRIVATE KEY") && rest[dash..].starts_with("-----") {
        Some(start + prefix.len() + dash + 5)
    } else {
        None
    }
}

fn private_key(text: &str, start: usize) -> Option<(usize, String)> {
    let body = private_header(text, start, "-----BEGIN")?;
    for (offset, _) in text[body..].match_indices("-----END") {
        if let Some(end) = private_header(text, body + offset, "-----END") {
            return Some((end, REDACTED.to_owned()));
        }
    }
    None
}

fn js_space(c: char) -> bool {
    matches!(c,
        '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' |
        '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' |
        '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn assignments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    // JavaScript multiline anchors/dot use these four terminators, not Rust's lines().
    for line in text.split_inclusive(['\n', '\r', '\u{2028}', '\u{2029}']) {
        let body = line.trim_end_matches(['\n', '\r', '\u{2028}', '\u{2029}']);
        if let Some(head) = assignment_head(body) {
            output.push_str(&body[..head]);
            output.push_str(REDACTED);
        } else {
            output.push_str(body);
        }
        output.push_str(&line[body.len()..]);
    }
    output
}

fn assignment_head(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut pos = 0;
    skip_tabs_spaces(bytes, &mut pos);
    // OD15's sole anchor widening: the start of a command in a Bash note.
    if bytes.get(pos..pos + 5)?.eq_ignore_ascii_case(b"Bash:") {
        pos += 5;
        let before = pos;
        skip_tabs_spaces(bytes, &mut pos);
        if pos == before {
            return None;
        }
    }
    if bytes
        .get(pos..pos + 6)
        .is_some_and(|part| part.eq_ignore_ascii_case(b"export"))
        && bytes
            .get(pos + 6)
            .is_some_and(|b| matches!(b, b' ' | b'\t'))
    {
        pos += 6;
        skip_tabs_spaces(bytes, &mut pos);
    }
    let key_start = pos;
    while bytes
        .get(pos)
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        pos += 1;
    }
    let key = line[key_start..pos].to_ascii_uppercase();
    if ![
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
    ]
    .iter()
    .any(|marker| key.contains(marker))
    {
        return None;
    }
    skip_tabs_spaces(bytes, &mut pos);
    if !matches!(bytes.get(pos), Some(b'=' | b':')) {
        return None;
    }
    pos += 1;
    skip_tabs_spaces(bytes, &mut pos);
    if line[pos..].chars().next().is_some_and(|c| !js_space(c)) {
        Some(pos)
    } else {
        None
    }
}

fn skip_tabs_spaces(bytes: &[u8], pos: &mut usize) {
    while matches!(bytes.get(*pos), Some(b' ' | b'\t')) {
        *pos += 1;
    }
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// JS's non-Unicode \b is ASCII, including next to non-ASCII letters.
fn boundary(bytes: &[u8], pos: usize) -> bool {
    pos.checked_sub(1).is_some_and(|i| word(bytes[i])) != bytes.get(pos).is_some_and(|b| word(*b))
}

fn bearer(text: &str, start: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if !boundary(bytes, start) {
        return None;
    }
    let keyword = ["Bearer", "Basic"].into_iter().find(|keyword| {
        bytes
            .get(start..start + keyword.len())
            .is_some_and(|part| part.eq_ignore_ascii_case(keyword.as_bytes()))
    })?;
    let head_end = start + keyword.len();
    let mut pos = head_end;
    skip_tabs_spaces(bytes, &mut pos);
    if pos == head_end {
        return None;
    }
    let token = pos;
    while bytes
        .get(pos)
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(b))
    {
        pos += 1;
    }
    (pos - token >= 8).then(|| (pos, format!("{} {REDACTED}", &text[start..head_end])))
}

fn vendor(text: &str, start: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if !boundary(bytes, start) {
        return None;
    }
    let rest = &text[start..];
    let (prefix, min, extra): (&str, usize, &[u8]) = if rest.starts_with("sk-") {
        ("sk-", 16, b"-")
    } else if rest.starts_with("ghp_") {
        ("ghp_", 20, b"")
    } else if rest.starts_with("github_pat_") {
        ("github_pat_", 20, b"_")
    } else if ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"]
        .iter()
        .any(|prefix| rest.starts_with(prefix))
    {
        (&rest[..5], 10, b"-")
    } else if rest.starts_with("AKIA") {
        let end = start + 20;
        return bytes
            .get(start + 4..end)
            .filter(|tail| {
                tail.iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .filter(|_| boundary(bytes, end))
            .map(|_| (end, REDACTED.to_owned()));
    } else {
        return None;
    };
    let token = start + prefix.len();
    let mut end = token;
    while bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || extra.contains(b))
    {
        end += 1;
    }
    while end >= token + min {
        if boundary(bytes, end) {
            return Some((end, REDACTED.to_owned()));
        }
        end -= 1;
    }
    None
}

fn opaque_runs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let (mut pos, mut copied) = (0, 0);
    while pos < bytes.len() {
        if !(word(bytes[pos]) || bytes[pos] == b'-') {
            pos += 1;
            continue;
        }
        let mut start = None;
        let mut end = pos;
        let (mut lower, mut upper, mut digit) = (false, false, false);
        // Each maximal ASCII run is visited once. Retrying every hyphen boundary
        // would scan quadratically on long nonsecret identifiers such as a-a-a-.
        while let Some(b) = bytes.get(pos).filter(|b| word(**b) || **b == b'-') {
            if word(*b) {
                start.get_or_insert(pos);
                end = pos + 1;
            }
            lower |= b.is_ascii_lowercase();
            upper |= b.is_ascii_uppercase();
            digit |= b.is_ascii_digit();
            pos += 1;
        }
        // A JS word boundary excludes leading/trailing hyphens. Once the first
        // candidate fails length or mixing, no shorter suffix can succeed.
        if let Some(start) = start.filter(|start| lower && upper && digit && end - start >= 40) {
            output.push_str(&text[copied..start]);
            output.push_str(REDACTED);
            copied = end;
        }
    }
    output.push_str(&text[copied..]);
    output
}
