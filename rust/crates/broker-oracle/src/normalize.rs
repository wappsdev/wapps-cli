//! What "byte-equal" means for a recording.
//!
//! Two runs of the same oracle differ in what no implementation can reproduce:
//! the temp directory they ran in, the random ids and capabilities they minted,
//! and how many milliseconds a wait took. The normalizer replaces exactly those,
//! by rule, and nothing else; every other byte is compared as it was recorded.
//!
//! The rules work on text, not on a parse: a recording keeps the bytes that
//! crossed the pipe, and an MCP answer carries its JSON a second time inside a
//! string, so a key is matched at both levels (`"k":` and `\"k\":`).
//! Replacements are numbered by first occurrence within one `apply`, so a value
//! that appears twice still appears twice as the same placeholder: identity
//! survives normalization even though the value does not.

use std::collections::HashMap;

enum Rule {
    Uuids,
    Key(String),
}

/// A set of rewrite rules. Literals run first, longest first, so a path and the
/// same path behind a symlink (`/private/tmp/x` and `/tmp/x`) both collapse to
/// one placeholder; then the other rules run in the order they were added.
#[derive(Default)]
pub struct Normalizer {
    literals: Vec<(String, String)>,
    rules: Vec<Rule>,
}

impl Normalizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace every occurrence of `from` with `to`.
    pub fn literal(mut self, from: &str, to: &str) -> Self {
        self.literals.push((from.to_string(), to.to_string()));
        self
    }

    /// Replace each RFC 4122-shaped id with `<uuid-N>`.
    pub fn uuids(mut self) -> Self {
        self.rules.push(Rule::Uuids);
        self
    }

    /// Replace the value of the JSON key `name`: a string becomes
    /// `<name-N>`, a number becomes `<name>`. `null` and booleans are kept.
    pub fn key(mut self, name: &str) -> Self {
        self.rules.push(Rule::Key(name.to_string()));
        self
    }

    pub fn apply(&self, text: &str) -> String {
        let mut literals: Vec<&(String, String)> = self.literals.iter().collect();
        literals.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        let mut out = text.to_string();
        for (from, to) in literals {
            if !from.is_empty() {
                out = out.replace(from.as_str(), to);
            }
        }
        for rule in &self.rules {
            out = match rule {
                Rule::Uuids => replace_uuids(&out),
                Rule::Key(name) => replace_key(&out, name),
            };
        }
        out
    }
}

fn numbered(seen: &mut HashMap<String, usize>, value: &str) -> usize {
    let next = seen.len() + 1;
    *seen.entry(value.to_string()).or_insert(next)
}

const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
const UUID_LEN: usize = 36;

fn is_uuid(bytes: &[u8]) -> bool {
    if bytes.len() != UUID_LEN {
        return false;
    }
    let mut at = 0;
    for (i, group) in UUID_GROUPS.iter().enumerate() {
        if i > 0 {
            if bytes[at] != b'-' {
                return false;
            }
            at += 1;
        }
        if !bytes[at..at + group].iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        at += group;
    }
    true
}

fn replace_uuids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut seen = HashMap::new();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i + UUID_LEN <= bytes.len() {
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after_ok = i + UUID_LEN == bytes.len() || !bytes[i + UUID_LEN].is_ascii_alphanumeric();
        if before_ok && after_ok && is_uuid(&bytes[i..i + UUID_LEN]) {
            out.push_str(&text[copied..i]);
            let n = numbered(&mut seen, &text[i..i + UUID_LEN]);
            out.push_str(&format!("<uuid-{n}>"));
            i += UUID_LEN;
            copied = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// Where a key's value ends, and what kind it was.
enum Value {
    /// The string's contents span `start..end`; quotes are outside it.
    Str {
        start: usize,
        end: usize,
    },
    Num {
        start: usize,
        end: usize,
    },
}

fn string_end(bytes: &[u8], start: usize, escaped: bool) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if escaped {
            // Inside a JSON string that is itself inside a JSON string: the
            // closing quote is `\"`; an escaped backslash is `\\\\`.
            if bytes[i..].starts_with(b"\\\\\\\\") {
                i += 4;
                continue;
            }
            if bytes[i..].starts_with(b"\\\"") {
                return Some(i);
            }
            i += 1;
        } else {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => return Some(i),
                _ => i += 1,
            }
        }
    }
    None
}

fn value_at(bytes: &[u8], at: usize, escaped: bool) -> Option<Value> {
    let quote: &[u8] = if escaped { b"\\\"" } else { b"\"" };
    if bytes[at..].starts_with(quote) {
        let start = at + quote.len();
        let end = string_end(bytes, start, escaped)?;
        return Some(Value::Str { start, end });
    }
    let numeric = |b: u8| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E');
    if at < bytes.len() && (bytes[at].is_ascii_digit() || bytes[at] == b'-') {
        let mut end = at;
        while end < bytes.len() && numeric(bytes[end]) {
            end += 1;
        }
        return Some(Value::Num { start: at, end });
    }
    None
}

fn replace_key(text: &str, name: &str) -> String {
    let raw = format!("\"{name}\":");
    let escaped = format!("\\\"{name}\\\":");
    let bytes = text.as_bytes();
    let mut seen = HashMap::new();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let hit = if bytes[i..].starts_with(escaped.as_bytes()) {
            Some((escaped.len(), true))
        } else if bytes[i..].starts_with(raw.as_bytes()) && (i == 0 || bytes[i - 1] != b'\\') {
            Some((raw.len(), false))
        } else {
            None
        };
        let Some((len, is_escaped)) = hit else {
            i += 1;
            continue;
        };
        let after = i + len;
        match value_at(bytes, after, is_escaped) {
            Some(Value::Str { start, end }) => {
                out.push_str(&text[copied..start]);
                let n = numbered(&mut seen, &text[start..end]);
                out.push_str(&format!("<{name}-{n}>"));
                copied = end;
                i = end;
            }
            Some(Value::Num { start, end }) => {
                out.push_str(&text[copied..start]);
                out.push_str(&format!("<{name}>"));
                copied = end;
                i = end;
            }
            None => i = after,
        }
    }
    out.push_str(&text[copied..]);
    out
}
