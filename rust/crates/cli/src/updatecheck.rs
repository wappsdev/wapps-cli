// updatecheck, the best-effort "newer release available" notice.
//
// ORACLE: internal/updatecheck/updatecheck.go; the two gates that call it and
// the skill refresh live in main.rs (Go: cmd/root.go, after Execute).
//
// The contract, all of it Go's:
//   - Never affects the exit code; every failure is swallowed and the worst
//     outcome is no notice.
//   - The network is hit at most once per 24h; between checks the answer comes
//     from `<user cache dir>/wapps/version-check.json` — a file the Go and the
//     Rust binary SHARE. It is read with encoding/json's rules (keys folded,
//     `null` a no-op, the last key wins, the time field NOT unescaped) and
//     written with Go's bytes: `{"checked_at":<RFC3339Nano, local>,
//     "latest_version":<Go-escaped string>}` (gotime, gozone).
//   - Only a release version (a numeric triple) is eligible, so "dev" never
//     asks.
//   - Only digits and dots reach the terminal: the notice is rebuilt from the
//     parsed integers, never echoed from the server.
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

use crate::gojson;
use crate::gotime;
use crate::gozone;

/// DEFAULT_API_URL is GitHub's "latest release" endpoint for this repo.
pub const DEFAULT_API_URL: &str = "https://api.github.com/repos/wappsdev/wapps-cli/releases/latest";

/// API_URL_ENV replaces DEFAULT_API_URL when set and non-empty, in both
/// binaries. It exists for the differential: the default is HTTPS to
/// api.github.com, which no test can stand in for.
pub const API_URL_ENV: &str = "WAPPS_UPDATE_CHECK_URL";

const TTL_NS: i128 = 24 * 3600 * 1_000_000_000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
// Go's http.Client follows up to 10 redirects.
const MAX_REDIRECTS: u32 = 10;
const BODY_LIMIT: u64 = 1 << 20;

/// Semver, a parsed MAJOR.MINOR.PATCH (Go's `int`, 64-bit here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Semver {
    major: i64,
    minor: i64,
    patch: i64,
}

impl std::fmt::Display for Semver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// parse_semver, Go's ParseSemver: "vX.Y.Z" or "X.Y.Z" after trimming
/// Unicode white space, anything from the first `-` or `+` dropped.
pub fn parse_semver(s: &str) -> Option<Semver> {
    // Go's TrimSpace (unicode.IsSpace) and Rust's trim (White_Space) are the
    // same set.
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = s.find(['-', '+']).map_or(s, |i| &s[..i]);
    let parts: Vec<&str> = s.split('.').collect();
    let [a, b, c] = parts.as_slice() else {
        return None;
    };
    // No sign is left after the cut above, so i64's parser accepts exactly
    // what strconv.Atoi accepts here: ASCII digits, in range.
    let n = |p: &str| p.parse::<i64>().ok();
    Some(Semver {
        major: n(a)?,
        minor: n(b)?,
        patch: n(c)?,
    })
}

/// compare, Go's Compare: >0 if a is newer, <0 if older, 0 if equal.
pub fn compare(a: &Semver, b: &Semver) -> i64 {
    if a.major != b.major {
        return a.major - b.major;
    }
    if a.minor != b.minor {
        return a.minor - b.minor;
    }
    a.patch - b.patch
}

/// Options, one check. Production fills it from the environment
/// (`notify_from_env`); tests inject the clock, the endpoint and the zone.
pub struct Options<'a> {
    pub current_version: &'a str,
    pub api_url: &'a str,
    /// The base cache dir; the file is `<dir>/wapps/version-check.json`.
    pub cache_dir: &'a str,
    /// The clock, read twice as Go reads it: for the freshness check, and
    /// again (after the fetch) for the time written to the cache.
    pub now: &'a dyn Fn() -> (i64, u32),
    /// The TZ variable (`None`: unset) the written time's zone comes from.
    pub tz: Option<&'a str>,
}

/// maybe_notify, Go's MaybeNotify: writes the one-line upgrade notice to `w`
/// when a newer release exists. Never fails.
pub fn maybe_notify<W: Write>(w: &mut W, o: &Options<'_>) {
    let Some(current) = parse_semver(o.current_version) else {
        return;
    };
    let latest = match latest_version(o) {
        Some(l) if !l.is_empty() => l,
        _ => return,
    };
    let Some(latest) = parse_semver(&latest) else {
        return;
    };
    if compare(&latest, &current) > 0 {
        let _ = write!(
            w,
            "\n⚡ wapps {latest} is available (you have {current}). Upgrade: brew upgrade wapps\n"
        );
    }
}

/// notify_from_env, MaybeNotify as cmd/root.go calls it: this binary's
/// version, the real clock, Go's user cache dir, the endpoint from
/// API_URL_ENV or the default.
pub fn notify_from_env<W: Write>(w: &mut W) {
    let env = |k: &str| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned());
    let api_url = env(API_URL_ENV)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    let cache_dir = user_cache_dir().unwrap_or_else(|| {
        env("TMPDIR")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "/tmp".to_string())
    });
    let tz = env("TZ");
    let now = || {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (d.as_secs() as i64, d.subsec_nanos())
    };
    maybe_notify(
        w,
        &Options {
            current_version: env!("CARGO_PKG_VERSION"),
            api_url: &api_url,
            cache_dir: &cache_dir,
            now: &now,
            tz: tz.as_deref(),
        },
    );
}

/// human_notices_enabled, Go's humanNoticesEnabled: the side notices ("a new
/// version", "skill refreshed") are for a human at a terminal only. In agent
/// mode stderr carries the JSON envelope, and a stray line would break whoever
/// parses it.
pub fn human_notices_enabled(no_update_check: bool, stderr_is_tty: bool, agent: bool) -> bool {
    !no_update_check && stderr_is_tty && !agent
}

// user_cache_dir is Go's os.UserCacheDir; `None` where Go returns an error.
fn user_cache_dir() -> Option<String> {
    let env = |k: &str| {
        std::env::var_os(k)
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    if cfg!(target_os = "macos") {
        let home = env("HOME");
        return (!home.is_empty()).then(|| home + "/Library/Caches");
    }
    let xdg = env("XDG_CACHE_HOME");
    if xdg.is_empty() {
        let home = env("HOME");
        return (!home.is_empty()).then(|| home + "/.cache");
    }
    xdg.starts_with('/').then_some(xdg)
}

// latest_version: the newest release tag, from the cache while fresh, else
// fetched and cached. `None` is Go's error.
fn latest_version(o: &Options<'_>) -> Option<String> {
    let path = crate::wappsyaml::go_clean(&format!("{}/wapps/version-check.json", o.cache_dir));
    if let Some(entry) = std::fs::read(&path).ok().and_then(|d| read_cache(&d)) {
        let (sec, nsec) = (o.now)();
        let age = (sec as i128 - entry.checked_at.0 as i128) * 1_000_000_000
            + (nsec as i128 - entry.checked_at.1 as i128);
        // Go's Time.Sub saturates at the int64 range; the 24h comparison is
        // the same on the exact difference.
        if age < TTL_NS {
            return Some(entry.latest);
        }
    }
    let latest = fetch_latest(o.api_url)?;
    // Best effort: a failed write only means a fetch on the next run.
    let (sec, nsec) = (o.now)();
    write_cache(&path, sec, nsec, gozone::local_offset(o.tz, sec), &latest);
    Some(latest)
}

struct Entry {
    checked_at: (i64, u32),
    latest: String,
}

// read_cache is json.Unmarshal into Go's cacheEntry; `None` is an error.
fn read_cache(data: &[u8]) -> Option<Entry> {
    let mut e = Entry {
        checked_at: (gotime::ZERO_TIME_UNIX, 0),
        latest: String::new(),
    };
    let text = go_lossy(data);
    let Some(pairs) = gojson::decode_raw_object(text.as_bytes(), "updatecheck.cacheEntry").ok()?
    else {
        return Some(e); // a top-level `null` changes nothing
    };
    let mut type_error = false;
    for (key, raw) in pairs {
        let raw = raw.get();
        match go_fold(&key).as_str() {
            // Time.UnmarshalJSON: an error stops the whole decode.
            "CHECKED_AT" => match time_unmarshal_json(raw.as_bytes()) {
                TimeJson::Null => {}
                TimeJson::At(sec, nsec) => e.checked_at = (sec, nsec),
                TimeJson::Invalid => return None,
            },
            "LATEST_VERSION" => match raw.as_bytes()[0] {
                b'"' => e.latest = go_unquote(raw),
                b'n' => {}
                // A type error is remembered and decoding goes on.
                _ => type_error = true,
            },
            _ => {}
        }
    }
    (!type_error).then_some(e)
}

/// TimeJson, what Go's Time.UnmarshalJSON does with one raw JSON value.
#[derive(Debug, PartialEq, Eq)]
pub enum TimeJson {
    /// `null`: a no-op, the field keeps whatever it held.
    Null,
    /// The instant, unix seconds and nanoseconds.
    At(i64, u32),
    /// An error, which stops the whole decode.
    Invalid,
}

/// time_unmarshal_json, Go's Time.UnmarshalJSON on the RAW JSON value:
/// anything but `null` must be a JSON string whose bytes — NOT unescaped —
/// parse as RFC 3339.
pub fn time_unmarshal_json(raw: &[u8]) -> TimeJson {
    if raw == b"null" {
        return TimeJson::Null;
    }
    if raw.len() < 2 || raw[0] != b'"' || raw[raw.len() - 1] != b'"' {
        return TimeJson::Invalid;
    }
    match gotime::parse_rfc3339(&raw[1..raw.len() - 1]) {
        Some((sec, nsec)) => TimeJson::At(sec, nsec),
        None => TimeJson::Invalid,
    }
}

fn write_cache(path: &str, sec: i64, nsec: u32, offset: i32, latest: &str) {
    // Go's json.Marshal of the entry fails when MarshalJSON does.
    let Some(t) = gotime::rfc3339nano_json(sec, nsec, offset) else {
        return;
    };
    let Ok(latest) = gojson::to_string(&latest) else {
        return;
    };
    let dir = path.rfind('/').map_or(".", |i| &path[..i.max(1)]);
    use std::os::unix::fs::DirBuilderExt;
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .is_err()
    {
        return;
    }
    let data = format!("{{\"checked_at\":\"{t}\",\"latest_version\":{latest}}}");
    let _ = crate::atomicfile::write(std::path::Path::new(path), data.as_bytes(), 0o644);
}

// fetch_latest: GET the endpoint with GitHub's headers, demand 200, decode
// the FIRST JSON value of at most 1 MiB of body (Go's Decoder ignores what
// follows it) and return its tag_name.
fn fetch_latest(url: &str) -> Option<String> {
    let resp = ureq::AgentBuilder::new()
        .timeout(HTTP_TIMEOUT)
        .redirects(MAX_REDIRECTS)
        .build()
        .get(url)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "wapps-cli")
        .call()
        .ok()?;
    if resp.status() != 200 {
        return None;
    }
    let mut body = BufReader::new(resp.into_reader().take(BODY_LIMIT));
    let value = first_json_value(&mut body)?;
    let text = go_lossy(&value);
    let Some(pairs) =
        gojson::decode_raw_object(text.as_bytes(), "updatecheck.githubRelease").ok()?
    else {
        return Some(String::new());
    };
    let mut tag = String::new();
    let mut type_error = false;
    for (key, raw) in pairs {
        if go_fold(&key) != "TAG_NAME" {
            continue;
        }
        let raw = raw.get();
        match raw.as_bytes()[0] {
            b'"' => tag = go_unquote(raw),
            b'n' => {}
            _ => type_error = true,
        }
    }
    (!type_error).then_some(tag)
}

// first_json_value reads exactly the first JSON value from `r`, as Go's
// json.Decoder does: it stops at the value's end instead of waiting for the
// body's, so a server that sends the value and stalls is answered at once. A
// scalar ends at the first byte that cannot continue it (or EOF). The bytes
// are only DELIMITED here; serde validates them afterwards.
fn first_json_value<R: BufRead>(r: &mut R) -> Option<Vec<u8>> {
    fn next<R: BufRead>(r: &mut R) -> Option<u8> {
        let b = *r.fill_buf().ok()?.first()?;
        r.consume(1);
        Some(b)
    }
    let mut first = next(r)?;
    while matches!(first, b' ' | b'\t' | b'\n' | b'\r') {
        first = next(r)?;
    }
    let mut out = vec![first];
    match first {
        b'{' | b'[' | b'"' => {
            let mut depth = usize::from(first != b'"');
            let (mut in_str, mut esc) = (first == b'"', false);
            loop {
                let b = next(r)?;
                out.push(b);
                if in_str {
                    if esc {
                        esc = false;
                    } else if b == b'\\' {
                        esc = true;
                    } else if b == b'"' {
                        in_str = false;
                        if depth == 0 {
                            return Some(out);
                        }
                    }
                    continue;
                }
                match b {
                    b'"' => in_str = true,
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(out);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {
            while let Ok(buf) = r.fill_buf() {
                match buf.first() {
                    Some(&b) if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-') => {
                        out.push(b);
                        r.consume(1);
                    }
                    _ => break,
                }
            }
            Some(out)
        }
    }
}

// go_lossy decodes bytes as Go's JSON decoder sees them: every byte that does
// not start a valid UTF-8 sequence becomes one U+FFFD (Rust's from_utf8_lossy
// would fold a broken sequence into a single one). Outside strings such a
// byte is a syntax error either way.
fn go_lossy(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let (ok, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(ok).unwrap_or_default());
                out.push('\u{fffd}');
                rest = &bad[1..];
            }
        }
    }
    out
}

// go_fold is encoding/json's key folding for these ASCII field names: ASCII
// upper case, plus the two non-ASCII runes whose fold orbit holds an ASCII
// letter — the Kelvin sign (K) and the long s (S).
fn go_fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{212a}' => 'K',
            '\u{17f}' => 'S',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

// go_unquote is encoding/json's unquote on a VALID JSON string literal: a
// surrogate pair is joined, and a surrogate that does not pair becomes
// U+FFFD (serde_json refuses the literal instead).
fn go_unquote(raw: &str) -> String {
    let body = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(body.len());
    let mut chars = body.char_indices().peekable();
    let hex4 = |at: usize| -> Option<u32> {
        let h = body.get(at..at + 4)?;
        u32::from_str_radix(h, 16).ok()
    };
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some((_, e)) = chars.next() else { break };
        let ch = match e {
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let Some(u) = hex4(i + 2) else { break };
                for _ in 0..4 {
                    chars.next();
                }
                if (0xd800..0xe000).contains(&u) {
                    // Pair with a following \uXXXX low surrogate if there is one.
                    let low = body
                        .get(i + 6..i + 8)
                        .filter(|p| *p == "\\u")
                        .and_then(|_| hex4(i + 8))
                        .filter(|l| u < 0xdc00 && (0xdc00..0xe000).contains(l));
                    match low {
                        Some(l) => {
                            for _ in 0..6 {
                                chars.next();
                            }
                            char::from_u32(0x10000 + ((u - 0xd800) << 10) + (l - 0xdc00))
                                .unwrap_or('\u{fffd}')
                        }
                        None => '\u{fffd}',
                    }
                } else {
                    char::from_u32(u).unwrap_or('\u{fffd}')
                }
            }
            other => other, // `"`, `\`, `/`
        };
        out.push(ch);
    }
    out
}
