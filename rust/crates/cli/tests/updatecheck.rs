// The update check against a LIVE Go oracle: tests/testdata/ucoracle runs the
// real internal/updatecheck code and Go's time package on the same vectors.
//
// Why live and not frozen: half of what is compared is a time zone offset
// read from the system's zoneinfo files. Frozen expectations would go stale
// with the next tzdata update while Go and Rust still agreed; the oracle reads
// the same files the port does, so only a real divergence fails.
//
// The pty differential measures the two binaries end to end (cases.py,
// UPDATE_CASES); this file pins what it cannot reach: an injected clock (the
// 24h edge to the nanosecond, a cache written at a chosen instant), dozens of
// zones, and parser corners that would each cost a pty case.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use wapps::gobase64::{std_decode, std_encode};
use wapps::updatecheck::TimeJson;
use wapps::{gotime, gozone, updatecheck};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

// oracle runs the Go program once over `vectors` with TZ set to `tz` (None:
// unset) and returns one answer per vector.
fn oracle(tz: Option<&str>, vectors: &[Value]) -> Vec<Value> {
    let mut cmd = Command::new("go");
    cmd.args(["run", "./rust/crates/cli/tests/testdata/ucoracle"])
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match tz {
        Some(v) => cmd.env("TZ", v),
        None => cmd.env_remove("TZ"),
    };
    let mut child = cmd.spawn().expect("go run ucoracle");
    let mut input = String::new();
    for v in vectors {
        input.push_str(&v.to_string());
        input.push('\n');
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "ucoracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let answers: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(answers.len(), vectors.len(), "one answer per vector");
    answers
}

fn b64(b: &[u8]) -> String {
    std_encode(b)
}

#[test]
fn semver_parsing_and_comparison_match_go() {
    let inputs: &[&str] = &[
        "v0.12.0",
        "0.12.0",
        "v1.2.3",
        "v0.12.0-rc1",
        "v0.12.0+build5",
        "dev",
        "main-2978d52",
        "",
        "v1.2",
        "v1.2.3.4",
        "vX.Y.Z",
        "v1.-2.3",
        " v1.2.3 ",
        "\u{a0}v1.2.3\u{85}",
        "v1.2.3\n",
        "v1.2.3\u{3000}",
        "v1.2.3\u{200b}",
        "V1.2.3",
        "vv1.2.3",
        "v01.002.0003",
        "v1.2.3-",
        "v1.2-3.4",
        "v+1.2.3",
        "v1..3",
        "v9223372036854775807.0.0",
        "v9223372036854775808.0.0",
        "\u{661}.\u{662}.\u{663}",
        "v00.013.00",
        "v9.9.9\x1b[2J\x1b[H",
        "v\x1b[31m9.9.9",
        "v9.9.9\r\nFAKE",
    ];
    let vectors: Vec<Value> = inputs
        .iter()
        .map(|s| json!({"kind": "semver", "s": b64(s.as_bytes())}))
        .collect();
    let answers = oracle(Some("UTC"), &vectors);
    for (s, want) in inputs.iter().zip(&answers) {
        let got = updatecheck::parse_semver(s);
        assert_eq!(got.is_some(), want["ok"] == true, "parse_semver({s:?})");
        if let Some(v) = got {
            assert_eq!(v.to_string(), want["v"], "parse_semver({s:?}).String()");
        }
    }

    let pairs: &[(&str, &str)] = &[
        ("v1.0.0", "v0.9.9"),
        ("v0.12.0", "v0.11.1"),
        ("v0.12.1", "v0.12.0"),
        ("v0.11.1", "v0.12.0"),
        ("v0.12.0", "v0.12.0"),
        ("v2.0.0", "v1.99.99"),
        ("v0.0.9223372036854775807", "v0.0.0"),
    ];
    let vectors: Vec<Value> = pairs
        .iter()
        .map(|(a, b)| json!({"kind": "compare", "a": a, "b": b}))
        .collect();
    let answers = oracle(Some("UTC"), &vectors);
    for ((a, b), want) in pairs.iter().zip(&answers) {
        let got = updatecheck::compare(
            &updatecheck::parse_semver(a).unwrap(),
            &updatecheck::parse_semver(b).unwrap(),
        )
        .signum();
        assert_eq!(json!(got), want["sign"], "compare({a}, {b})");
    }
}

#[test]
fn the_cache_s_time_field_parses_as_go_s_unmarshal_json() {
    let raws: &[&[u8]] = &[
        b"\"2026-10-05T14:33:20Z\"",
        b"\"2026-10-05T14:33:20.123456789Z\"",
        b"\"2026-10-05T14:33:20.000000000Z\"",
        b"\"2026-10-05T14:33:20.1234567891Z\"",
        b"\"2026-10-05T14:33:20.5+03:00\"",
        b"\"2026-10-05T14:33:20-03:30\"",
        b"\"2026-10-05T14:33:20,5Z\"",
        b"\"2026-10-05T7:33:20Z\"",
        b"\"2026-10-05T7:33:20.25-01:00\"",
        b"\"2026-10-05T07:33:20Z\"",
        b"\"2026-10-05T14:33:20+24:00\"",
        b"\"2026-10-05T14:33:20-24:60\"",
        b"\"2026-10-05T14:33:20+25:00\"",
        b"\"2026-10-05T14:33:20+03:61\"",
        b"\"2024-02-29T00:00:00Z\"",
        b"\"2026-02-29T00:00:00Z\"",
        b"\"2100-02-29T00:00:00Z\"",
        b"\"2000-02-29T00:00:00Z\"",
        b"\"0000-01-01T00:00:00Z\"",
        b"\"0000-02-29T00:00:00Z\"",
        b"\"9999-12-31T23:59:59.999999999-23:59\"",
        b"\"1969-12-31T23:59:59.999999999Z\"",
        b"\"2026-10-05t14:33:20Z\"",
        b"\"2026-10-05T14:33:20z\"",
        b"\"2026-10-05T14:33:20\"",
        b"\"2026-10-05T24:00:00Z\"",
        b"\"2026-10-05T14:60:00Z\"",
        b"\"2026-10-05T14:33:60Z\"",
        b"\"2026-1-05T14:33:20Z\"",
        b"\"2026-10-5T14:33:20Z\"",
        b"\"2026-10-05T14:3:20Z\"",
        b"\"2026-10-05T14:33:2Z\"",
        b"\"2026-10-05T14:33:20.Z\"",
        b"\"2026-10-05T14:33:20.5\"",
        b"\"2026-10-05T14:33:20+0300\"",
        b"\"2026-10-05T14:33:20+03:00 \"",
        b"\"2026-10-05T14:33:20x03:00\"",
        b"\"2026-10-05T14:33:20+03:0a\"",
        b"\"2026-10-05T14:33:20+3:00\"",
        b"\" 2026-10-05T14:33:20Z\"",
        b"\"20261-10-05T14:33:20Z\"",
        b"\"-001-10-05T14:33:20Z\"",
        b"\"+026-10-05T14:33:20Z\"",
        b"\"2026-13-05T14:33:20Z\"",
        b"\"2026-00-05T14:33:20Z\"",
        b"\"2026-10-00T14:33:20Z\"",
        b"\"2026-10-32T14:33:20Z\"",
        b"\"2026-04-31T14:33:20Z\"",
        b"\"2026-10-05 14:33:20Z\"",
        b"\"2026-10-05T14:33:20ZZ\"",
        b"\"2026-10-05T14:33:20.123Z+03:00\"",
        b"\"2026\\u002d10-05T14:33:20Z\"",
        b"\"\"",
        b"\"x\"",
        b"null",
        b"123",
        b"true",
        b"{}",
        b"\"2026-10-05T14:33:20Z",
        b"2026-10-05T14:33:20Z\"",
        b"\"",
    ];
    let vectors: Vec<Value> = raws
        .iter()
        .map(|r| json!({"kind": "parse", "s": b64(r)}))
        .collect();
    let answers = oracle(Some("UTC"), &vectors);
    for (raw, want) in raws.iter().zip(&answers) {
        let shown = String::from_utf8_lossy(raw);
        let got = match updatecheck::time_unmarshal_json(raw) {
            TimeJson::Invalid => None,
            // `null` leaves Go's zero Time in the field.
            TimeJson::Null => Some((gotime::ZERO_TIME_UNIX, 0)),
            TimeJson::At(sec, nsec) => Some((sec, nsec)),
        };
        assert_eq!(got.is_some(), want["ok"] == true, "accepts {shown}");
        if let Some(t) = got {
            assert_eq!(json!([t.0, t.1]), want["t"], "instant of {shown}");
        }
    }
}

// The zones: the machine's own (TZ unset) and TZ="" / "UTC" (Go: UTC
// without a file); northern and southern DST; half- and quarter-hour offsets;
// zones whose present rule lives only in the TZif footer (no DST any more, or
// a rule with negative or >24h transition times); the Etc sign inversion;
// TZ values Go falls back to UTC for (unknown name, POSIX string, missing
// absolute path); an absolute path with and without the leading colon; a
// relative path that climbs out of the zoneinfo directory.
const ZONES: &[Option<&str>] = &[
    None,
    Some(""),
    Some("UTC"),
    Some(":UTC"),
    Some(":"),
    Some("Europe/Istanbul"),
    Some("Europe/Berlin"),
    Some("Europe/Dublin"),
    Some("America/New_York"),
    Some("America/Sao_Paulo"),
    Some("America/St_Johns"),
    Some("America/Nuuk"),
    Some("America/Scoresbysund"),
    Some("Australia/Sydney"),
    Some("Australia/Lord_Howe"),
    Some("Asia/Kolkata"),
    Some("Asia/Kathmandu"),
    Some("Asia/Tehran"),
    Some("Asia/Gaza"),
    Some("Africa/Casablanca"),
    Some("Antarctica/Troll"),
    Some("Pacific/Chatham"),
    Some("Pacific/Kiritimati"),
    Some("Etc/GMT+3"),
    Some("Etc/GMT-14"),
    Some("EST5EDT"),
    Some("Nowhere/Zone"),
    Some("XYZ-3"),
    Some("/nonexistent/zone"),
    Some("/usr/share/zoneinfo/Asia/Tokyo"),
    Some(":/usr/share/zoneinfo/Asia/Tokyo"),
    Some("../../../../etc/localtime"),
];

// The instants: now-ish; one second either side of the 2026 EU, US and
// Australian DST switches; past the last transition of every slim TZif file
// (2099, 2100: only the footer rule answers); the 32-bit time_t edge; the
// epoch; a local year that leaves [0, 9999] (Go's MarshalJSON fails); and
// nanosecond fractions that trim differently.
fn instants() -> Vec<(i64, u32)> {
    let mut v = vec![
        (1_791_200_000, 0),
        (1_791_200_000, 1),
        (1_791_200_000, 100),
        (1_791_200_000, 120_000_000),
        (1_791_200_000, 123_456_789),
        (1_791_200_000, 999_999_999),
        (0, 0),
        (2_147_483_647, 0),
        (2_147_483_648, 500),
        (4_086_000_000, 0),
        (4_102_444_800, 0),
        (4_118_000_000, 0),
        (253_402_300_799, 0),
        (253_402_214_400, 0),
        (-62_135_596_800, 0),
        (-62_167_219_200, 0),
    ];
    for t in [
        1_774_746_000, // 2026-03-29T01:00:00Z, EU spring
        1_792_890_000, // 2026-10-25T01:00:00Z, EU autumn
        1_772_953_200, // 2026-03-08T07:00:00Z, US spring
        1_793_512_800, // 2026-11-01T06:00:00Z, US autumn
        1_775_318_400, // 2026-04-04T16:00:00Z, AU autumn
        1_791_043_200, // 2026-10-03T16:00:00Z, AU spring
    ] {
        v.push((t - 1, 0));
        v.push((t, 0));
    }
    v
}

#[test]
fn the_written_time_is_go_s_json_in_every_zone() {
    let instants = instants();
    let vectors: Vec<Value> = instants
        .iter()
        .map(|(s, n)| json!({"kind": "format", "t": [s, n]}))
        .collect();
    let mut compared = 0;
    for tz in ZONES {
        let answers = oracle(*tz, &vectors);
        for ((sec, nsec), want) in instants.iter().zip(&answers) {
            let offset = gozone::local_offset(*tz, *sec);
            let got = gotime::rfc3339nano_json(*sec, *nsec, offset).map(|s| format!("\"{s}\""));
            assert_eq!(
                json!(got),
                want["json"],
                "TZ={tz:?} t=({sec}, {nsec}) offset={offset}"
            );
            compared += 1;
        }
    }
    println!(
        "zones={} instants={} compared={compared}",
        ZONES.len(),
        instants.len()
    );
}

// --- MaybeNotify, end to end with an injected clock ----------------------------

// serve answers every request on a fresh port with `status` and `body` after
// `delay_ms`, under the oracle's rule (GitHub's Accept and the wapps-cli
// User-Agent, else 400). Returns the URL and the hit counter.
fn serve(status: u16, body: Vec<u8>, delay_ms: u64) -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/releases/latest", l.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut c) = conn else { return };
            h.fetch_add(1, Ordering::SeqCst);
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&req).to_ascii_lowercase();
            let ok = head.contains("\r\naccept: application/vnd.github+json\r\n")
                && head.contains("\r\nuser-agent: wapps-cli\r\n");
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            let (st, b) = if ok {
                (status, body.as_slice())
            } else {
                (400, &b""[..])
            };
            let _ = c.write_all(
                format!(
                    "HTTP/1.1 {st} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                )
                .as_bytes(),
            );
            let _ = c.write_all(b);
        }
    });
    (url, hits)
}

struct Scenario {
    name: &'static str,
    current: &'static str,
    now: (i64, u32),
    cache: Option<Vec<u8>>,
    status: u16,
    body: Vec<u8>,
    delay_ms: u64,
}

const NOW: (i64, u32) = (1_791_200_000, 500_000_000);

fn tag(t: &str) -> Vec<u8> {
    format!("{{\"tag_name\":{}}}", serde_json::to_string(t).unwrap()).into_bytes()
}

// cache builds a cache file whose time is `ago` seconds (and `ago_ns` more
// nanoseconds) before NOW, in UTC.
fn cache_at(ago: i64, ago_ns: i64, latest: &str) -> Vec<u8> {
    let total = (NOW.0 as i128) * 1_000_000_000 + NOW.1 as i128
        - (ago as i128 * 1_000_000_000 + ago_ns as i128);
    let sec = total.div_euclid(1_000_000_000) as i64;
    let nsec = total.rem_euclid(1_000_000_000) as u32;
    let t = gotime::rfc3339nano_json(sec, nsec, 0).unwrap();
    format!("{{\"checked_at\":\"{t}\",\"latest_version\":\"{latest}\"}}").into_bytes()
}

fn scenarios() -> Vec<Scenario> {
    let s = |name, cache: Option<Vec<u8>>, status, body: Vec<u8>| Scenario {
        name,
        current: "0.23.0",
        now: NOW,
        cache,
        status,
        body,
        delay_ms: 0,
    };
    let fresh = |raw: &str| Some(raw.as_bytes().to_vec());
    let t = "2026-10-05T12:00:00Z"; // 33 min before NOW: fresh
    let mut v = vec![
        s("new release", None, 200, tag("v0.24.0")),
        s("up to date", None, 200, tag("v0.23.0")),
        s("server is older", None, 200, tag("v0.22.9")),
        s(
            "fresh cache, newer",
            Some(cache_at(3600, 0, "v0.25.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "fresh cache, current",
            Some(cache_at(3600, 0, "v0.23.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "cache exactly 24h old",
            Some(cache_at(86_400, 0, "v0.25.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "cache 24h minus 1ns old",
            Some(cache_at(86_399, 999_999_999, "v0.25.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "cache from the future",
            Some(cache_at(-7200, 0, "v0.25.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "stale cache",
            Some(cache_at(90_000, 0, "v0.25.0")),
            200,
            tag("v0.24.0"),
        ),
        s(
            "fresh cache, +03:00",
            fresh(r#"{"checked_at":"2026-10-05T15:00:00+03:00","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s("empty cache file", fresh(""), 200, tag("v0.24.0")),
        s("cache not JSON", fresh("not json"), 200, tag("v0.24.0")),
        s("cache {}", fresh("{}"), 200, tag("v0.24.0")),
        s("cache null", fresh("null"), 200, tag("v0.24.0")),
        s("cache []", fresh("[]"), 200, tag("v0.24.0")),
        s(
            "time is a number",
            fresh(r#"{"checked_at":123,"latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "time is escaped",
            fresh(r#"{"checked_at":"2026\u002d10-05T12:00:00Z","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "time with a comma fraction",
            fresh(r#"{"checked_at":"2026-10-05T12:00:00,5Z","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "time with a one-digit hour",
            fresh(r#"{"checked_at":"2026-10-05T9:00:00-03:00","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "time with a +24:00 offset",
            fresh(r#"{"checked_at":"2026-10-06T12:00:00+24:00","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "time is the string null",
            fresh(r#"{"checked_at":"null","latest_version":"v0.25.0"}"#),
            200,
            tag("v0.24.0"),
        ),
        s(
            "keys in upper case",
            fresh(&format!(
                r#"{{"CHECKED_AT":"{t}","Latest_Version":"v0.25.0"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "key with the Kelvin sign",
            fresh(&format!(
                "{{\"chec\u{212a}ed_at\":\"{t}\",\"latest_version\":\"v0.25.0\"}}"
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "key with the long s",
            fresh(&format!(
                "{{\"checked_at\":\"{t}\",\"latest_ver\u{17f}ion\":\"v0.25.0\"}}"
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "key with an escape",
            fresh(&format!(
                r#"{{"checked\u005fat":"{t}","latest_version":"v0.25.0"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "version is a number",
            fresh(&format!(r#"{{"checked_at":"{t}","latest_version":25}}"#)),
            200,
            tag("v0.24.0"),
        ),
        s(
            "version is null",
            fresh(&format!(r#"{{"checked_at":"{t}","latest_version":null}}"#)),
            200,
            tag("v0.24.0"),
        ),
        s(
            "version is empty",
            fresh(&format!(r#"{{"checked_at":"{t}","latest_version":""}}"#)),
            200,
            tag("v0.24.0"),
        ),
        s(
            "trailing garbage",
            fresh(&format!(
                r#"{{"checked_at":"{t}","latest_version":"v0.25.0"}} x"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "surrounding whitespace",
            fresh(&format!(
                " \n{{\"checked_at\":\"{t}\",\"latest_version\":\"v0.25.0\"}}\n "
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "a later null keeps the time",
            fresh(&format!(
                r#"{{"checked_at":"{t}","checked_at":null,"latest_version":"v0.25.0"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "a later bad time wins",
            fresh(&format!(
                r#"{{"checked_at":"{t}","checked_at":"x","latest_version":"v0.25.0"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "the last version wins",
            fresh(&format!(
                r#"{{"checked_at":"{t}","latest_version":"v0.26.0","latest_version":"v0.25.0"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "unknown fields",
            fresh(&format!(
                r#"{{"x":{{"y":[1,2]}},"checked_at":"{t}","latest_version":"v0.25.0","z":null}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "version with a lone surrogate",
            fresh(&format!(
                r#"{{"checked_at":"{t}","latest_version":"v0.25.0-\ud800"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "version with a lone surrogate only",
            fresh(&format!(
                r#"{{"checked_at":"{t}","latest_version":"\udc00"}}"#
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "a leading BOM",
            fresh(&format!(
                "\u{feff}{{\"checked_at\":\"{t}\",\"latest_version\":\"v0.25.0\"}}"
            )),
            200,
            tag("v0.24.0"),
        ),
        s(
            "server 500",
            None,
            500,
            b"{\"tag_name\":\"v0.24.0\"}".to_vec(),
        ),
        s("server 404", None, 404, Vec::new()),
        s("server 201", None, 201, tag("v0.24.0")),
        s("body not JSON", None, 200, b"garbage".to_vec()),
        s("body empty", None, 200, Vec::new()),
        s(
            "body truncated",
            None,
            200,
            b"{\"tag_name\":\"v0.24.0\"".to_vec(),
        ),
        s(
            "body with trailing data",
            None,
            200,
            b"{\"tag_name\":\"v0.24.0\"} trailing".to_vec(),
        ),
        s("body null", None, 200, b"null".to_vec()),
        s("tag null", None, 200, b"{\"tag_name\":null}".to_vec()),
        s(
            "tag key in upper case",
            None,
            200,
            b"{\"TAG_NAME\":\"v0.24.0\"}".to_vec(),
        ),
        s("tag is a number", None, 200, b"{\"tag_name\":24}".to_vec()),
        s("body is an array", None, 200, b"[]".to_vec()),
        s("body is a string", None, 200, b"\"v0.24.0\"".to_vec()),
        s("tag not canonical", None, 200, tag("v00.024.00")),
        s(
            "tag smuggles escapes",
            None,
            200,
            tag("v9.9.9\x1b[2J\x1b[H"),
        ),
        s(
            "tag with characters Go escapes",
            None,
            200,
            tag("v0.24.0-<&>\u{2028}\u{1}\t\u{8}\u{c}\u{7f} é"),
        ),
        s(
            "tag with invalid UTF-8",
            None,
            200,
            b"{\"tag_name\":\"v0.24.0-\xff\xf0\x9f\x98\"}".to_vec(),
        ),
        s(
            "tag with a lone surrogate",
            None,
            200,
            br#"{"tag_name":"v0.24.0-\ud83d"}"#.to_vec(),
        ),
        s(
            "tag with a surrogate pair",
            None,
            200,
            b"{\"tag_name\":\"v0.24.0-\\ud83d\\ude00\"}".to_vec(),
        ),
    ];
    let mut big = b"{\"tag_name\":\"v0.24.0\",\"x\":\"".to_vec();
    big.extend(std::iter::repeat_n(b'a', 1 << 21));
    big.extend_from_slice(b"\"}");
    v.push(s("first value past the 1 MiB cap", None, 200, big));
    let mut tail = tag("v0.24.0");
    tail.extend(std::iter::repeat_n(b'z', 1 << 21));
    v.push(s("first value inside the cap", None, 200, tail));
    for (name, current) in [
        ("dev build", "dev"),
        ("main build", "main-2978d52"),
        ("pre-release build", "v0.23.0-rc1"),
    ] {
        let mut x = s(name, None, 200, tag("v0.24.0"));
        x.current = current;
        v.push(x);
    }
    let mut slow = s("server slower than the timeout", None, 200, tag("v0.24.0"));
    slow.delay_ms = 2500;
    v.push(slow);
    let mut ns = s("clock with no fraction", None, 200, tag("v0.24.0"));
    ns.now = (NOW.0, 0);
    v.push(ns);
    v
}

#[test]
fn maybe_notify_matches_go_under_an_injected_clock() {
    let scenarios = scenarios();
    let vectors: Vec<Value> = scenarios
        .iter()
        .map(|s| {
            json!({"kind": "notify", "current": s.current, "now": [s.now.0, s.now.1],
                   "cache": s.cache.as_deref().map(b64), "status": s.status,
                   "body": b64(&s.body), "delay_ms": s.delay_ms})
        })
        .collect();
    // TZ unset: the cache is written in the machine's own zone, as a user's
    // would be.
    let answers = oracle(None, &vectors);
    let mut differ = Vec::new();
    for (s, want) in scenarios.iter().zip(&answers) {
        let dir = tempdir(s.name);
        let path = dir.join("wapps/version-check.json");
        if let Some(c) = &s.cache {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, c).unwrap();
        }
        let (url, hits) = serve(s.status, s.body.clone(), s.delay_ms);
        let mut out = Vec::new();
        updatecheck::maybe_notify(
            &mut out,
            &updatecheck::Options {
                current_version: s.current,
                api_url: &url,
                cache_dir: dir.to_str().unwrap(),
                now: &|| s.now,
                tz: None,
            },
        );
        let cache = std::fs::read(&path).ok();
        let got = json!({
            "out": String::from_utf8(out).unwrap(),
            "hits": hits.load(Ordering::SeqCst),
            "cache": cache.as_deref().map(b64),
        });
        if &got != want {
            let dec = |v: &Value| {
                v.as_str()
                    .map(|c| String::from_utf8_lossy(&std_decode(c).unwrap()).to_string())
            };
            differ.push(format!(
                "{}:\n  GO out={:?} hits={} cache={:?}\n  RS out={:?} hits={} cache={:?}",
                s.name,
                want["out"],
                want["hits"],
                dec(&want["cache"]),
                got["out"],
                got["hits"],
                dec(&got["cache"])
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!(
        "notify scenarios={} differ={}",
        scenarios.len(),
        differ.len()
    );
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "wapps-uc-{}-{}",
        std::process::id(),
        name.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
