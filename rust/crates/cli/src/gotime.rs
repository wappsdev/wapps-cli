// gotime, the Go `time` outputs the CLI prints: RFC3339 timestamps and
// `time.Duration` strings.
//
// WHY HAND-WRITTEN — the same decision as `rotateplan::rfc3339_valid`: a date
// library (chrono/time) would bring new crates into the graph, and this
// estate does not pay that for a handful of formatting calls. Unlike there,
// the RFC3339 part is a real CALENDAR computation, because `token exchange`
// prints a unix stamp from the gate to a HUMAN.
//
// Every expected byte in tests/gotime.rs was measured from Go.

/// rfc3339_utc, writes unix seconds as `YYYY-MM-DDTHH:MM:SSZ`
/// (Go's `time.Unix(n, 0).UTC().Format(time.RFC3339)`).
///
/// NEGATIVE INPUT IS NOT CARRIED, as a scope decision: the only caller is on
/// an `exp > 0` branch. Go formats negative stamps too; carrying that would
/// be a branch without a caller, and an unmeasured one. A negative input
/// saturates to the epoch instead of silently producing a wrong date.
pub fn rfc3339_utc(unix: i64) -> String {
    let secs = unix.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// civil_from_days, days since 1970-01-01 to (year, month, day).
//
// Howard Hinnant's `civil_from_days`: starting the year in MARCH puts the leap
// day at the END of the year, so month lengths fit one formula and all three
// leap-year rules (4 / 100 / 400) live in one place. A month-table loop would
// work too; this form makes it visible that the three leap-year test cases go
// through the SAME two lines.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], MARCH = 0
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// --- time.Duration ------------------------------------------------------------
//
// `wapps login` prints session lifetimes as Go `time.Duration` strings, so the
// three Go operations behind those lines are ported literally, with Go's
// wrapping and saturating integer semantics. doctorverb::go_duration is the
// whole-seconds subset of `duration_string`; it stays where it is because its
// callers never see a fraction.

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// duration_string, Go's `time.Duration.String()`.
///
/// Below one second the unit shrinks (ns, µs, ms) and keeps a fraction; from
/// one second up the form is `[h][m]s` with a seconds fraction, the hour field
/// never rolls into days, and a zero hour or minute field is omitted only
/// while every larger field is zero too ("1h0m0s", but "59m59s").
pub fn duration_string(d: i64) -> String {
    let neg = d < 0;
    let mut u = d.unsigned_abs();
    let mut out = String::new();
    if u < NANOS_PER_SEC as u64 {
        if u == 0 {
            return "0s".to_string();
        }
        let (prec, unit) = if u < 1_000 {
            (0, "ns")
        } else if u < 1_000_000 {
            (3, "µs")
        } else {
            (6, "ms")
        };
        let (frac, int) = frac_part(u, prec);
        out.push_str(&int.to_string());
        out.push_str(&frac);
        out.push_str(unit);
    } else {
        let (frac, secs) = frac_part(u, 9);
        u = secs;
        let s = u % 60;
        u /= 60;
        if u > 0 {
            let m = u % 60;
            u /= 60;
            if u > 0 {
                out.push_str(&format!("{u}h"));
            }
            out.push_str(&format!("{m}m"));
        }
        out.push_str(&format!("{s}{frac}s"));
    }
    if neg {
        out.insert(0, '-');
    }
    out
}

// frac_part, Go's fmtFrac: the `prec` low decimal digits of v as ".ddd" with
// trailing zeros dropped ("" when they are all zero), plus v / 10^prec.
fn frac_part(v: u64, prec: u32) -> (String, u64) {
    let pow = 10u64.pow(prec);
    let mut digits = format!("{:0width$}", v % pow, width = prec as usize);
    while digits.ends_with('0') {
        digits.pop();
    }
    let frac = if digits.is_empty() {
        String::new()
    } else {
        format!(".{digits}")
    };
    (frac, v / pow)
}

/// round_second, Go's `d.Round(time.Second)`: halves round away from zero,
/// and a result that would overflow saturates to the extreme instead.
pub fn round_second(d: i64) -> i64 {
    let m = NANOS_PER_SEC;
    let less_than_half = |x: i64| (x as u64).wrapping_add(x as u64) < m as u64;
    let r = d % m;
    if d < 0 {
        let r = -r;
        if less_than_half(r) {
            return d + r;
        }
        let d1 = d.wrapping_sub(m).wrapping_add(r);
        return if d1 < d { d1 } else { i64::MIN };
    }
    if less_than_half(r) {
        return d - r;
    }
    let d1 = d.wrapping_add(m).wrapping_sub(r);
    if d1 > d {
        d1
    } else {
        i64::MAX
    }
}

/// until_unix, Go's `time.Until(time.Unix(exp, 0))` with `now` given as unix
/// seconds + nanoseconds.
///
/// Go computes the difference in nanoseconds and SATURATES when it does not
/// fit an int64 (Time.Sub). A far-future expiry therefore prints as
/// 2562047h47m16.854775807s, not as a wrapped negative number.
pub fn until_unix(exp: i64, now_sec: i64, now_nsec: i64) -> i64 {
    let d = (exp as i128) * (NANOS_PER_SEC as i128)
        - (now_sec as i128 * NANOS_PER_SEC as i128 + now_nsec as i128);
    d.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

// --- time.Time in JSON: what `~/.cache/wapps/version-check.json` carries ------
//
// The update check's cache file is SHARED by the Go and the Rust binary, so
// its `checked_at` is read and written exactly as Go's encoding/json does:
// MarshalJSON is RFC3339Nano in the LOCAL zone (the offset comes from
// gozone), UnmarshalJSON is time.Parse(RFC3339) on the raw string. Still no
// date crate: the format is fixed, and every branch below is compared with
// the live Go oracle in tests/updatecheck.rs.

/// ZERO_TIME_UNIX is Go's zero `time.Time` (0001-01-01T00:00:00Z) in unix
/// seconds: what a decoded `null` leaves in the field.
pub const ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// rfc3339nano_json, the string inside `json.Marshal(t)` for the instant
/// (`sec`, `nsec`) in a zone `offset` seconds east of UTC: RFC3339Nano, the
/// fraction's trailing zeros dropped, `Z` for a zero offset. `None` where Go's
/// MarshalJSON fails: a local year outside [0, 9999], or an offset of 24
/// hours or more.
pub fn rfc3339nano_json(sec: i64, nsec: u32, offset: i32) -> Option<String> {
    let local = sec + offset as i64;
    let (y, m, d) = civil_from_days(local.div_euclid(86_400));
    if !(0..=9999).contains(&y) {
        return None;
    }
    let rem = local.rem_euclid(86_400);
    let mut out = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    if nsec != 0 {
        let digits = format!("{nsec:09}");
        out.push('.');
        out.push_str(digits.trim_end_matches('0'));
    }
    if offset == 0 {
        out.push('Z');
        return Some(out);
    }
    // Go writes the offset in whole minutes, truncated toward zero; the
    // seconds of an LMT offset are dropped.
    let mut zone = offset / 60;
    if zone < 0 {
        out.push('-');
        zone = -zone;
    } else {
        out.push('+');
    }
    if zone / 60 >= 24 {
        return None;
    }
    out.push_str(&format!("{:02}:{:02}", zone / 60, zone % 60));
    Some(out)
}

/// parse_rfc3339, Go's `time.Parse(time.RFC3339, s)` as unix (seconds,
/// nanoseconds). This is what Time.UnmarshalJSON runs: its strict RFC 3339
/// checks are disabled in Go 1.26 (go.dev/issue/54580), so the layout
/// parser's leniency is the contract — a one-digit hour, a comma before the
/// fraction, an offset up to 24:60, more than nine fraction digits
/// (truncated).
pub fn parse_rfc3339(s: &[u8]) -> Option<(i64, u32)> {
    let digit = |v: &[u8], i: usize| v.get(i).is_some_and(u8::is_ascii_digit);
    // getnum: one or two digits; `fixed` demands two.
    let getnum = |v: &[u8], fixed: bool| -> Option<(i64, usize)> {
        if !digit(v, 0) {
            return None;
        }
        if !digit(v, 1) {
            return if fixed {
                None
            } else {
                Some(((v[0] - b'0') as i64, 1))
            };
        }
        Some((((v[0] - b'0') * 10 + (v[1] - b'0')) as i64, 2))
    };
    let expect = |v: &[u8], c: u8| -> Option<usize> { (v.first() == Some(&c)).then_some(1) };

    let mut v = s;
    if v.len() < 4 || !v[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year: i64 = std::str::from_utf8(&v[..4]).ok()?.parse().ok()?;
    v = &v[4..];
    v = &v[expect(v, b'-')?..];
    let (month, n) = getnum(v, true)?;
    if !(1..=12).contains(&month) {
        return None;
    }
    v = &v[n..];
    v = &v[expect(v, b'-')?..];
    let (day, n) = getnum(v, true)?;
    v = &v[n..];
    v = &v[expect(v, b'T')?..];
    let (hour, n) = getnum(v, false)?;
    if hour >= 24 {
        return None;
    }
    v = &v[n..];
    v = &v[expect(v, b':')?..];
    let (min, n) = getnum(v, true)?;
    if min >= 60 {
        return None;
    }
    v = &v[n..];
    v = &v[expect(v, b':')?..];
    let (sec, n) = getnum(v, true)?;
    if sec >= 60 {
        return None;
    }
    v = &v[n..];
    let mut nsec = 0u32;
    if v.len() >= 2 && (v[0] == b'.' || v[0] == b',') && digit(v, 1) {
        let mut n = 2;
        while digit(v, n) {
            n += 1;
        }
        // Go's parseNanoseconds: at most nine digits count, then scaled.
        let used = n.min(10);
        let ns: u32 = std::str::from_utf8(&v[1..used]).ok()?.parse().ok()?;
        nsec = ns * 10u32.pow(10 - used as u32);
        v = &v[n..];
    }
    let offset: i64 = if v.first() == Some(&b'Z') {
        v = &v[1..];
        0
    } else {
        if v.len() < 6 || v[3] != b':' {
            return None;
        }
        let (hr, _) = getnum(&v[1..3], true)?;
        let (mm, _) = getnum(&v[4..6], true)?;
        if hr > 24 || mm > 60 {
            return None;
        }
        let off = (hr * 60 + mm) * 60;
        let off = match v[0] {
            b'+' => off,
            b'-' => -off,
            _ => return None,
        };
        v = &v[6..];
        off
    };
    if !v.is_empty() || day < 1 || day > days_in(month, year) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + hour * 3600 + min * 60 + sec - offset, nsec))
}

/// days_from_civil, (year, month, day) to days since 1970-01-01: the inverse
/// of civil_from_days (Howard Hinnant's algorithm again, March-based years).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11], MARCH = 0
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// civil, unix days to (year, month, day); the public face of
/// civil_from_days for gozone's rule arithmetic.
pub fn civil(days: i64) -> (i64, i64, i64) {
    civil_from_days(days)
}

/// is_leap, the Gregorian leap-year rule.
pub fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// days_in, the length of month `m` (1-12) in year `y`.
pub fn days_in(m: i64, y: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
