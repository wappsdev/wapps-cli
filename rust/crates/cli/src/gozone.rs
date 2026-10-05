// gozone, Go's `time.Local`: the UTC offset Go uses for "now" when it writes
// a local time.
//
// ONE CALLER: the update check's cache file (`checked_at`), which the Go and
// the Rust binary share. Go writes it with time.Now() in the local zone, so
// the same instant reads `...+03:00` in Istanbul and `...Z` under TZ=UTC; to
// write the same bytes the port needs Go's offset, which means Go's way of
// FINDING the zone, not the C library's:
//
//   - TZ unset: /etc/localtime. TZ="" or "UTC": UTC without reading a file.
//   - TZ="foo" or ":foo": an absolute path is read as is; a name is looked up
//     in /usr/share/zoneinfo/, /usr/share/lib/zoneinfo/, /usr/lib/locale/TZ/,
//     /etc/zoneinfo — and nothing found means UTC. A POSIX rule string
//     ("XYZ-3") is NOT parsed from TZ (libc would); Go falls back to UTC.
//   - The file is TZif. Past its last transition the footer's POSIX rule
//     answers (current tzdata is "slim": most present-day offsets live only
//     there).
//
// WHY BY HAND: the alternative is a date crate with a local-zone reader
// (chrono pulls iana-time-zone and platform crates; `time` refuses the local
// offset in a multi-threaded process). This is a literal port of
// time/zoneinfo_read.go (LoadLocationFromTZData), time/zoneinfo.go (lookup,
// tzset) and time/zoneinfo_unix.go (initLocal) from Go 1.26, compared with
// the live Go oracle over 32 TZ values and 28 instants (tests/updatecheck.rs).
//
// Not ported: Go's last-resort source, $GOROOT/lib/time/zoneinfo.zip, which
// only answers when a zone is missing from every system directory (the port
// then says UTC).

const PLATFORM_ZONE_SOURCES: &[&str] = &[
    "/usr/share/zoneinfo/",
    "/usr/share/lib/zoneinfo/",
    "/usr/lib/locale/TZ/",
    "/etc/zoneinfo",
];

// Go's readFile refuses zone files above this size.
const MAX_FILE_SIZE: usize = 10 << 20;

const SECONDS_PER_DAY: i64 = 86_400;

/// local_offset, the offset (seconds east of UTC) Go's Local has at unix
/// second `sec`, for the TZ variable `tz` (`None`: unset).
pub fn local_offset(tz: Option<&str>, sec: i64) -> i32 {
    match load_local(tz) {
        Some(loc) => loc.lookup(sec),
        None => 0,
    }
}

// load_local is initLocal: `None` is UTC.
fn load_local(tz: Option<&str>) -> Option<Location> {
    let tz = match tz {
        None => return load_location("localtime", &["/etc"]),
        Some(t) => t.strip_prefix(':').unwrap_or(t),
    };
    if tz.starts_with('/') {
        load_location(tz, &[""])
    } else if !tz.is_empty() && tz != "UTC" {
        load_location(tz, PLATFORM_ZONE_SOURCES)
    } else {
        None
    }
}

fn load_location(name: &str, sources: &[&str]) -> Option<Location> {
    sources.iter().find_map(|source| {
        let path = if source.is_empty() {
            name.to_string()
        } else {
            format!("{source}/{name}")
        };
        let data = std::fs::read(path).ok()?;
        if data.len() > MAX_FILE_SIZE {
            return None;
        }
        Location::from_tzdata(&data)
    })
}

struct Zone {
    offset: i32,
    is_dst: bool,
}

struct Location {
    zones: Vec<Zone>,
    // (when, zone index)
    tx: Vec<(i64, usize)>,
    extend: String,
}

// Reader is Go's dataIO: a read past the end empties it and fails.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn read(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            self.0 = &[];
            return None;
        }
        let (p, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(p)
    }
    fn big4(&mut self) -> Option<u32> {
        self.read(4)
            .map(|p| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
    }
    fn big8(&mut self) -> Option<u64> {
        let hi = self.big4()? as u64;
        let lo = self.big4()? as u64;
        Some(hi << 32 | lo)
    }
}

impl Location {
    // from_tzdata is LoadLocationFromTZData, keeping only what the offset
    // needs (no abbreviations, no isstd/isut flags, no cache).
    fn from_tzdata(data: &[u8]) -> Option<Location> {
        let mut d = Reader(data);
        if d.read(4)? != b"TZif" {
            return None;
        }
        let version = match d.read(16)?[0] {
            0 => 1,
            b'2' => 2,
            b'3' => 3,
            _ => return None,
        };
        let mut n = [0usize; 6];
        for c in n.iter_mut() {
            *c = d.big4()? as usize;
        }
        const NUTC: usize = 0;
        const NSTD: usize = 1;
        const NLEAP: usize = 2;
        const NTIME: usize = 3;
        const NZONE: usize = 4;
        const NCHAR: usize = 5;
        let is64 = version > 1;
        if is64 {
            // Skip the 32-bit body and the second header's magic+version.
            let skip = n[NTIME] * 4
                + n[NTIME]
                + n[NZONE] * 6
                + n[NCHAR]
                + n[NLEAP] * 8
                + n[NSTD]
                + n[NUTC]
                + 4
                + 16;
            // Go ignores a short skip here; the reads below then fail.
            let _ = d.read(skip);
            for c in n.iter_mut() {
                *c = d.big4()? as usize;
            }
        }
        let size = if is64 { 8 } else { 4 };
        let txtimes = d.read(n[NTIME] * size)?;
        let txzones = d.read(n[NTIME])?;
        let zonedata = d.read(n[NZONE] * 6)?;
        let abbrev = d.read(n[NCHAR])?;
        d.read(n[NLEAP] * (size + 4))?;
        d.read(n[NSTD])?;
        d.read(n[NUTC])?;
        let rest = d.0;
        let extend = if rest.len() > 2 && rest[0] == b'\n' && rest[rest.len() - 1] == b'\n' {
            String::from_utf8_lossy(&rest[1..rest.len() - 1]).into_owned()
        } else {
            String::new()
        };

        if n[NZONE] == 0 {
            return None;
        }
        let mut zd = Reader(zonedata);
        let mut zones = Vec::with_capacity(n[NZONE]);
        for _ in 0..n[NZONE] {
            let offset = zd.big4()? as i32;
            let is_dst = zd.read(1)?[0] != 0;
            if zd.read(1)?[0] as usize >= abbrev.len() {
                return None;
            }
            zones.push(Zone { offset, is_dst });
        }
        let mut tt = Reader(txtimes);
        let mut tx = Vec::with_capacity(n[NTIME]);
        for &zi in txzones {
            let when = if is64 {
                tt.big8()? as i64
            } else {
                tt.big4()? as i32 as i64
            };
            if zi as usize >= zones.len() {
                return None;
            }
            tx.push((when, zi as usize));
        }
        if tx.is_empty() {
            // A fixed zone ("Etc/GMT+3"): one fake transition covering all time.
            tx.push((i64::MIN, 0));
        }
        Some(Location { zones, tx, extend })
    }

    // lookup is Location.lookup, the offset only.
    fn lookup(&self, sec: i64) -> i32 {
        if sec < self.tx[0].0 {
            return self.zones[self.lookup_first_zone()].offset;
        }
        let (mut lo, mut hi) = (0usize, self.tx.len());
        while hi - lo > 1 {
            let m = (lo + hi) / 2;
            if sec < self.tx[m].0 {
                hi = m;
            } else {
                lo = m;
            }
        }
        if lo == self.tx.len() - 1 && !self.extend.is_empty() {
            if let Some(off) = tzset(&self.extend, sec) {
                return off;
            }
        }
        self.zones[self.tx[lo].1].offset
    }

    fn lookup_first_zone(&self) -> usize {
        if !self.tx.iter().any(|t| t.1 == 0) {
            return 0;
        }
        if self.zones[self.tx[0].1].is_dst {
            if let Some(zi) = (0..self.tx[0].1).rev().find(|&zi| !self.zones[zi].is_dst) {
                return zi;
            }
        }
        self.zones.iter().position(|z| !z.is_dst).unwrap_or(0)
    }
}

// tzset evaluates a POSIX TZ rule (the TZif footer) at `sec`: Go's tzset,
// offset only. `None` where Go reports the rule unusable.
fn tzset(s: &str, sec: i64) -> Option<i32> {
    let (_std_name, s) = tzset_name(s)?;
    let (std_offset, s) = tzset_offset(s)?;
    // The rule's numbers are added to local time to get UTC; ours are added
    // to UTC.
    let std_offset = -std_offset;
    if s.is_empty() || s.starts_with(',') {
        return Some(std_offset as i32);
    }
    let (_dst_name, s) = tzset_name(s)?;
    let (dst_offset, mut s) = if s.is_empty() || s.starts_with(',') {
        (std_offset + 3600, s)
    } else {
        let (o, rest) = tzset_offset(s)?;
        (-o, rest)
    };
    if s.is_empty() {
        s = ",M3.2.0,M11.1.0"; // tzcode's default rules
    }
    if !(s.starts_with(',') || s.starts_with(';')) {
        return None;
    }
    let (start_rule, s) = tzset_rule(&s[1..])?;
    let s = s.strip_prefix(',')?;
    let (end_rule, s) = tzset_rule(s)?;
    if !s.is_empty() {
        return None;
    }

    let (year, yday) = year_yday(sec);
    // Go's `%` truncates toward zero; kept as is.
    let ysec = (yday - 1) * SECONDS_PER_DAY + sec % SECONDS_PER_DAY;
    let mut start = tzrule_time(year, &start_rule, std_offset);
    let mut end = tzrule_time(year, &end_rule, dst_offset);
    let (mut std_off, mut dst_off) = (std_offset, dst_offset);
    if end < start {
        // Southern hemisphere: the labels flip.
        std::mem::swap(&mut start, &mut end);
        std::mem::swap(&mut std_off, &mut dst_off);
    }
    if ysec < start || ysec >= end {
        Some(std_off as i32)
    } else {
        Some(dst_off as i32)
    }
}

// year_yday is Go's absSeconds(...).days().yearYday() for a unix second: the
// UTC calendar year and its 1-based day.
fn year_yday(sec: i64) -> (i64, i64) {
    let days = sec.div_euclid(SECONDS_PER_DAY);
    let (y, _, _) = crate::gotime::civil(days);
    (y, days - crate::gotime::days_from_civil(y, 1, 1) + 1)
}

fn tzset_name(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    if !s.starts_with('<') {
        for (i, r) in s.char_indices() {
            if matches!(r, '0'..='9' | ',' | '-' | '+') {
                if i < 3 {
                    return None;
                }
                return Some((&s[..i], &s[i..]));
            }
        }
        if s.len() < 3 {
            return None;
        }
        return Some((s, ""));
    }
    let i = s.find('>')?;
    Some((&s[1..i], &s[i + 1..]))
}

fn tzset_offset(s: &str) -> Option<(i64, &str)> {
    if s.is_empty() {
        return None;
    }
    let (neg, s) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let sign = |off: i64| if neg { -off } else { off };
    // tzdata permits hours up to 24*7, although POSIX does not.
    let (hours, s) = tzset_num(s, 0, 24 * 7)?;
    let mut off = hours * 3600;
    let Some(s) = s.strip_prefix(':') else {
        return Some((sign(off), s));
    };
    let (mins, s) = tzset_num(s, 0, 59)?;
    off += mins * 60;
    let Some(s) = s.strip_prefix(':') else {
        return Some((sign(off), s));
    };
    let (secs, s) = tzset_num(s, 0, 59)?;
    Some((sign(off + secs), s))
}

enum Rule {
    Julian(i64),
    Doy(i64),
    MonthWeekDay { mon: i64, week: i64, day: i64 },
}

fn tzset_rule(s: &str) -> Option<((Rule, i64), &str)> {
    if s.is_empty() {
        return None;
    }
    let (rule, s) = if let Some(rest) = s.strip_prefix('J') {
        let (jday, s) = tzset_num(rest, 1, 365)?;
        (Rule::Julian(jday), s)
    } else if let Some(rest) = s.strip_prefix('M') {
        let (mon, s) = tzset_num(rest, 1, 12)?;
        let s = s.strip_prefix('.')?;
        let (week, s) = tzset_num(s, 1, 5)?;
        let s = s.strip_prefix('.')?;
        let (day, s) = tzset_num(s, 0, 6)?;
        (Rule::MonthWeekDay { mon, week, day }, s)
    } else {
        let (day, s) = tzset_num(s, 0, 365)?;
        (Rule::Doy(day), s)
    };
    let Some(rest) = s.strip_prefix('/') else {
        return Some(((rule, 2 * 3600), s)); // 2am is the default
    };
    let (time, s) = tzset_offset(rest)?;
    Some(((rule, time), s))
}

fn tzset_num(s: &str, min: i64, max: i64) -> Option<(i64, &str)> {
    if s.is_empty() {
        return None;
    }
    let mut num = 0i64;
    for (i, r) in s.char_indices() {
        if !r.is_ascii_digit() {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, &s[i..]));
        }
        num = num * 10 + (r as i64 - '0' as i64);
        if num > max {
            return None;
        }
    }
    if num < min {
        return None;
    }
    Some((num, ""))
}

// tzrule_time: seconds from the start of `year` at which the rule takes
// effect, for a zone `off` seconds east of UTC.
fn tzrule_time(year: i64, (rule, time): &(Rule, i64), off: i64) -> i64 {
    use crate::gotime::{days_in, is_leap};
    const DAYS_BEFORE: [i64; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
    let s = match *rule {
        Rule::Julian(day) => {
            let mut s = (day - 1) * SECONDS_PER_DAY;
            if is_leap(year) && day >= 60 {
                s += SECONDS_PER_DAY;
            }
            s
        }
        Rule::Doy(day) => day * SECONDS_PER_DAY,
        Rule::MonthWeekDay { mon, week, day } => {
            // Zeller's congruence: the weekday of the month's first day.
            let m1 = (mon + 9) % 12 + 1;
            let yy0 = if mon <= 2 { year - 1 } else { year };
            let yy1 = yy0 / 100;
            let yy2 = yy0 % 100;
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }
            let mut d = day - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..week {
                if d + 7 >= days_in(mon, year) {
                    break;
                }
                d += 7;
            }
            d += DAYS_BEFORE[(mon - 1) as usize];
            if is_leap(year) && mon > 2 {
                d += 1;
            }
            d * SECONDS_PER_DAY
        }
    };
    s + time - off
}
