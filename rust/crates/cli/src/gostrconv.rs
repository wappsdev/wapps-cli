// gostrconv, Go'nun `strconv.ParseInt(s, 0, 64)` semantiginin portudur.
//
// NEDEN BURADA: `token exchange --ttl` cobra'da bir `IntVar`. Deger
// AYRISTIRICIDA cozuluyor, yani bozuk bir `--ttl` verb'un RunE'sine HIC
// girmeden reddediliyor ve reddin metni Go'nun `*strconv.NumError` prozasi.
// clap'in kendi tamsayi ayristiricisini kullanmak hem KABUL KUMESINI
// (taban 0'in `0x`/`0o`/`0b`/`0` onekleri, alt cizgi ayiricilari) hem de
// RET METNINI ayristirirdi.
//
// ORACLE Go'nun `strconv/atoi.go`'su ve tablonun tamami OLCULDU
// (tests/gostrconv.rs), kaynaktan HATIRLANMADI.
//
// SADECE `base=0, bitSize=64` TASINIYOR. Genel bir ayristirici yazmak
// cagirani olmayan bir API port etmek olurdu; ihtiyac tek ve bu.

/// ParseIntError, Go'nun `NumError.Err` alanindaki IKI hatadir.
/// Ayri tutulmalari kozmetik degil: ikisinin CUMLESI farkli.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIntError {
    /// ErrSyntax — "invalid syntax".
    Syntax,
    /// ErrRange — "value out of range". Go bu durumda SINIR degeri de
    /// donduruyor; cagiran onu kullanmadigi icin burada tasinmiyor.
    Range,
}

impl ParseIntError {
    /// go_text, Go'nun `(*NumError).Error()` ciktisidir.
    ///
    /// `num` DAIMA ISARETLI ORIJINALDIR (`s0`): ParseInt, ParseUint'ten gelen
    /// hatanin `Num` alanini kendi girdisiyle DEGISTIRIYOR. Yani `-abc` icin
    /// basilan dize `parsing "-abc"`, `parsing "abc"` DEGIL.
    pub fn go_text(self, num: &str) -> String {
        let what = match self {
            ParseIntError::Syntax => "invalid syntax",
            ParseIntError::Range => "value out of range",
        };
        format!(
            "strconv.ParseInt: parsing {}: {}",
            crate::gojson::quote(num),
            what
        )
    }
}

// lower, Go'nun `lower()`i: yalnizca ASCII harflerde anlamli (bit 0x20).
fn lower(c: u8) -> u8 {
    c | (b'a' - b'A')
}

/// parse_int_base0, `strconv.ParseInt(s, 0, 64)`.
pub fn parse_int_base0(s: &str) -> Result<i64, ParseIntError> {
    if s.is_empty() {
        return Err(ParseIntError::Syntax);
    }
    let s0 = s;
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut neg = false;
    if b[0] == b'+' {
        i = 1;
    } else if b[0] == b'-' {
        neg = true;
        i = 1;
    }
    let un = parse_uint_base0(&b[i..])?;
    // Go'nun isaretli sinir kontrolu: cutoff = 1<<63.
    const CUTOFF: u64 = 1u64 << 63;
    if !neg && un >= CUTOFF {
        return Err(ParseIntError::Range);
    }
    if neg && un > CUTOFF {
        return Err(ParseIntError::Range);
    }
    let _ = s0;
    let n = un as i64;
    Ok(if neg { n.wrapping_neg() } else { n })
}

// parse_uint_base0, `strconv.ParseUint(s, 0, 64)`.
//
// SIRA GO ILE AYNI ve onemli: taban onegi once secilir, sonra basamaklar
// gezilir, ve ALT CIZGI DOGRULAMASI EN SONA birakilir. Go'da da oyle —
// bu yuzden `1__0` once bir sayi gibi okunur, sonra `underscoreOK`
// tarafindan reddedilir.
fn parse_uint_base0(s: &[u8]) -> Result<u64, ParseIntError> {
    if s.is_empty() {
        return Err(ParseIntError::Syntax);
    }
    let s0 = s;
    let mut base: u64 = 10;
    let mut body = s;
    if s[0] == b'0' {
        // `len(s) >= 3` SART: "0x" (uzunluk 2) onek SAYILMAZ, "0" + "x"
        // olarak okunur ve sekizlik bir 'x' aranir -> sozdizimi hatasi.
        if s.len() >= 3 && matches!(lower(s[1]), b'b' | b'o' | b'x') {
            base = match lower(s[1]) {
                b'b' => 2,
                b'o' => 8,
                _ => 16,
            };
            body = &s[2..];
        } else {
            base = 8;
            body = &s[1..];
        }
    }

    let cutoff = u64::MAX / base + 1;
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in body {
        // Alt cizgi YALNIZCA taban 0'da bir ayiricidir — ve bu fonksiyon
        // yalnizca taban 0 icin var.
        if c == b'_' {
            underscores = true;
            continue;
        }
        let d: u64 = if c.is_ascii_digit() {
            (c - b'0') as u64
        } else if lower(c).is_ascii_lowercase() {
            (lower(c) - b'a') as u64 + 10
        } else {
            return Err(ParseIntError::Syntax);
        };
        if d >= base {
            return Err(ParseIntError::Syntax);
        }
        if n >= cutoff {
            return Err(ParseIntError::Range);
        }
        n *= base;
        let n1 = n.checked_add(d).ok_or(ParseIntError::Range)?;
        n = n1;
    }
    if underscores && !underscore_ok(s0) {
        return Err(ParseIntError::Syntax);
    }
    Ok(n)
}

// underscore_ok, Go'nun `underscoreOK`'u: alt cizgi basamaklarin ARASINDA
// (ya da taban oneginden hemen sonra) olmak zorunda.
//
// `saw` uc durumu izliyor: '^' baslangic, '0' basamak/onek, '_' alt cizgi,
// '!' digerleri. Go ile AYNI harfler kullaniliyor ki karsilastirma kolay olsun.
fn underscore_ok(s: &[u8]) -> bool {
    let mut saw = b'^';
    let mut i = 0usize;
    let mut s = s;
    if !s.is_empty() && (s[0] == b'-' || s[0] == b'+') {
        s = &s[1..];
    }
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        // Taban onegi "bir basamak" sayilir: `0x_10` GECERLI.
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else if saw == b'_' {
            return false;
        } else {
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

// --- ParseBool, Quote, QuoteRune -------------------------------------------------
//
// Added for `coolify set-labels`/`update-env`: `--strip-cert-resolver` is a
// pflag `BoolVar` (parsed by `strconv.ParseBool`, refused with its prose), and
// the coolify errors quote user input with `%q`. Vectors measured from Go 1.26
// (tests/gostrconv.rs).

/// parse_bool, Go's `strconv.ParseBool`; the error is Go's full sentence.
pub fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!(
            "strconv.ParseBool: parsing {}: invalid syntax",
            quote(s)
        )),
    }
}

/// quote, Go's `strconv.Quote` (what `%q` prints for a string).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        push_escaped(&mut out, c, '"');
    }
    out.push('"');
    out
}

/// quote_rune, Go's `strconv.QuoteRune` (what `%q` prints for a rune).
pub fn quote_rune(c: char) -> String {
    let mut out = String::with_capacity(4);
    out.push('\'');
    push_escaped(&mut out, c, '\'');
    out.push('\'');
    out
}

// push_escaped, one rune the way Go's appendEscapedRune writes it.
//
// ASCII is exact. Beyond ASCII Go escapes what `unicode.IsPrint` rejects; std
// has no Unicode category table, so this escapes control characters, Unicode
// spaces other than ' ' (Go's IsPrint admits only the ASCII space) and the
// format characters (Cf) a user can plausibly paste. Unassigned and
// private-use code points print raw here, where Go escapes them — a known,
// unmeasured gap.
fn push_escaped(out: &mut String, c: char, delim: char) {
    use std::fmt::Write;
    match c {
        '\\' => out.push_str("\\\\"),
        _ if c == delim => {
            out.push('\\');
            out.push(c);
        }
        '\x07' => out.push_str("\\a"),
        '\x08' => out.push_str("\\b"),
        '\x0c' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\x0b' => out.push_str("\\v"),
        _ if c < ' ' || c == '\x7f' => {
            let _ = write!(out, "\\x{:02x}", c as u32);
        }
        _ if c.is_ascii() => out.push(c),
        _ if c.is_control() || c.is_whitespace() || is_format(c) => {
            if (c as u32) < 0x10000 {
                let _ = write!(out, "\\u{:04x}", c as u32);
            } else {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
        _ => out.push(c),
    }
}

// is_format, the Unicode Cf (format) characters.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891
        | 0x08E2 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
        | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001
        | 0xE0020..=0xE007F)
}
