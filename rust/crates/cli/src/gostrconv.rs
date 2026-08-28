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
