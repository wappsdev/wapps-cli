// rotateplan, `wapps secrets rotate-plan` — offboard sonrasi NELERIN
// dondurulmesi gerektigini audit ledger'indan sorar.
//
// FIIL DEGER DONDURMEZ ve bu bir ayrinti degil, verb'un tanimi: donen her satir
// bir (project, key) ADI ve bir okuma sayacidir. Bir sir degeri bu yuzeye
// HICBIR kolda giremez — gate zaten gondermiyor, istemci de bir yer tutmuyor.
//
// ORACLE: cmd/secrets/rotateplan.go, internal/store/worker.go (RotatePlan).
use crate::store::RotatePlanResult;

/// render_text, insan-okunur tabloyu uretir.
///
/// Sutun genislikleri Go'nun `%-20s %-32s %-25s` hizalamasidir ve KESME YOK:
/// daha uzun bir ad sutunu tasirir (Go da tasirir). Iki bosluk girinti her
/// satirda.
pub fn render_text(res: &RotatePlanResult) -> String {
    let mut s = format!(
        "rotate plan for {} (generated {}): {} item(s)\n",
        res.identity,
        res.generated_at,
        res.items.len()
    );
    if res.items.is_empty() {
        // BOS PLAN: tablo BASILMAZ. Bos bir baslik satiri basmak burada en
        // kolay hata olurdu ve operatore "sutunlar var ama satir yok" derdi;
        // Go tek bir cumle basip DONUYOR.
        s.push_str(
            "  (nothing to rotate — the ledger has no plaintext-knowing rows for this identity)\n",
        );
        return s;
    }
    s.push_str(&format!(
        "  {:<20} {:<32} {:<25} {}\n",
        "PROJECT", "KEY", "LAST_READ", "READS"
    ));
    for it in &res.items {
        // BOS `last_read` "(assume-policy)" olur: satir audit'ten degil
        // policy kurallarindan turemis demektir. Bos dize basmak, operatore
        // "hic okunmamis" ile "audit kaydi yok"u AYNI gosterirdi.
        let last = if it.last_read.is_empty() {
            "(assume-policy)"
        } else {
            &it.last_read
        };
        s.push_str(&format!(
            "  {:<20} {:<32} {:<25} {}\n",
            it.project, it.key, last, it.reads
        ));
    }
    s.push_str("\nNext: execute the worklist with `wapps secrets rotate <project>` (typed recipes, highest blast radius first).\n");
    s
}

/// rfc3339_valid, `--since` degerinin Go'nun `time.Parse(time.RFC3339, s)`
/// tarafindan KABUL EDILIP EDILMEYECEGINI doner.
///
/// NEDEN ELDE YAZILDI: bir tarih kutuphanesi (chrono/time) bu grafige YENI
/// crate'ler sokardi ve bu estate tek bir dogrulama icin bunu odemiyor. Elde
/// yazilan sey bir AYRISTIRICI degil bir KABUL KUMESI — degerin kendisi tel'e
/// AYNEN bindigi icin cozulmus bir zamana hic ihtiyac yok.
///
/// KABUL KUMESI TAHMIN EDILMEDI, Go'dan OLCULDU (tests/rotateplan.rs'teki
/// tablo o olcumun kendisidir). Sasirtan uc nokta:
///   - `+03:60` KABUL: Go offset'in DAKIKASINI aralik kontrolune sokmuyor,
///     yalnizca SAATINI (`+99:00` reddediliyor).
///   - `23:59:60` RET: artik saniye yok.
///   - `2024-02-29` kabul, `2026-02-29` ret: artik yil GERCEKTEN hesaplaniyor.
///
/// RET SEBEBI DONMUYOR ve bu bilincli: Go'nun ret cumlesi ayristiricinin ic
/// durumunu anlatiyor (bes ayri bicim) ve onu taklit etmek sahte bir sadakat
/// olurdu. Ayrisan sey CUMLE, KARAR DEGIL (bkz. cases.py, EXCLUDED).
pub fn rfc3339_valid(s: &str) -> bool {
    let b = s.as_bytes();
    // Sabit govde: YYYY-MM-DDTHH:MM:SS = 19 bayt.
    if b.len() < 20 {
        return false;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    if !(d(0) && d(1) && d(2) && d(3)) || b[4] != b'-' {
        return false;
    }
    if !(d(5) && d(6)) || b[7] != b'-' {
        return false;
    }
    if !(d(8) && d(9)) {
        return false;
    }
    // 'T' YALNIZCA BUYUK HARF: Go RFC3339 layout'u kucuk `t`yi kabul etmiyor.
    if b[10] != b'T' {
        return false;
    }
    if !(d(11) && d(12)) || b[13] != b':' {
        return false;
    }
    if !(d(14) && d(15)) || b[16] != b':' {
        return false;
    }
    if !(d(17) && d(18)) {
        return false;
    }
    let num = |i: usize, n: usize| -> u32 { s[i..i + n].parse::<u32>().unwrap_or(u32::MAX) };
    let (year, month, day) = (num(0, 4), num(5, 2), num(8, 2));
    let (hour, min, sec) = (num(11, 2), num(14, 2), num(17, 2));
    if !(1..=12).contains(&month) {
        return false;
    }
    if day < 1 || day > days_in_month(year, month) {
        return false;
    }
    // 24:00:00 RET (Go: hour aralik kontrolu 0..23), artik saniye RET.
    if hour > 23 || min > 59 || sec > 59 {
        return false;
    }

    let mut rest = &b[19..];
    // Kesirli saniye: nokta VARSA en az BIR rakam gerekiyor ("05.Z" ret).
    if rest.first() == Some(&b'.') {
        let digits = rest[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        rest = &rest[1 + digits..];
    }
    // Bolge: `Z` (yalnizca buyuk harf) ya da (+|-)HH:MM.
    match rest {
        [b'Z'] => true,
        [sign, h1, h2, b':', m1, m2]
            if (*sign == b'+' || *sign == b'-')
                && h1.is_ascii_digit()
                && h2.is_ascii_digit()
                && m1.is_ascii_digit()
                && m2.is_ascii_digit() =>
        {
            // Offset SAATI aralik kontrolunden geciyor, DAKIKASI GECMIYOR.
            // Bu Go'nun davranisi ve olculdu: `+03:60` kabul, `+99:00` ret.
            let oh = (h1 - b'0') as u32 * 10 + (h2 - b'0') as u32;
            oh <= 23
        }
        _ => false,
    }
}

/// days_in_month, artik yil kuralini UYGULAYARAK ayin gun sayisini doner.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

/// query_escape, Go'nun `url.QueryEscape`inin AYNISIDIR.
///
/// Elde yazilmasinin sebebi bir tercih degil bir GOZLEMLENEBILIRLIK: kacilmamis
/// bir `&` sorgu dizesini IKIYE BOLER ve gate bambaska bir `identity` gorur.
/// Kacis kumesi Go'nunkiyle birebir: kacilmayanlar A-Za-z0-9 ve `-_.~`; bosluk
/// `+` olur; kalan her bayt BUYUK harfli `%XX`.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// query_string, `url.Values.Encode()` gibi ANAHTARA GORE SIRALI bir sorgu
/// dizesi uretir. Sira davranisi degistirmiyor ama sahadaki ikilinin URL'iyle
/// birebir ayni kalmasi, bir proxy/log satirinin da ayni gorunmesi demek.
pub fn query_string(pairs: &[(&str, String)]) -> String {
    let mut kv: Vec<&(&str, String)> = pairs.iter().collect();
    kv.sort_by_key(|(k, _)| *k);
    kv.iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}
