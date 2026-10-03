// safelog, DISARIDAN gelen metinlerdeki sir-bicimli parcalari zarfa girmeden
// once maskeler. Go'daki internal/safelog.RedactPatterns'in portudur ve Go
// ORACLE'dir.
//
// NEDEN GEREKLI — bu teorik bir yuzey degil, OLCULDU: `unknown flag: --<a>&b`
// vakasi kullanicinin kontrol ettigi metnin dogrudan zarfin `message` alanina
// girdigini gosteriyor. Dis metin tasiyan bir yol, ayni zamanda sirra komsu
// hatalari da tasiyorsa (ucuncu-taraf API govdesi, yakalanmis log satiri) bu bir
// sizinti yuzeyidir.
//
// TASINMAYAN parca: Go'nun Wrap()/Errorf() isaretleyicisi. O, cagri yerinde
// "bu deger bir sir" demenin yolu ve bu dilimde (`secrets get`) sir DEGERI
// tasiyan tek bir bicimlendirme cagrisi yok — deger stdout'a ham basiliyor,
// hata metnine hic girmiyor. Isaretleyiciyi cagirani olmadan tasimak,
// kullanilmayan bir API'yi port etmek olurdu.
//
// NEREDE UYGULANIR: YALNIZCA zarf yolunda (clierr::emit). Go'nun insan yolu
// (`Error: <cumle>`) RedactPatterns'tan GECMIYOR — (*Error).Error() onu
// cagirmiyor. Bu asimetri kasitli olarak birebir tasindi; iki tarafi da
// redakte etmek sahadaki ikiliyle ayrisma olurdu ve differential'da
// human_unredacted_token_flag vakasi tam olarak bunu pinliyor.
//
// SEMANTIK: Go'nun regexp'i ASCII \b kullaniyor ve leftmost-first/greedy
// esliyor. Burada desenler ELLE yurutuluyor (yeni bir bagimlilik degil):
// `regex` crate'inin \b'si varsayilan olarak UNICODE ve bu tek basina bir
// ayrisma kaynagi olurdu (korpustaki non_ascii_before_token vakasi). Iki
// desenin de karakter sinifi tamamen ASCII oldugu icin tarama BAYT duzeyinde
// yapilir; bir eslesmenin kenarlari daima ASCII, yani daima gecerli bir
// karakter siniri.

/// REDACTED, JWT deseninin yerine konan sabittir (Go'daki safelog.Redacted).
pub const REDACTED: &str = "[REDACTED]";

// jwt_class, `[A-Za-z0-9_-]`.
fn jwt_class(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

// token_class, `[A-Za-z0-9_+/=-]`.
fn token_class(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'/' | b'=' | b'-')
}

// is_word, Go'nun ASCII \b'sinin kelime karakteri: `[0-9A-Za-z_]`.
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// run_len, i'den itibaren sinifa uyan EN UZUN diziyi olcer.
fn run_len(bytes: &[u8], i: usize, class: fn(u8) -> bool) -> usize {
    let mut n = 0;
    while i + n < bytes.len() && class(bytes[i + n]) {
        n += 1;
    }
    n
}

// jwt_match_end, i'de baslayan `{8,}\.{8,}\.{8,}` eslesmesinin bitisini doner.
//
// Greedy dizi MAKSIMAL alinabiliyor cunku ayirici ('.') karakter sinifinin
// DISINDA: daha kisa bir dizinin ardindan gelen karakter yine sinifa ait bir
// karakterdir, '.' olamaz. Yani geri izlemenin bu desende yardimi YOK.
fn jwt_match_end(bytes: &[u8], i: usize) -> Option<usize> {
    let mut p = i;
    for seg in 0..3 {
        let n = run_len(bytes, p, jwt_class);
        if n < 8 {
            return None;
        }
        p += n;
        if seg < 2 {
            if bytes.get(p) != Some(&b'.') {
                return None;
            }
            p += 1;
        }
    }
    Some(p)
}

// boundary_at, Go'nun ASCII \b'si: p'nin iki yanindan TAM BIRI kelime karakteri.
fn boundary_at(bytes: &[u8], p: usize) -> bool {
    let before = p > 0 && is_word(bytes[p - 1]);
    let after = p < bytes.len() && is_word(bytes[p]);
    before != after
}

// token_match_end, i'de baslayan `\b[...]{24,}\b` eslesmesinin bitisini doner.
//
// Burada geri izleme GEREKLI ve olculdu: sinif '-', '=', '+' ve '/' tasiyor ama
// bunlar kelime karakteri DEGIL, yani maksimal dizinin sonunda \b saglanmayabilir.
// "AbC…AbC123--" ornegi Go'da 26 degil 24 karakter esliyor. Greedy oldugu icin
// EN UZUN gecerli bitis secilir.
fn token_match_end(bytes: &[u8], i: usize) -> Option<usize> {
    if !boundary_at(bytes, i) {
        return None;
    }
    let max = i + run_len(bytes, i, token_class);
    if max - i < 24 {
        return None;
    }
    let mut end = max;
    while end >= i + 24 {
        if boundary_at(bytes, end) {
            return Some(end);
        }
        end -= 1;
    }
    None
}

// has_mixed_case, Go'daki hasMixedCase: (kucuk, buyuk, rakam) siniflarindan en
// az IKISI varsa true. Boylece /home/user/... gibi tek-sinifli yollar hayatta
// kalir, AKIA… bicimli karisik jetonlar redakte edilir.
fn has_mixed_case(s: &[u8]) -> bool {
    let lower = s.iter().any(|b| b.is_ascii_lowercase());
    let upper = s.iter().any(|b| b.is_ascii_uppercase());
    let digit = s.iter().any(|b| b.is_ascii_digit());
    usize::from(lower) + usize::from(upper) + usize::from(digit) >= 2
}

// scan, leftmost-first, ORTUSMEYEN degistirme dongusudur (Go'nun ReplaceAll'i).
// `replace` None donerse eslesme AYNEN korunur ama tarama yine eslesmenin
// SONUNDAN devam eder — ReplaceAllStringFunc'in davranisi budur.
fn scan(
    s: &str,
    find: fn(&[u8], usize) -> Option<usize>,
    replace: fn(&[u8]) -> Option<String>,
) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match find(bytes, i) {
            Some(end) => {
                let m = &bytes[i..end];
                match replace(m) {
                    Some(r) => out.push_str(&r),
                    // Eslesme ASCII sinifindan; UTF-8 gecerliligi garanti.
                    None => out.push_str(std::str::from_utf8(m).expect("ASCII eslesme")),
                }
                i = end;
            }
            None => {
                // Cok baytli bir karakterin ortasindan kesmemek icin bayt bayt
                // degil, karakter karakter ilerlemek gerekmiyor: eslesmeyen
                // baytlar oldugu gibi kopyalaniyor ve sonunda tampon yine ayni
                // bayt dizisi. Ama String'e yazmak icin gecerli bir dilim lazim,
                // o yuzden karakter sinirina kadar tasiyoruz.
                let mut end = i + 1;
                while end < bytes.len() && !s.is_char_boundary(end) {
                    end += 1;
                }
                out.push_str(&s[i..end]);
                i = end;
            }
        }
    }
    out
}

/// redact_patterns, DIS kaynakli bir metindeki sir-bicimli parcalari maskeler.
///
/// Sira Go ile AYNI: once JWT (en spesifik desen), sonra uzun karisik jetonlar.
/// Sirayi ters cevirmek "unknown flag: --<jwt>" vakasinda farkli bir cikti verir.
pub fn redact_patterns(s: &str) -> String {
    let s = scan(s, jwt_match_end, |_| Some(REDACTED.to_string()));
    scan(&s, token_match_end, |m| {
        if has_mixed_case(m) {
            Some(format!("[REDACTED:{}]", m.len()))
        } else {
            None
        }
    })
}
