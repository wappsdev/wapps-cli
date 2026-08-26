// scrubber, `secrets exec`in SIZINTI YUZEYIDIR: alt-surecin stdout/stderr'ini
// saran, enjekte edilen gizli DEGERLERIN her tam gecisini `***` yapan streaming
// redaktor (Go: internal/agentmode/scrubber.go).
//
// NE OLDUGU ve NE OLMADIGI: bu bir kripto zorlamasi DEGIL, katmanli bir
// azaltmadir. Alt surec duz metni ZATEN elinde tutar ve bant disi sizdirabilir
// (dosyaya yazar, aga gonderir). Scrubber'in korudugu sey TRANSCRIPT'tir: bir
// aracin bagalanti dizesini ekrana echo'lamasi, o degeri ajan gecmisine ve
// operatorun kaydirma tamponuna kalici olarak yazar. Korunan yuzey budur.
//
// ASIL ZORLUK CHUNK SINIRLARI: bir sir iki ayri okumaya bolundugunde de
// yakalanmali. Bu yuzden "rolling boundary buffer" tutuluyor — en uzun degerden
// bir kisa (max_len-1) bayt her zaman elde kalir, cunku daha kisa bir kuyruk bir
// eslesmenin BASI olamaz. Bu olmadan sizinti "arada bir" olur ve tam olarak
// tekrar uretilemeyen sinif hataya donusur.
//
// Bu dosya bugun bir VERB tarafindan cagrilmiyor: `secrets exec` .wapps.yaml
// yuklemesine bagli ve o katman henuz portlanmadi. Once burada duruyor cunku
// exec'in en riskli ve en zor parcasi bu, ve Go korpusuyla sabitlenmis halde
// beklemesi, verb geldiginde onu ucuz ve guvenli yapar.
use std::io::Write;

/// REDACTION, bir gizli degerin yerine yazilan isarettir.
pub const REDACTION: &str = "***";

/// SCRUB_FLOOR, alt-surec ciktisindan GUVENLE redakte edilebilecek en kisa
/// gizli deger uzunlugudur (BAYT — Go'nun len()'i de bayt sayar).
///
/// Altindaki degerler scrubber'a VERILMEZ: iki harflik bir dizeyi `***` yapmak
/// ilgisiz ciktiyi bozar. Ama gercek-gorunumlu biri atlandiginda cagirana TEK
/// bir uyari yazilir — sessizce atlamak, korunmadigini bilmeden korundugunu
/// sanmaktir.
pub const SCRUB_FLOOR: usize = 4;

// common_literal, redakte EDILMEYECEK yaygin/dusuk-entropili literaller.
fn common_literal(v: &str) -> bool {
    matches!(v, "" | "null" | "true" | "false" | "nil" | "none" | "n/a")
}

// all_digits, yalnizca ondalik basamak mi (port/sayac/index — sir degil).
fn all_digits(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

/// is_scrubbable, bir degerin scrubber'a verilip verilmeyecegi.
pub fn is_scrubbable(v: &str) -> bool {
    !common_literal(v) && v.len() >= SCRUB_FLOOR
}

/// filter_scrubbable, aday kumeden scrubber'a verilecek alt kumeyi doner.
///
/// Floor'un ALTINDA kalip bu yuzden ATLANAN, gercek-gorunumlu (literal/saf-
/// basamak OLMAYAN) en az bir deger varsa note'a TEK bir uyari satiri yazar.
/// Uyari ASLA deger icermez — yalnizca SAYI.
pub fn filter_scrubbable(values: &[String], note: Option<&mut dyn Write>) -> Vec<String> {
    let mut out = Vec::with_capacity(values.len());
    let mut skipped = 0usize;
    for v in values {
        if is_scrubbable(v) {
            out.push(v.clone());
            continue;
        }
        if v.len() < SCRUB_FLOOR && !common_literal(v) && !all_digits(v) {
            skipped += 1;
        }
    }
    if skipped > 0 {
        if let Some(w) = note {
            let _ = writeln!(
                w,
                "wapps: {skipped} short secret value(s) below the {SCRUB_FLOOR}-char scrub floor were NOT redacted from child output — they may appear in the transcript"
            );
        }
    }
    out
}

/// Scrubber, w'yi saran streaming tam-eslesme redaktorudur.
pub struct Scrubber<'a, W: Write> {
    w: &'a mut W,
    // values, uzunluga gore AZALAN sirali (uzun-once).
    values: Vec<Vec<u8>>,
    max_len: usize,
    pending: Vec<u8>,
}

impl<'a, W: Write> Scrubber<'a, W> {
    /// new, verilen gizli deger kumesiyle w'yi sarar. Bos degerler ve tekrarlar
    /// elenir; deger yoksa scrubber saydam bir passthrough olur.
    pub fn new(w: &'a mut W, values: &[String]) -> Self {
        let mut seen: Vec<&str> = Vec::new();
        let mut vals: Vec<Vec<u8>> = Vec::new();
        let mut max_len = 0usize;
        for v in values {
            if v.is_empty() || seen.contains(&v.as_str()) {
                continue;
            }
            seen.push(v.as_str());
            max_len = max_len.max(v.len());
            vals.push(v.as_bytes().to_vec());
        }
        // Uzun degerleri ONCE dene: bir deger baskasinin on-ekiyse once uzunu
        // yakala (daha fazla bayt redakte edilir).
        vals.sort_by_key(|v| std::cmp::Reverse(v.len()));
        Scrubber { w, values: vals, max_len, pending: Vec::new() }
    }

    /// write_all, gelen baytlari biriktirir ve GUVENLE bosaltilabilir oneki yazar.
    pub fn write_all(&mut self, p: &[u8]) -> std::io::Result<()> {
        if self.values.is_empty() {
            return self.w.write_all(p);
        }
        self.pending.extend_from_slice(p);
        self.process(false)
    }

    /// flush, kalan tamponu bosaltir — cocuk ciktiginda cagrilmalidir. Idempotent.
    pub fn flush(&mut self) -> std::io::Result<()> {
        if self.values.is_empty() {
            return Ok(());
        }
        self.process(true)
    }

    fn process(&mut self, final_pass: bool) -> std::io::Result<()> {
        // Once pending icindeki TUM tam eslesmeleri isle.
        while let Some((idx, match_len)) = self.earliest_match() {
            self.w.write_all(&self.pending[..idx])?;
            self.w.write_all(REDACTION.as_bytes())?;
            self.pending.drain(..idx + match_len);
        }

        if final_pass {
            if !self.pending.is_empty() {
                self.w.write_all(&self.pending)?;
                self.pending.clear();
            }
            return Ok(());
        }

        // Kismi-eslesme korumasi: son (max_len-1) bayti TUT, gerisini bosalt.
        // Uzunlugu <= max_len olan bir deger, basi bu bolgenin DISINDA ise
        // zaten tamamen icerilirdi ve yukarida bulunurdu.
        let keep = self.max_len.saturating_sub(1);
        if self.pending.len() > keep {
            let flush_len = self.pending.len() - keep;
            self.w.write_all(&self.pending[..flush_len])?;
            self.pending.drain(..flush_len);
        }
        Ok(())
    }

    // earliest_match, EN ERKEN baslangic indeksini ve eslesen degerin uzunlugunu
    // doner. Ayni indekste birden cok deger basliyorsa EN UZUN secilir.
    fn earliest_match(&self) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for v in &self.values {
            let Some(i) = find_sub(&self.pending, v) else { continue };
            best = match best {
                None => Some((i, v.len())),
                Some((bi, bl)) if i < bi || (i == bi && v.len() > bl) => Some((i, v.len())),
                keep => keep,
            };
        }
        best
    }
}

// find_sub, needle'in haystack icindeki ilk indeksi (bytes.Index karsiligi).
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
