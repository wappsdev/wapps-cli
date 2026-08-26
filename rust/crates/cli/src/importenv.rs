// importenv, `wapps secrets import-env <dosya>` fiilidir: bir .env dosyasindaki
// KEY=VALUE ciftlerini TEK atomik epoch'ta store'a yazar.
//
// ORACLE: internal/source/file.go (parseEnvFile, unquote) ve
// cmd/secrets/import_env.go.
//
// AYRISTIRICI PAYLASILIYOR, ve bu Go'da bilincli: import-env, `file`
// kaynaginin ayristiricisini (ParseEnvFileBytes) AYNEN cagiriyor, boylece
// temiz import edilen bir .env ayni depoda bir file-source olarak da
// calisiyor. Ayri bir ayristirici yazmak o esitligi sessizce bozardi.
//
// SIR DISIPLINI — bu modulun en onemli satiri asagida, `no '=' delimiter`
// hatasinda: bir operator `.env`e yanlislikla CIPLAK bir jeton yapistirdiginda
// SATIRIN TAMAMI o jetondur. Hata mesaji satiri YANKILAMAZ; yalnizca
// UZUNLUGU tasir, ki operator satiri bulabilsin ve deger terminale, CI
// loguna ya da bir ajan transcript'ine DUSMESIN.
use std::collections::BTreeMap;

/// parse_env_file, bir .env bayt akisini anahtar→deger haritasina cevirir.
///
/// BTreeMap: Go'nun map'i sirasiz ama tuketiciler (rapor satiri, hedef
/// yazicisi) zaten siraliyor. Sirali bir harita ayni sonucu DETERMINISTIK
/// verir.
pub fn parse_env_file(path: &str, data: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    // Go bufio.Scanner + ScanLines: satir sonundaki `\r` DUSURULUR. `\n`e gore
    // bolup `\r`i kirpmak ayni sonucu verir. Son eleman bos ise (dosya `\n`
    // ile bitmisse) o da bos satir olarak atlanir.
    let text = String::from_utf8_lossy(data);
    for (i, raw) in text.split('\n').enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "export " oneki (BOSLUGUYLA birlikte) soyulur. "exportA" bir onek
        // DEGIL, anahtar adinin kendisi.
        let line = line.strip_prefix("export ").unwrap_or(line);
        match line.find('=') {
            // idx == 0 da hata: bos anahtar adi kabul edilmiyor (Go: idx <= 0).
            None | Some(0) => {
                return Err(format!(
                    "source[file ({path})]: line {line_no}: no '=' delimiter (line length {})",
                    line.len()
                ))
            }
            Some(idx) => {
                let key = line[..idx].trim().to_string();
                let val = unquote(line[idx + 1..].trim());
                // Sonraki satir oncekini EZER (Go map atamasi).
                out.insert(key, val.to_string());
            }
        }
    }
    Ok(out)
}

// unquote, degeri saran ES tirnak ciftini soyar. Kabuk kacis dizilerini
// COZMEZ — Go da cozmuyor.
fn unquote(s: &str) -> &str {
    if s.len() < 2 {
        return s;
    }
    let b = s.as_bytes();
    let (first, last) = (b[0], b[b.len() - 1]);
    if (first == b'"' || first == b'\'') && first == last {
        return &s[1..s.len() - 1];
    }
    s
}

/// success_line, basari raporudur (STDOUT). Deger TASIMAZ — yalnizca SAYI,
/// dosya adi ve proje.
pub fn success_line(count: usize, file: &str, project: &str) -> String {
    format!("✓ Imported {count} keys from {file} into {project}\n")
}

/// override_line, UZERINE YAZILAN anahtar ADLARINI bildirir (STDERR).
///
/// Bicim Go'nun `%v`si: `[A B]` — virgul YOK. Bu bir kozmetik ayrinti degil,
/// bu satiri bir insan okuyor ve iki ikilinin ayni cumleyi basmasi
/// differential'da olculuyor.
pub fn override_line(names: &[String]) -> String {
    format!("⚠ overwrote existing keys: [{}]\n", names.join(" "))
}

/// EMPTY_INPUT_WARNING, hicbir anahtar bulunamadiginda basilan satirdir
/// (STDERR) — ve bu bir HATA DEGIL: cikis kodu 0.
pub const EMPTY_INPUT_WARNING: &str =
    "⚠ no keys found in input file (all lines were blank/comments)\n";
