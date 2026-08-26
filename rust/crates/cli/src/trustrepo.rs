// trustrepo, `wapps secrets trust-repo` fiilidir: depo→proje baglamasini
// GUVENILEN home-dir'de (repo-pins.json) pinler.
//
// ORACLE: cmd/secrets/trustrepo.go.
//
// NEDEN AYRI BIR FIIL: bir `.wapps.yaml` bir proje ADI verir, ama o dosya
// deponun icinde durur ve saldirgan-yazilabilir icerktir (confused-deputy
// dikisi). Pin depoda DEGIL, home-dir'de tutulur; bir ajan onu ASLA yazamaz.
//
// IKI SEY BURADA GO'DAN AYRILIYOR ve ikisi de KASITLI korunuyor:
//
//  1. ONAY KELIMESI YALNIZCA "y" (EqualFold, yani "Y" da olur). Satir ici
//     baglama istemi (configctx::bind_prompt) "yes"i de kabul ediyor; bu
//     etmiyor. Iki istemi tek fonksiyona indirmek farki sessizce silerdi.
//  2. ISTEM STDOUT'A gidiyor (Go: cmd.OutOrStdout()), satir ici isteminin
//     aksine (o stderr'e).
use crate::wappsyaml::WappsYaml;
use std::io::{BufRead, BufReader, Read, Write};

/// prompt_block, pinlenecek baglamayi gosteren blok + soru satiridir.
/// Sonda newline YOK: soru satiri cevabin yazilacagi yerde biter.
pub fn prompt_block(repo_id: &str, cfg: &WappsYaml) -> String {
    let mut s = String::from("Pin repo→project binding:\n");
    s.push_str(&format!("  repo:    {repo_id}\n"));
    s.push_str(&format!("  project: {}\n", cfg.project));
    s.push_str(&format!("  backend: {}\n", cfg.backend));
    if !cfg.profiles.is_empty() {
        // BTreeMap zaten alfabetik: Go tarafi names'i sort.Strings ile
        // siraliyor, ayni sira.
        let names: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
        s.push_str(&format!("  profiles: {}\n", names.join(", ")));
    }
    s.push_str("Pin this binding? [y/N]: ");
    s
}

/// short_repo, uzun bir depo kimligini GORUNTU icin kisaltir (deger degil).
/// Go: 60'tan uzunsa "…" + son 59 karakter.
pub fn short_repo(s: &str) -> String {
    if s.len() > 60 {
        // Go BAYT dilimliyor (s[len(s)-59:]). Kimlik bir yol/URL oldugu icin
        // pratikte ASCII; yine de bayt sinirinda kalmak icin karakter sinirina
        // yuvarlaniyor ki gecersiz UTF-8 uretmeyelim.
        let start = s.len() - 59;
        let mut i = start;
        while i < s.len() && !s.is_char_boundary(i) {
            i += 1;
        }
        return format!("…{}", &s[i..]);
    }
    s.to_string()
}

/// success_line, pinleme sonrasi basilan tek satirdir.
pub fn success_line(repo_id: &str, project: &str) -> String {
    format!("pinned {} → {project}\n", short_repo(repo_id))
}

/// confirm_y, istemi yazar ve cevabin "y" (buyuk/kucuk harf farketmez)
/// oldugunu doner. "yes" KABUL EDILMEZ — Go'da strings.EqualFold(line, "y").
/// EOF de ret.
pub fn confirm_y<R: Read, W: Write>(r: &mut R, w: &mut W, prompt: &str) -> bool {
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    // Go bufio.Reader.ReadString('\n') kullaniyor ve HATAYI YUTUYOR: EOF'ta
    // okunan kismi satir yine degerlendiriliyor. read_line de ayni sekilde
    // okunani birakir, yani "y" (newline'siz, EOF) IKI tarafta da gecerli.
    let _ = BufReader::new(r).read_line(&mut line);
    line.trim().eq_ignore_ascii_case("y")
}
