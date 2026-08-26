// safelog KORPUS testi: Go ORACLE, fikstur TEK dosya.
//
// Neden ayri bir korpus dosyasi ve neden Go tarafinda: RedactPatterns bir
// HEURISTIC ve heuristiklerin sinir vakalari (geri izleme, ASCII \b, sinif
// sayimi) elle yeniden turetilemez. Iki taraf da AYNI goldenlara bagli:
// internal/safelog/testdata/redact_corpus.json. Go'nun cikti uretimi degisirse
// ORADAKI test kirilir; buradaki port ayrisirsa BU test kirilir.
//
// GERCEK SIR YOK: korpustaki her dize uydurma bir BICIM ornegi.
use std::path::{Path, PathBuf};
use wapps::safelog;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "in")]
    input: String,
    want: String,
}

fn corpus() -> Vec<Case> {
    let p = repo_root().join("internal/safelog/testdata/redact_corpus.json");
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("korpus okunamadi ({}): {e}", p.display()));
    serde_json::from_str(&raw).expect("korpus JSON'u cozulemedi")
}

#[test]
fn redaction_matches_the_go_corpus_case_for_case() {
    let cases = corpus();
    // Bos bir korpus da "fark yok" derdi.
    assert!(cases.len() >= 20, "korpus yalnizca {} vaka tasiyor", cases.len());
    let mut bad = Vec::new();
    for c in &cases {
        let got = safelog::redact_patterns(&c.input);
        if got != c.want {
            bad.push(format!(
                "{}:\n  in:   {:?}\n  want: {:?}\n  got:  {:?}",
                c.name, c.input, c.want, got
            ));
        }
    }
    assert!(bad.is_empty(), "{} vaka ayristi:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_corpus_actually_redacts_something() {
    // Hicbir seyi redakte etmeyen bir korpus, redaksiyonu kaldiran bir
    // mutasyonu yakalayamazdi.
    let cases = corpus();
    let jwt = cases.iter().filter(|c| c.want != c.input && !c.want.contains("[REDACTED:")).count();
    let token = cases.iter().filter(|c| c.want.contains("[REDACTED:")).count();
    let untouched = cases.iter().filter(|c| c.want == c.input).count();
    assert!(jwt > 0 && token > 0 && untouched > 0, "jwt={jwt} token={token} untouched={untouched}");
}
