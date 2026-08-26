// exec'in SIZINTI YUZEYI: korpus testi, Go ORACLE.
//
// Scrubber, `secrets exec`in alt-surecinin stdout/stderr'ini saran streaming
// redaktordur: enjekte edilen her gizli DEGERIN tam gecisini `***` yapar.
// Onemli olan kolay kol degil — asil davranis CHUNK SINIRLARINDA: bir sir iki
// ayri okumaya bolundugunde yine yakalanmali, yoksa "arada bir" transcript'e
// dusen bir sizinti olur ve o tam olarak tekrar uretilemeyen sinif hatadir.
//
// Iki taraf da AYNI goldenlara bagli:
// internal/agentmode/testdata/scrub_corpus.json (Go uretiyor, Go dogruluyor).
//
// GERCEK SIR YOK: korpustaki her dize uydurma bir test dizesidir.
use std::path::{Path, PathBuf};
use wapps::scrubber::{filter_scrubbable, Scrubber};

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
    values: Vec<String>,
    chunks: Vec<String>,
    want_filtered: Vec<String>,
    want_note: String,
    want_out: String,
}

fn corpus() -> Vec<Case> {
    let p = repo_root().join("internal/agentmode/testdata/scrub_corpus.json");
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("korpus okunamadi ({}): {e}", p.display()));
    serde_json::from_str(&raw).expect("korpus JSON'u cozulemedi")
}

// run_case, URETIM sirasini birebir tekrarlar (Go: runWithInjectedEnv):
// once filter_scrubbable, sonra ONUN sonucuyla Scrubber.
fn run_case(c: &Case) -> (Vec<String>, String, String) {
    let mut note: Vec<u8> = Vec::new();
    let filtered = filter_scrubbable(&c.values, Some(&mut note));

    let mut out: Vec<u8> = Vec::new();
    {
        let mut s = Scrubber::new(&mut out, &filtered);
        for chunk in &c.chunks {
            s.write_all(chunk.as_bytes()).expect("yazim");
        }
        s.flush().expect("flush");
    }
    (
        filtered,
        String::from_utf8_lossy(&note).into_owned(),
        String::from_utf8_lossy(&out).into_owned(),
    )
}

#[test]
fn scrubber_matches_the_go_corpus_case_for_case() {
    let cases = corpus();
    // Bos bir korpus da "fark yok" derdi.
    assert!(cases.len() >= 20, "korpus yalnizca {} vaka tasiyor", cases.len());
    let mut bad = Vec::new();
    for c in &cases {
        let (filtered, note, out) = run_case(c);
        if out != c.want_out {
            bad.push(format!("{} out:\n  want: {:?}\n  got:  {:?}", c.name, c.want_out, out));
        }
        if note != c.want_note {
            bad.push(format!("{} note:\n  want: {:?}\n  got:  {:?}", c.name, c.want_note, note));
        }
        if filtered != c.want_filtered {
            bad.push(format!(
                "{} filtered:\n  want: {:?}\n  got:  {:?}",
                c.name, c.want_filtered, filtered
            ));
        }
    }
    assert!(bad.is_empty(), "{} ayrisma:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_corpus_actually_exercises_the_hard_parts() {
    // Hicbir seyi redakte etmeyen, hic chunk bolmeyen bir korpus da "gecer"
    // ve hicbir mutasyonu yakalamaz.
    let cases = corpus();
    let redacted = cases.iter().filter(|c| c.want_out.contains("***")).count();
    let untouched = cases.iter().filter(|c| c.want_out == c.chunks.concat()).count();
    let multi_chunk = cases.iter().filter(|c| c.chunks.len() > 1).count();
    let noted = cases.iter().filter(|c| !c.want_note.is_empty()).count();
    let filtered_out =
        cases.iter().filter(|c| c.want_filtered.len() < c.values.len()).count();
    assert!(
        redacted > 0 && untouched > 0 && multi_chunk > 0 && noted > 0 && filtered_out > 0,
        "korpus bir kolu kaciriyor: redacted={redacted} untouched={untouched} \
         multi_chunk={multi_chunk} noted={noted} filtered_out={filtered_out}"
    );
}
