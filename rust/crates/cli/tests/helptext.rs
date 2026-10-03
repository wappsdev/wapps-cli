// `--help` ciktisinda ic-spesifikasyon referansi YASAK — ve yasak bir
// konvansiyon degil, bir MEKANIZMA: bu test onu tutuyor.
//
// Bu, Go tarafindaki cmd/helptext_test.go'nun portudur. Neden port edildigi
// somut: clap'in derive'i `///` doc yorumlarini yardim metnine cevirir, yani
// Rust'ta `///` yazmak bir spec referansini sessizce kullanicinin yuzune
// basabilir. Bu estate ayni kiri iki release boyunca ELLE temizledi ve temizligi
// koruyan bir test YOKTU.
//
// Neden SPEC referansi yasak: SPEC bu depoda YOK. "(§7.1)" bir kullanici icin
// olu bir isaret — acamayacagi bir belgeye yapilan referans.
use clap::{Arg, Command, CommandFactory, Parser};

// spec_ref_patterns, yasak biciler. Go tarafindaki uc desenin AYNISI.
fn spec_ref_hits(line: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    // "§7.4", "(§2.1/§2.3)", "bkz. §6" — bolum isaretinin KENDISI.
    if line.contains('§') {
        hits.push("section sign (§)");
    }
    let lower = line.to_lowercase();
    // § olmadan yazilmis hali: "SPEC 7.5", "specification 3.10".
    if has_word_then_number(&lower, &["spec", "specification"]) {
        hits.push("spec + number");
    }
    // "section 7.4", "sections 2.1" — duz Ingilizce karsiligi.
    if has_word_then_dotted_number(&lower, &["section", "sections"]) {
        hits.push("section + number");
    }
    hits
}

// has_word_then_number, "<kelime> <sayi>" (nokta ayrik olabilir) arar.
fn has_word_then_number(hay: &str, words: &[&str]) -> bool {
    words.iter().any(|w| {
        hay.match_indices(w).any(|(i, _)| {
            let rest = &hay[i + w.len()..];
            let rest = rest.trim_start_matches([' ', '.', '\t']);
            rest.starts_with(|c: char| c.is_ascii_digit())
        })
    })
}

// has_word_then_dotted_number, "section 7.4" gibi NOKTALI sayi ister; "section 6"
// tek basina bir spec referansi sayilmaz (Go tarafiyla ayni siki kural).
fn has_word_then_dotted_number(hay: &str, words: &[&str]) -> bool {
    words.iter().any(|w| {
        hay.match_indices(w).any(|(i, _)| {
            let rest = &hay[i + w.len()..];
            if !rest.starts_with(' ') {
                return false;
            }
            let rest = rest.trim_start();
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            num.contains('.') && num.split('.').all(|p| !p.is_empty())
        })
    })
}

// walk, agacin TAMAMINI (kok dahil, her derinlikte) doner. Elle yazilmis bir
// liste DEGIL: Go tarafindaki temizlik tam da elle liste yuzunden iki kez eksik
// kaldi.
fn walk(cmd: &Command) -> Vec<Command> {
    let mut out = vec![cmd.clone()];
    for sub in cmd.get_subcommands() {
        out.extend(walk(sub));
    }
    out
}

fn violations(root: &Command) -> Vec<String> {
    let mut found = Vec::new();
    for mut c in walk(root) {
        let path = c.get_name().to_string();
        let help = c.render_long_help().to_string();
        for line in help.lines() {
            for hit in spec_ref_hits(line) {
                found.push(format!("{path}: {hit}: {}", line.trim()));
            }
        }
    }
    found.sort();
    found
}

// ASIL KORUMA: bugunku agacin hicbir komutunun yardim metni bir spec referansi
// icermiyor, ve bir daha iceremez.
#[test]
fn help_text_carries_no_spec_references() {
    let v = violations(&wapps::cli::build());
    assert!(
        v.is_empty(),
        "--help output must carry no spec references ({} found):\n  {}",
        v.len(),
        v.join("\n  ")
    );
}

// Gezinti GERCEKTEN agacin derinine iniyor mu? Bos/sig gezen bir koruma sessizce
// hicbir seyi korumaz.
#[test]
fn walk_reaches_whole_tree() {
    let names: Vec<String> = walk(&wapps::cli::build())
        .iter()
        .map(|c| c.get_name().to_string())
        .collect();
    for want in ["wapps", "secrets", "get"] {
        assert!(
            names.contains(&want.to_string()),
            "walk never reached {want}; saw {names:?}"
        );
    }
    // 2. seviyeye ULASTIGININ iddiasi (kontrol listesi degil).
    assert!(
        names.len() >= 3,
        "walk visited only {} commands",
        names.len()
    );
}

// Koruma BOS DEGIL: sentetik bir agacta, iki seviye derinde ve bir bayrak
// aciklamasinda gizlenmis referanslar yakalaniyor mu?
#[test]
fn detector_catches_hidden_references() {
    let leaf = Command::new("leaf")
        .about("First line is clean.\nSecond line derives the KEK (HKDF §2.3) and is not.")
        .arg(
            Arg::new("out")
                .long("out")
                .help("write the env file (SPEC 7.5 format)"),
        )
        .subcommand(Command::new("deep").about("reads the ledger, see section 6.2"));
    let root = Command::new("fake").subcommand(Command::new("mid").subcommand(leaf));
    let joined = violations(&root).join("\n");
    for want in ["HKDF §2.3", "SPEC 7.5", "section 6.2"] {
        assert!(
            joined.contains(want),
            "detector missed {want}; found:\n{joined}"
        );
    }
}

// clap DERIVE vektoru: `///` doc yorumu yardim metnine DONUSUYOR. Bu test onu
// somut olarak gosteriyor — yani `///` yasagi bir uslup tercihi degil, bu
// detektorun gercekten kapattigi bir delik.
#[derive(Parser)]
#[command(name = "derivecanary")]
struct DeriveCanary {
    /// rotates the DEK (§4.11) before writing
    #[arg(long)]
    #[allow(dead_code)]
    rotate: bool,
}

#[test]
fn doc_comments_leak_into_help_and_are_caught() {
    let cmd = DeriveCanary::command();
    let rendered = cmd.clone().render_long_help().to_string();
    assert!(
        rendered.contains("§4.11"),
        "/// yardim metnine girmedi: {rendered}"
    );
    assert!(
        !violations(&cmd).is_empty(),
        "detektor `///` uzerinden gelen spec referansini kacirdi"
    );
}
