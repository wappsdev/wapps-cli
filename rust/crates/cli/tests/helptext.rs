// Internal spec references are FORBIDDEN in `--help` output — and the ban is
// not a convention but a MECHANISM: this test holds it.
//
// This is the port of the Go side's cmd/helptext_test.go. Why it was ported is
// concrete: clap's derive turns `///` doc comments into help text, so writing
// `///` in Rust can silently put a spec reference in front of the user. This
// estate cleaned the same dirt BY HAND for two releases and there was NO test
// guarding the cleanup.
//
// Why spec references are forbidden: the SPEC is NOT in this repo. "(§7.1)" is
// a dead pointer for a user — a reference to a document they cannot open.
use clap::{Arg, Command, CommandFactory, Parser};

// spec_ref_hits, the forbidden forms. The SAME three patterns as the Go side.
fn spec_ref_hits(line: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    // "§7.4", "(§2.1/§2.3)", "see §6" — the section sign ITSELF.
    if line.contains('§') {
        hits.push("section sign (§)");
    }
    let lower = line.to_lowercase();
    // Written without §: "SPEC 7.5", "specification 3.10".
    if has_word_then_number(&lower, &["spec", "specification"]) {
        hits.push("spec + number");
    }
    // "section 7.4", "sections 2.1" — the plain English form.
    if has_word_then_dotted_number(&lower, &["section", "sections"]) {
        hits.push("section + number");
    }
    hits
}

// has_word_then_number looks for "<word> <number>" (a dot may separate them).
fn has_word_then_number(hay: &str, words: &[&str]) -> bool {
    words.iter().any(|w| {
        hay.match_indices(w).any(|(i, _)| {
            let rest = &hay[i + w.len()..];
            let rest = rest.trim_start_matches([' ', '.', '\t']);
            rest.starts_with(|c: char| c.is_ascii_digit())
        })
    })
}

// has_word_then_dotted_number wants a DOTTED number like "section 7.4";
// "section 6" alone is not a spec reference (the same strict rule as Go's).
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

// walk returns the path of every command in the tree (the root's is empty),
// at every depth. Not a hand-written list: the Go-side cleanup stayed
// incomplete twice precisely because of a hand-written list.
fn walk(cmd: &Command, path: Vec<String>, out: &mut Vec<Vec<String>>) {
    out.push(path.clone());
    for sub in cmd.get_subcommands() {
        let mut next = path.clone();
        next.push(sub.get_name().to_string());
        walk(sub, next, out);
    }
}

// violations scans the page the binary PRINTS: cobra's layout rendered by
// cobrahelp (Short, Long, Use, every flag usage, the subcommand listing), not
// clap's own help, which `wapps` no longer prints.
fn violations(root: &Command) -> Vec<String> {
    let mut paths = Vec::new();
    walk(root, Vec::new(), &mut paths);
    let mut found = Vec::new();
    for path in paths {
        let chain = wapps::cobrahelp::chain(root, &path).expect("walked path");
        let name = chain[chain.len() - 1].get_name().to_string();
        for line in wapps::cobrahelp::help_page(&chain).lines() {
            for hit in spec_ref_hits(line) {
                found.push(format!("{name}: {hit}: {}", line.trim()));
            }
        }
    }
    found.sort();
    found
}

// THE GUARD: no command of today's tree prints a spec reference on its help
// page, and none can again.
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

// Does the walk REALLY reach the depth of the tree? A guard that walks an
// empty or shallow tree silently guards nothing.
#[test]
fn walk_reaches_whole_tree() {
    let mut paths = Vec::new();
    walk(&wapps::cli::build(), Vec::new(), &mut paths);
    let names: Vec<String> = paths.iter().map(|p| p.join(" ")).collect();
    for want in ["", "secrets", "secrets get", "secrets policy set"] {
        assert!(
            names.contains(&want.to_string()),
            "walk never reached {want:?}; saw {names:?}"
        );
    }
}

// The guard is NOT empty: in a synthetic tree, are references hidden two
// levels deep and in a flag's description caught?
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

// The clap DERIVE vector: a `///` doc comment BECOMES help text. This test
// shows it concretely — the `///` ban is not a style preference but a hole
// this detector really closes.
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
        "/// did not reach the help text: {rendered}"
    );
    assert!(
        !violations(&cmd).is_empty(),
        "the detector missed the spec reference that came through `///`"
    );
}
