// `wapps skill`: the parts the pty differential cannot see.
//
// The differential compares what two binaries wrote; a defect both share (the
// wrong embedded text, a fingerprint computed the same wrong way) would read
// EQUAL. These pin the Rust side to the Go SOURCE instead.
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn go_skill_src() -> String {
    std::fs::read_to_string(repo_root().join("cmd/skill/skill.go")).expect("cmd/skill/skill.go")
}

// go_string_expr evaluates the Go string expression that starts at `s`: raw
// (`...`) and interpreted ("...", no escapes beyond \" needed here) literals
// joined by `+`, up to the first `,` outside a literal.
fn go_string_expr(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s.trim_start();
    loop {
        let (quote, body_start) = match rest.chars().next() {
            Some('`') => ('`', 1),
            Some('"') => ('"', 1),
            other => panic!("unexpected token {other:?} in Go string expression"),
        };
        let end = rest[body_start..].find(quote).expect("closing quote") + body_start;
        out.push_str(&rest[body_start..end]);
        rest = rest[end + 1..].trim_start();
        match rest.strip_prefix('+') {
            Some(r) => rest = r.trim_start(),
            None => return out,
        }
    }
}

// field returns the evaluated `<name>: <expr>` of the cobra.Command declared
// as `var <var> = &cobra.Command{`.
fn field(src: &str, var: &str, name: &str) -> String {
    let decl = format!("var {var} = &cobra.Command{{");
    let at = src.find(&decl).unwrap_or_else(|| panic!("{decl}"));
    let body = &src[at..];
    let f = body
        .find(&format!("\t{name}: "))
        .unwrap_or_else(|| panic!("{var}.{name}"));
    go_string_expr(&body[f + name.len() + 3..])
}

#[test]
fn the_embedded_skill_is_go_s_asset_byte_for_byte() {
    let go = std::fs::read(repo_root().join("internal/skill/assets/wapps-secrets/SKILL.md"))
        .expect("Go asset");
    assert_eq!(wapps::skill::SKILL_MD.as_bytes(), go.as_slice());
}

#[test]
fn the_fingerprint_is_the_one_the_go_binary_writes() {
    // Read from the `.fingerprint` marker a Go `wapps skill install` wrote,
    // with the asset at this commit. It changes whenever SKILL.md does; the
    // test above then says whether both binaries still embed the same text.
    assert_eq!(
        wapps::skill::fingerprint(),
        "3a6443b64e40aede7151c8e10f5d4454f72747ed7d68179cc3b12f7005e99ced"
    );
}

#[test]
fn the_fingerprint_follows_go_s_framing() {
    // sha256 over, per file in name order: name, NUL, content, NUL.
    let mut framed = b"SKILL.md\0".to_vec();
    framed.extend_from_slice(wapps::skill::SKILL_MD.as_bytes());
    framed.push(0);
    let d = ring::digest::digest(&ring::digest::SHA256, &framed);
    let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(wapps::skill::fingerprint(), hex);
}

#[test]
fn the_help_texts_are_go_s_byte_for_byte() {
    let src = go_skill_src();
    let mut cmd = wapps::cli::build();
    let skill = cmd.find_subcommand_mut("skill").expect("skill");
    assert_eq!(
        skill.get_about().expect("about").to_string(),
        field(&src, "SkillCmd", "Short")
    );
    assert_eq!(
        skill.get_long_about().expect("long_about").to_string(),
        field(&src, "SkillCmd", "Long")
    );
    for (leaf, var) in [
        ("install", "installCmd"),
        ("status", "statusCmd"),
        ("uninstall", "uninstallCmd"),
    ] {
        let c = skill.find_subcommand_mut(leaf).expect(leaf);
        assert_eq!(
            c.get_about().expect("about").to_string(),
            field(&src, var, "Short"),
            "{leaf} Short"
        );
    }
    let install = skill.find_subcommand_mut("install").unwrap();
    assert_eq!(
        install.get_long_about().expect("long_about").to_string(),
        field(&src, "installCmd", "Long")
    );
}
