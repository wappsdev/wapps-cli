// trustrepo is the `wapps secrets trust-repo` verb: it pins the repo→project
// binding in the TRUSTED home dir (repo-pins.json).
//
// ORACLE: cmd/secrets/trustrepo.go.
//
// WHY A SEPARATE VERB: a `.wapps.yaml` gives a project NAME, but that file
// lives inside the repo and is attacker-writable content (the confused-deputy
// seam). The pin is kept in the home dir, NOT in the repo; an agent can NEVER
// write it.
//
// TWO THINGS differ from the inline prompt here, and both are kept ON PURPOSE
// (Go does the same):
//
//  1. THE CONFIRMATION WORD IS ONLY "y" (EqualFold, so "Y" works too). The
//     inline binding prompt (configctx::bind_prompt) also accepts "yes"; this
//     one does not. Folding both prompts into one function would silently
//     erase the difference.
//  2. THE PROMPT GOES TO STDOUT (Go: cmd.OutOrStdout()), unlike the inline
//     prompt (stderr).
use crate::wappsyaml::WappsYaml;
use std::io::{BufRead, BufReader, Read, Write};

/// prompt_block is the block showing the binding to pin, every source a sync
/// would read (configctx::sync_reads_block, owner decision B), and the
/// question line. NO trailing newline: the question ends where the answer is
/// typed.
pub fn prompt_block(repo_id: &str, cfg: &WappsYaml) -> String {
    let mut s = String::from("Pin repo→project binding:\n");
    s.push_str(&format!("  repo:    {repo_id}\n"));
    s.push_str(&format!("  project: {}\n", cfg.project));
    s.push_str(&format!("  backend: {}\n", cfg.backend));
    if !cfg.profiles.is_empty() {
        // A BTreeMap is already alphabetical: Go sorts the names with
        // sort.Strings, the same order.
        let names: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
        s.push_str(&format!("  profiles: {}\n", names.join(", ")));
    }
    s.push_str(&crate::configctx::sync_reads_block(cfg));
    s.push_str("Pin this binding? [y/N]: ");
    s
}

/// short_repo shortens a long repo identity for DISPLAY (not a value).
/// Go: longer than 60 → "…" + the last 59 bytes.
pub fn short_repo(s: &str) -> String {
    if s.len() > 60 {
        // Go slices BYTES (s[len(s)-59:]). The identity is a path/URL, so in
        // practice ASCII; the cut is still rounded up to a char boundary so
        // no invalid UTF-8 is produced.
        let start = s.len() - 59;
        let mut i = start;
        while i < s.len() && !s.is_char_boundary(i) {
            i += 1;
        }
        return format!("…{}", &s[i..]);
    }
    s.to_string()
}

/// success_line is the single line printed after pinning.
pub fn success_line(repo_id: &str, project: &str) -> String {
    format!("pinned {} → {project}\n", short_repo(repo_id))
}

/// confirm_y writes the prompt and reports whether the answer is "y" (case
/// insensitive). "yes" is NOT accepted (Go: strings.EqualFold(line, "y")).
/// EOF is a refusal too.
pub fn confirm_y<R: Read, W: Write>(r: &mut R, w: &mut W, prompt: &str) -> bool {
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    // Go uses bufio.Reader.ReadString('\n') and SWALLOWS THE ERROR: at EOF
    // the partial line read is still evaluated. read_line keeps what it read
    // the same way, so "y" (no newline, EOF) is accepted on BOTH sides.
    let _ = BufReader::new(r).read_line(&mut line);
    line.trim().eq_ignore_ascii_case("y")
}
