// The help axis: every node of the Go binary's command tree, its `--help`
// bytes compared with the Rust binary's, node by node.
//
// Why a separate comparison and not pty cases: help does not depend on the
// mode (agent or human) or on any identity arm, so it has none of the axes the
// pty corpus is built around; what it has is breadth (one page per node). The
// tree is not listed here: it is WALKED out of the oracle's own help ("Available
// Commands:"), so a node added to Go appears here without anyone writing it down.
//
// Three forms are compared for every node: `<path> --help`, `<path> -h` and
// `help <path>` (cobra's help command reaches the same page). No node is
// excepted: `completion` and its four shells are compared like every other.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-helpaxis-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("scratch");
    assert!(
        !d.starts_with(repo_root()),
        "scratch inside the repo: {}",
        d.display()
    );
    d
}

// go_oracle builds the Go binary the way the release does: the version comes
// from the ldflag, here set to the Rust crate's version (the owner's rule:
// Cargo.toml's version is the tag's).
fn go_oracle(work: &Path) -> PathBuf {
    let bin = work.join("wapps-go-helpaxis");
    let out = Command::new("go")
        .arg("build")
        .arg("-ldflags")
        .arg(format!(
            "-X github.com/wappsdev/wapps-cli/cmd.Version={}",
            env!("CARGO_PKG_VERSION")
        ))
        .arg("-o")
        .arg(&bin)
        .arg("./main.go")
        .current_dir(repo_root())
        .output()
        .expect("go build could not run");
    assert!(
        out.status.success(),
        "go build (oracle) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

fn run(bin: &Path, work: &Path, args: &[String]) -> Output {
    Command::new(bin)
        .args(args)
        .current_dir(work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", work)
        .env("WAPPS_NO_UPDATE_CHECK", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("binary could not run")
}

// children reads the subcommand names out of a cobra help page.
fn children(page: &str) -> Vec<String> {
    let Some(start) = page.find("Available Commands:\n") else {
        return Vec::new();
    };
    page[start + "Available Commands:\n".len()..]
        .lines()
        .take_while(|l| l.starts_with("  "))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect()
}

// walk visits the tree under `path` as the binary's own help describes it.
fn walk(bin: &Path, work: &Path, path: Vec<String>, out: &mut Vec<Vec<String>>) {
    let mut args = path.clone();
    args.push("--help".into());
    let page = String::from_utf8_lossy(&run(bin, work, &args).stdout).to_string();
    out.push(path.clone());
    for child in children(&page) {
        let mut next = path.clone();
        next.push(child);
        walk(bin, work, next, out);
    }
}

fn shown(o: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}--- stderr\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn every_help_page_matches_the_oracle() {
    let work = scratch();
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));

    let mut go_nodes = Vec::new();
    walk(&go, &work, Vec::new(), &mut go_nodes);
    let mut rs_nodes = Vec::new();
    walk(&rs, &work, Vec::new(), &mut rs_nodes);
    // Slice 13.1's two Rust-only nodes are explicit, not a blanket allowance
    // for any extra command. Every legacy node still compares byte-for-byte.
    let added: Vec<_> = rs_nodes
        .iter()
        .filter(|p| !go_nodes.contains(p))
        .map(|p| p.join(" "))
        .collect();
    assert_eq!(added, ["broker", "broker serve"]);
    rs_nodes.retain(|p| go_nodes.contains(p));
    assert_eq!(
        go_nodes.iter().map(|p| p.join(" ")).collect::<Vec<_>>(),
        rs_nodes.iter().map(|p| p.join(" ")).collect::<Vec<_>>(),
        "the two binaries list different command trees"
    );
    // Floor: the walk must really reach the tree (54 nodes since `completion`
    // and its four shells joined; 49 when this test landed without them).
    assert!(go_nodes.len() >= 54, "walked only {} nodes", go_nodes.len());

    let mut diffs = Vec::new();
    let mut compared = 0;
    for path in &go_nodes {
        let forms: [Vec<String>; 3] = [
            path.iter().cloned().chain(["--help".to_string()]).collect(),
            path.iter().cloned().chain(["-h".to_string()]).collect(),
            ["help".to_string()]
                .into_iter()
                .chain(path.iter().cloned())
                .collect(),
        ];
        for args in forms {
            let g = run(&go, &work, &args);
            let mut r = run(&rs, &work, &args);
            // Only this exact new root row is outside the Go oracle's surface.
            r.stdout = String::from_utf8(r.stdout)
                .unwrap()
                .replace("  broker      Local broker bridge\n", "")
                .into_bytes();
            compared += 1;
            if g.stdout != r.stdout || g.stderr != r.stderr || g.status.code() != r.status.code() {
                diffs.push(format!(
                    "=== wapps {}\n### GO\n{}### RS\n{}",
                    args.join(" "),
                    shown(&g),
                    shown(&r)
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "help axis: {} nodes, {compared} pages compared, {} differ",
        go_nodes.len(),
        diffs.len()
    );
    assert!(
        diffs.is_empty(),
        "{} of {} help pages differ:\n{}",
        diffs.len(),
        compared,
        diffs.join("\n")
    );
}

// A recorded divergence, pinned so it cannot change unseen (docs/PORT-kalan-
// yuzey.md, slice 9, "Known divergence"). An empty word before a command name:
// cobra's stripFlags skips it, so Go runs `get` (here refused, the run is not a
// terminal); clap takes it as the family's stray word, so Rust prints the
// `secrets` page with exit 0. When the port closes it, the Rust half fails:
// then compare the two outputs instead and drop the doc's paragraph.
#[test]
fn an_empty_word_before_a_command_is_a_recorded_divergence() {
    let work = scratch().join("empty-word");
    std::fs::create_dir_all(&work).expect("scratch");
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));
    let args: Vec<String> = ["secrets", "", "get"].map(String::from).to_vec();
    let family: Vec<String> = ["secrets", "--help"].map(String::from).to_vec();

    let g = run(&go, &work, &args);
    let g_family = run(&go, &work, &family);
    assert_eq!(g.status.code(), Some(1), "Go:\n{}", shown(&g));
    assert!(
        String::from_utf8_lossy(&g.stderr).contains("AGENT_MODE_REFUSED"),
        "Go no longer runs `get` after an empty word:\n{}",
        shown(&g)
    );
    assert_ne!(g.stdout, g_family.stdout, "Go printed the family page");

    let r = run(&rs, &work, &args);
    let r_family = run(&rs, &work, &family);
    assert_eq!(
        (r.status.code(), &r.stdout, &r.stderr),
        (Some(0), &r_family.stdout, &r_family.stderr),
        "Rust no longer prints the family page for an empty word; the \
         divergence may be closed, update this test and the doc:\n{}",
        shown(&r)
    );
    let _ = std::fs::remove_dir_all(&work);
}
