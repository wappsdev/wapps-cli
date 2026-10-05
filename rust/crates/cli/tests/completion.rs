// completion: what Tab offers with the Rust binary's scripts, compared with
// what it offers with the Go binary's.
//
// The two binaries generate different scripts (cobra's ask the binary itself
// through its hidden `__complete` command; clap_complete's carry the command
// tree in the script), so their bytes are never compared. What is compared is
// the user-visible result: for each partial command line below, the words the
// shell offers on Tab. Both shells are driven for real, without a terminal of
// our own: bash through COMP_WORDS/COMP_CWORD and the function the script
// registered (tests/tab/drive.bash), zsh inside its line editor under zpty
// (tests/tab/drive.zsh). fish and PowerShell are generated (and checked to be)
// but not driven: neither shell is installed on the machine this was measured
// on (docs/PORT-kalan-yuzey.md, the completion slice).
//
// Recorded divergences, each asserted exactly rather than tolerated. They are
// what a script carrying the tree cannot know and cobra asks the binary at
// every Tab (docs/PORT-kalan-yuzey.md, the completion slice):
//
//  1. On an EMPTY word right after a command, clap_complete's bash script
//     offers that command's flags together with its subcommands, where cobra
//     offers the flags only once a `-` is typed. For such a line the Rust words
//     must be exactly the oracle's words for the line plus the oracle's words
//     for the line with `-` typed: nothing more, nothing less.
//  2. While a command's required flag is not given yet, cobra offers only the
//     required flags (`coolify update-env --` is `--app-uuid`); the scripts
//     offer every flag.
//  3. cobra drops a flag already on the line (unless it repeats); the scripts
//     still offer it (zsh drops the same spelling only: `-v` but not
//     `--verbose`).
//
// 2 and 3 are pinned by `recorded_divergences_still_diverge` on one line each.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// The partial command lines: the root, a prefix on the root, a family, a
// prefix inside a family, families of each kind, the completion command
// itself, the help command (it completes a command path), and flag positions
// on the root and on leaves (inherited root flags, a local `--project`
// shadowing the root's, pflag-style bools).
const LINES: &[&str] = &[
    "wapps ",
    "wapps s",
    "wapps secrets ",
    "wapps secrets s",
    "wapps secrets policy ",
    "wapps coolify ",
    "wapps skill ",
    "wapps dr ",
    "wapps completion ",
    "wapps help ",
    "wapps help secrets ",
    "wapps help secrets -",
    "wapps -",
    "wapps --c",
    "wapps secrets list --",
    "wapps skill install --",
    "wapps token exchange --",
    "wapps projects rm --",
    "wapps deploy --",
    "wapps completion zsh --",
];

const SHELLS: &[&str] = &["bash", "zsh"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn tab_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tab")
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-completion-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    assert!(
        !d.starts_with(repo_root()),
        "scratch inside the repo: {}",
        d.display()
    );
    d
}

// go_oracle builds the Go binary the way the release does (see helpaxis.rs).
fn go_oracle(work: &Path) -> PathBuf {
    let bin = work.join("wapps-go-completion");
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

// A side: one binary, reachable as `wapps` on PATH (cobra's scripts call it
// back by that name), with its generated scripts.
struct Side {
    name: &'static str,
    path_dir: PathBuf,
    dir: PathBuf,
}

impl Side {
    fn new(name: &'static str, bin: &Path, work: &Path) -> Side {
        let dir = work.join(name);
        let path_dir = dir.join("bin");
        std::fs::create_dir_all(&path_dir).expect("side dir");
        std::os::unix::fs::symlink(bin, path_dir.join("wapps")).expect("symlink");
        Side {
            name,
            path_dir,
            dir,
        }
    }

    fn env(&self, cmd: &mut Command, work: &Path) {
        cmd.env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.path_dir.display()))
            .env("HOME", work)
            .env("WAPPS_NO_UPDATE_CHECK", "1")
            .stdin(Stdio::null());
    }

    // script runs `wapps completion <shell> [extra]` and returns its stdout.
    fn script(&self, work: &Path, shell: &str, extra: &[&str]) -> Vec<u8> {
        let mut cmd = Command::new(self.path_dir.join("wapps"));
        cmd.arg("completion").arg(shell).args(extra);
        self.env(&mut cmd, work);
        let out = cmd.output().expect("binary could not run");
        assert!(
            out.status.success(),
            "{}: `completion {shell}` exit {:?}: {}",
            self.name,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.stdout.is_empty(),
            "{}: empty {shell} script",
            self.name
        );
        out.stdout
    }

    fn script_file(&self, work: &Path, shell: &str) -> PathBuf {
        let f = self.dir.join(format!("wapps.{shell}"));
        if !f.exists() {
            std::fs::write(&f, self.script(work, shell, &[])).expect("write script");
        }
        f
    }

    // tab: the words the shell offers on Tab at the end of `line`.
    fn tab(&self, work: &Path, cwd: &Path, shell: &str, line: &str) -> BTreeSet<String> {
        let script = self.script_file(work, shell);
        let out_file = self.dir.join("zsh.out");
        let mut cmd = match shell {
            "bash" => {
                let mut c = Command::new("/bin/bash");
                c.arg("--norc")
                    .arg("--noprofile")
                    .arg(tab_dir().join("drive.bash"))
                    .arg(&script)
                    .arg(line);
                c
            }
            "zsh" => {
                let mut c = Command::new("/bin/zsh");
                c.arg("-f")
                    .arg(tab_dir().join("drive.zsh"))
                    .arg(&script)
                    .arg(line)
                    .arg(&out_file);
                c
            }
            _ => unreachable!(),
        };
        self.env(&mut cmd, work);
        cmd.current_dir(cwd);
        let stdout = run_with_deadline(cmd, Duration::from_secs(60), &format!("{shell} {line:?}"));
        let words = match shell {
            "bash" => stdout,
            _ => std::fs::read_to_string(&out_file).expect("zsh out file"),
        };
        words
            .lines()
            .filter(|w| !w.is_empty())
            .map(String::from)
            .collect()
    }
}

// run_with_deadline: a driver that hangs (a zpty read waiting for a marker
// that never comes) must fail the test, not stall it.
fn run_with_deadline(mut cmd: Command, limit: Duration, what: &str) -> String {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{what}: could not start the driver: {e}"));
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            let out = child.wait_with_output().expect("output");
            assert!(
                status.success(),
                "{what}: driver exit {:?}: {}",
                status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            return String::from_utf8(out.stdout).expect("utf-8 words");
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            panic!("{what}: the driver did not finish in {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn shown(words: &BTreeSet<String>) -> String {
    words.iter().cloned().collect::<Vec<_>>().join(" ")
}

#[test]
fn tab_offers_the_same_words_as_the_oracle() {
    let work = scratch("tab");
    let cwd = work.join("cwd");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let go = Side::new("go", &go_oracle(&work), &work);
    let rs = Side::new("rs", Path::new(env!("CARGO_BIN_EXE_wapps")), &work);

    let mut diffs = Vec::new();
    let mut compared = 0;
    let mut divergent = 0;
    for shell in SHELLS {
        for line in LINES {
            let g = go.tab(&work, &cwd, shell, line);
            let r = rs.tab(&work, &cwd, shell, line);
            // A comparison of two empty sets proves nothing: every line here
            // offers something in the oracle.
            assert!(
                !g.is_empty(),
                "the oracle offers nothing for {shell} {line:?}"
            );
            let mut expected: BTreeSet<String> = if *shell == "bash" && line.ends_with(' ') {
                divergent += 1;
                let flags = go.tab(&work, &cwd, shell, &format!("{line}-"));
                g.union(&flags).cloned().collect()
            } else {
                g.clone()
            };
            // Slice 13.1 adds a Rust-only family; keep every legacy candidate
            // exact and require the new family only at the two root positions.
            if matches!(*line, "wapps " | "wapps help ") {
                expected.insert("broker".into());
            }
            compared += 1;
            println!("{shell} {line:?}: {}", shown(&r));
            if r != expected {
                diffs.push(format!(
                    "{shell} {line:?}\n  GO      : {}\n  expected: {}\n  RS      : {}",
                    shown(&g),
                    shown(&expected),
                    shown(&r)
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "tab parity: {compared} lines ({} shells x {} lines), {divergent} of them under the \
         recorded bash divergence, {} differ",
        SHELLS.len(),
        LINES.len(),
        diffs.len()
    );
    assert!(
        diffs.is_empty(),
        "{} of {compared} lines offer different words:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

// Divergences 2 and 3 (see the top), pinned on one line each: when either
// binary changes what it offers here, this fails, and the doc's record of the
// divergence must be updated with the test.
#[test]
fn recorded_divergences_still_diverge() {
    let work = scratch("divergences");
    let cwd = work.join("cwd");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let go = Side::new("go", &go_oracle(&work), &work);
    let rs = Side::new("rs", Path::new(env!("CARGO_BIN_EXE_wapps")), &work);
    let set = |s: &str| -> BTreeSet<String> { s.split_whitespace().map(String::from).collect() };
    let cases = [
        (
            "bash",
            "wapps coolify update-env --",
            "--app-uuid",
            "--app-uuid --config --env --help --project --verbose",
        ),
        (
            "zsh",
            "wapps coolify update-env --",
            "--app-uuid",
            "--app-uuid --config --env --help --project --verbose",
        ),
        (
            "bash",
            "wapps secrets list --verbose --",
            "--config --help --project",
            "--config --help --project --verbose",
        ),
        (
            "zsh",
            "wapps secrets list --verbose --",
            "--config --help --project",
            "--config --help --project --verbose",
        ),
    ];
    for (shell, line, go_words, rs_words) in cases {
        let g = go.tab(&work, &cwd, shell, line);
        let r = rs.tab(&work, &cwd, shell, line);
        assert_eq!(
            (shown(&g), shown(&r)),
            (shown(&set(go_words)), shown(&set(rs_words))),
            "{shell} {line:?}: the recorded divergence changed; update the doc and this test"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

// Every shell the oracle offers, the Rust binary offers too, each script
// non-empty and exit 0 (fish and PowerShell are not driven, see the top).
#[test]
fn every_shell_of_the_oracle_generates_a_script() {
    let work = scratch("shells");
    let go = Side::new("go", &go_oracle(&work), &work);
    let rs = Side::new("rs", Path::new(env!("CARGO_BIN_EXE_wapps")), &work);
    for shell in ["bash", "zsh", "fish", "powershell"] {
        go.script(&work, shell, &[]);
        let script = String::from_utf8(rs.script(&work, shell, &[])).expect("utf-8 script");
        // The script carries the tree: a leaf's name is in it.
        assert!(
            script.contains("rotate-plan"),
            "rs {shell} script lacks the tree"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

// `--no-descriptions`, as cobra's: the script offers the same words without
// the commands' and flags' descriptions.
#[test]
fn no_descriptions_drops_the_descriptions() {
    let work = scratch("nodesc");
    let rs = Side::new("rs", Path::new(env!("CARGO_BIN_EXE_wapps")), &work);
    let short = "Write every declared consumption target from the store";
    let flag = "Verbose output";
    for shell in ["zsh", "fish", "powershell"] {
        let with = String::from_utf8(rs.script(&work, shell, &[])).unwrap();
        let without = String::from_utf8(rs.script(&work, shell, &["--no-descriptions"])).unwrap();
        assert!(
            with.contains(short) && with.contains(flag),
            "{shell}: no descriptions by default"
        );
        assert!(
            !without.contains(short) && !without.contains(flag),
            "{shell}: --no-descriptions kept a description"
        );
        assert!(
            without.contains("rotate-plan"),
            "{shell}: --no-descriptions lost the tree"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}
