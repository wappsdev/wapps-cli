//! The fake `claude` and `codex` workers (seam 1).
//!
//! One binary, `broker-oracle-fake`, copied to wherever the system under test
//! looks for a worker: first on `PATH` as `codex`, or over the Agent SDK's
//! bundled `claude`. Its configuration is a sidecar file next to the copy
//! (`<copy>.oracle.json`) and never an environment variable, because what the
//! fake is there to observe is the environment the daemon chose to give the
//! worker: codex workers get an allowlist of nine names, and a variable the
//! harness needed would either be stripped or would falsify the recording.
//!
//! The fake records, per launch, one text file `<kind>-<n>.txt`:
//!
//! ```text
//! launch {"kind":..,"program":..,"argv":[..],"cwd":..,"env":[names]}
//! in <a line the daemon wrote to the worker's stdin, verbatim>
//! out <a line the fake wrote back>
//! end <eof | idle | eof-before <pattern> | timeout-before <pattern> | ...>
//! ```
//!
//! Environment VALUES are never recorded: the worker's environment is where a
//! secret would be, and a recording is a file that gets committed.
//!
//! It answers from a script of `expect` and `send` steps. `expect` reads lines
//! until one matches a subset pattern; `send` writes one frame, whose `{{path}}`
//! placeholders are filled from the frame `expect` last matched (the request id
//! the answer must echo). After the script it keeps reading, so every frame
//! the daemon sends is recorded, until stdin closes or `idle_ms` passes quietly.

use crate::template::{fill, matches, pointer_lookup};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// Read stdin until a frame matches this pattern.
    Expect(Value),
    /// Write this frame, placeholders filled from the last matched frame.
    Send(Value),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerConfig {
    /// `claude` or `codex`: names the record files.
    pub kind: String,
    pub record_dir: PathBuf,
    pub script: Vec<Step>,
    /// After the script, how long a quiet stdin is waited on before stopping.
    pub idle_ms: u64,
    /// How long one `expect` waits for its frame.
    pub expect_timeout_ms: u64,
}

/// Exit code of a fake that did not hear what its script expected.
pub const EXIT_SCRIPT_UNMET: i32 = 3;
/// Exit code of a fake that could not run at all (no or bad configuration).
pub const EXIT_CONFIG: i32 = 2;

pub fn sidecar_path(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".oracle.json");
    PathBuf::from(name)
}

/// Puts a copy of the fake at `at`, with its script beside it.
pub fn install(fake: &Path, at: &Path, config: &PeerConfig) -> io::Result<()> {
    if let Some(parent) = at.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(fake, at)?;
    let text = serde_json::to_string_pretty(config).map_err(io::Error::other)?;
    fs::write(sidecar_path(at), text + "\n")
}

/// Every record in `dir`, ordered by kind and then launch number.
pub fn records(dir: &Path) -> io::Result<Vec<(String, String)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".txt") else {
            continue;
        };
        let Some((kind, n)) = stem.rsplit_once('-') else {
            continue;
        };
        let Ok(n) = n.parse::<u32>() else { continue };
        found.push(((kind.to_string(), n), name));
    }
    found.sort();
    found
        .into_iter()
        .map(|(_, name)| Ok((name.clone(), fs::read_to_string(dir.join(&name))?)))
        .collect()
}

#[derive(Serialize)]
struct Launch<'a> {
    kind: &'a str,
    program: String,
    argv: Vec<String>,
    cwd: String,
    env: Vec<String>,
}

struct Recorder {
    file: File,
}

impl Recorder {
    fn create(dir: &Path, kind: &str) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        for n in 1.. {
            let path = dir.join(format!("{kind}-{n}.txt"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(Self { file }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!("an unbounded range ends only by returning")
    }

    // Written and flushed line by line: the daemon may kill the worker at any
    // moment, and a recording that dies in a buffer is no recording.
    fn line(&mut self, tag: &str, text: &str) {
        let _ = writeln!(self.file, "{tag} {text}");
        let _ = self.file.flush();
    }
}

fn spawn_reader() -> Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stdin = BufReader::new(io::stdin().lock());
        loop {
            let mut line = Vec::new();
            match stdin.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) => {
                    if line.ends_with(b"\n") {
                        line.pop();
                    }
                    if tx.send(Some(line)).is_err() {
                        return;
                    }
                }
            }
        }
    });
    rx
}

fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// The fake's whole life, from its own executable path. Returns the exit code.
pub fn run_from_exe() -> i32 {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("broker-oracle-fake: cannot find itself: {e}");
            return EXIT_CONFIG;
        }
    };
    let sidecar = sidecar_path(&exe);
    let config: PeerConfig = match fs::read_to_string(&sidecar)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
    {
        Ok(config) => config,
        Err(e) => {
            eprintln!("broker-oracle-fake: no usable {}: {e}", sidecar.display());
            return EXIT_CONFIG;
        }
    };
    let mut args = std::env::args_os();
    let program = args
        .next()
        .map(|a| {
            Path::new(&a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let mut env: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    env.sort();
    let launch = Launch {
        kind: &config.kind,
        program,
        argv: args.map(|a| a.to_string_lossy().into_owned()).collect(),
        cwd: std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        env,
    };
    let mut recorder = match Recorder::create(&config.record_dir, &config.kind) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("broker-oracle-fake: cannot record: {e}");
            return EXIT_CONFIG;
        }
    };
    recorder.line(
        "launch",
        &serde_json::to_string(&launch).unwrap_or_default(),
    );
    play(
        &config,
        &mut recorder,
        &spawn_reader(),
        &mut io::stdout().lock(),
    )
}

fn play(
    config: &PeerConfig,
    recorder: &mut Recorder,
    input: &Receiver<Option<Vec<u8>>>,
    output: &mut impl Write,
) -> i32 {
    let mut last = Value::Null;
    let expect_timeout = Duration::from_millis(config.expect_timeout_ms);
    for step in &config.script {
        match step {
            Step::Expect(pattern) => loop {
                match input.recv_timeout(expect_timeout) {
                    Ok(Some(line)) => {
                        let text = String::from_utf8_lossy(&line);
                        recorder.line("in", &text);
                        if let Ok(frame) = serde_json::from_str::<Value>(&text) {
                            if matches(pattern, &frame) {
                                last = frame;
                                break;
                            }
                        }
                    }
                    Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                        recorder.line("end", &format!("eof-before {}", compact(pattern)));
                        return EXIT_SCRIPT_UNMET;
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        recorder.line("end", &format!("timeout-before {}", compact(pattern)));
                        return EXIT_SCRIPT_UNMET;
                    }
                }
            },
            Step::Send(frame) => {
                let filled = match fill(frame, &pointer_lookup(&last)) {
                    Ok(filled) => compact(&filled),
                    Err(e) => {
                        recorder.line("end", &format!("error {e}"));
                        return EXIT_CONFIG;
                    }
                };
                if writeln!(output, "{filled}")
                    .and_then(|()| output.flush())
                    .is_err()
                {
                    recorder.line("end", "stdout-closed");
                    return 0;
                }
                recorder.line("out", &filled);
            }
        }
    }
    let idle = Duration::from_millis(config.idle_ms);
    loop {
        match input.recv_timeout(idle) {
            Ok(Some(line)) => recorder.line("in", &String::from_utf8_lossy(&line)),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                recorder.line("end", "eof");
                return 0;
            }
            Err(RecvTimeoutError::Timeout) => {
                recorder.line("end", "idle");
                return 0;
            }
        }
    }
}
