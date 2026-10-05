// The fake worker is the oracle's eyes on seam 1: whatever it records is what
// the comparison sees. These tests drive the real binary over real pipes.
use broker_oracle::hermetic::temp_root;
use broker_oracle::peer::{self, PeerConfig, Step};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fake() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_broker-oracle-fake"))
}

fn codex_script() -> Vec<Step> {
    vec![
        Step::Expect(json!({"method": "initialize"})),
        Step::Send(json!({"jsonrpc": "2.0", "id": "{{id}}", "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "codex-oracle", "version": "0"}}})),
        Step::Expect(json!({"method": "tools/call"})),
        Step::Send(json!({"jsonrpc": "2.0", "method": "codex/event",
            "params": {"msg": {"type": "agent_message", "message": "working"}}})),
        Step::Send(json!({"jsonrpc": "2.0", "id": "{{id}}", "result": {
            "content": [{"type": "text", "text": "done"}]}})),
    ]
}

fn install(dir: &Path, name: &str, script: Vec<Step>, idle_ms: u64) -> PathBuf {
    let config = PeerConfig {
        kind: name.to_string(),
        record_dir: dir.join("records"),
        script,
        idle_ms,
        expect_timeout_ms: 10_000,
    };
    let exe = dir.join("bin").join(name);
    peer::install(&fake(), &exe, &config).unwrap();
    exe
}

#[test]
fn the_codex_fake_answers_an_mcp_client_and_records_every_frame() {
    let root = temp_root("peer-codex");
    let exe = install(&root, "codex", codex_script(), 5_000);
    let cwd = root.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let mut child = Command::new(&exe)
        .arg("mcp-server")
        .current_dir(&cwd)
        .env_clear()
        .env("HOME", "/nowhere")
        .env("SECRET_TOKEN", "do-not-record-this-value")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdout.read_line(&mut line).unwrap();
    assert!(line.contains(r#""id":0"#), "{line}");
    assert!(line.contains("codex-oracle"), "{line}");

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"codex"}}}}"#
    )
    .unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert!(line.contains("codex/event"), "{line}");
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert!(
        line.contains(r#""id":1"#) && line.contains("done"),
        "{line}"
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());

    let records = peer::records(&root.join("records")).unwrap();
    assert_eq!(records.len(), 1);
    let (name, text) = &records[0];
    assert_eq!(name, "codex-1.txt");
    let real_cwd = std::fs::canonicalize(&cwd).unwrap();
    let launch = format!(
        r#"launch {{"kind":"codex","program":"codex","argv":["mcp-server"],"cwd":{},"env":["HOME","SECRET_TOKEN"]}}"#,
        serde_json::to_string(&real_cwd.to_string_lossy()).unwrap()
    );
    let expected = [
        launch.as_str(),
        r#"in {"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#,
        r#"out {"id":0,"jsonrpc":"2.0","result":{"capabilities":{"tools":{}},"protocolVersion":"2025-06-18","serverInfo":{"name":"codex-oracle","version":"0"}}}"#,
        r#"in {"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"in {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"codex"}}"#,
        r#"out {"jsonrpc":"2.0","method":"codex/event","params":{"msg":{"message":"working","type":"agent_message"}}}"#,
        r#"out {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"done","type":"text"}]}}"#,
        "end eof",
        "",
    ]
    .join("\n");
    assert_eq!(text, &expected);
    assert!(!text.contains("do-not-record-this-value"));
}

#[test]
fn each_launch_gets_its_own_numbered_record() {
    let root = temp_root("peer-two");
    let exe = install(&root, "claude", vec![], 200);
    for _ in 0..2 {
        let status = Command::new(&exe)
            .arg("--version")
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    let names: Vec<String> = peer::records(&root.join("records"))
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["claude-1.txt", "claude-2.txt"]);
}

#[test]
fn a_peer_that_never_hears_what_it_expects_says_so_and_fails() {
    let root = temp_root("peer-timeout");
    let exe = install(
        &root,
        "codex",
        vec![Step::Expect(json!({"method": "initialize"}))],
        200,
    );
    let mut child = Command::new(&exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"method":"something-else"}}"#).unwrap();
    drop(stdin);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(3));
    let (_, text) = &peer::records(&root.join("records")).unwrap()[0];
    assert!(
        text.ends_with("end eof-before {\"method\":\"initialize\"}\n"),
        "{text}"
    );
}

#[test]
fn a_peer_that_is_never_closed_stops_after_its_idle_window() {
    let root = temp_root("peer-idle");
    let exe = install(&root, "codex", vec![], 300);
    let mut child = Command::new(&exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let _held_open = child.stdin.take().unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    let (_, text) = &peer::records(&root.join("records")).unwrap()[0];
    assert!(text.ends_with("end idle\n"), "{text}");
}
