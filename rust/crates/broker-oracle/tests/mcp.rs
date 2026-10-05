// The transcript runner is seam 2's measuring instrument. It is tested against
// the fake peer acting as a stdio MCP server, so every byte it should record is
// known in advance.
use broker_oracle::hermetic::temp_root;
use broker_oracle::mcp::{self, Server, Step};
use broker_oracle::peer::{self, PeerConfig, Step as PeerStep};
use serde_json::json;
use std::path::PathBuf;

fn server(tag: &str, script: Vec<PeerStep>) -> Server {
    let root = temp_root(tag);
    let exe = root.join("bin/mcp-server");
    let config = PeerConfig {
        kind: "server".to_string(),
        record_dir: root.join("records"),
        script,
        idle_ms: 2_000,
        expect_timeout_ms: 10_000,
    };
    peer::install(
        &PathBuf::from(env!("CARGO_BIN_EXE_broker-oracle-fake")),
        &exe,
        &config,
    )
    .unwrap();
    Server {
        program: exe,
        args: vec![],
        cwd: root,
        env: vec![("HOME".to_string(), "/nowhere".to_string())],
    }
}

fn text(id: &str, body: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": body.to_string()}]}})
}

fn steps(value: serde_json::Value) -> Vec<Step> {
    serde_json::from_value(value).unwrap()
}

#[test]
fn a_script_is_played_one_request_at_a_time_with_captures_and_polling() {
    let s = server(
        "mcp-play",
        vec![
            PeerStep::Expect(json!({"method": "initialize"})),
            PeerStep::Send(
                json!({"jsonrpc": "2.0", "id": "{{id}}", "result": {"protocolVersion": "2025-06-18"}}),
            ),
            PeerStep::Expect(json!({"params": {"name": "orchestrator_claim"}})),
            PeerStep::Send(
                json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}),
            ),
            PeerStep::Send(text(
                "{{id}}",
                json!({"capability": "cap-1", "fencingToken": 1}),
            )),
            PeerStep::Expect(
                json!({"params": {"name": "agent_submit", "arguments": {"capability": "cap-1", "fencingToken": 1}}}),
            ),
            PeerStep::Send(text("{{id}}", json!({"jobId": "j1"}))),
            PeerStep::Expect(
                json!({"params": {"name": "agent_status", "arguments": {"jobId": "j1"}}}),
            ),
            PeerStep::Send(text("{{id}}", json!({"state": "running"}))),
            PeerStep::Expect(
                json!({"params": {"name": "agent_status", "arguments": {"jobId": "j1"}}}),
            ),
            PeerStep::Send(text("{{id}}", json!({"state": "completed"}))),
        ],
    );
    let script = steps(json!([
        {"call": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"notify": "notifications/initialized"},
        {"tool": "orchestrator_claim", "arguments": {"missionId": "m"},
         "capture": {"cap": "capability", "fence": "fencingToken"}},
        {"tool": "agent_submit", "arguments": {"missionId": "m", "capability": "{{cap}}", "fencingToken": "{{fence}}"},
         "capture": {"job": "jobId"}},
        {"tool": "agent_status", "arguments": {"missionId": "m", "jobId": "{{job}}"},
         "until": {"state": "completed"}, "poll_ms": 10}
    ]));
    let transcript = mcp::run(&s, &script).unwrap();
    let expected = [
        r#"in {"id":0,"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"out {"id":0,"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"}}"#,
        r#"in {"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"in {"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"missionId":"m"},"name":"orchestrator_claim"}}"#,
        r#"out {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#,
        r#"out {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"{\"capability\":\"cap-1\",\"fencingToken\":1}","type":"text"}]}}"#,
        r#"in {"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"capability":"cap-1","fencingToken":1,"missionId":"m"},"name":"agent_submit"}}"#,
        r#"out {"id":2,"jsonrpc":"2.0","result":{"content":[{"text":"{\"jobId\":\"j1\"}","type":"text"}]}}"#,
        r#"in {"id":3,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"jobId":"j1","missionId":"m"},"name":"agent_status"}}"#,
        r#"out {"id":3,"jsonrpc":"2.0","result":{"content":[{"text":"{\"state\":\"completed\"}","type":"text"}]}}"#,
        "",
    ]
    .join("\n");
    assert_eq!(transcript, expected);
}

#[test]
fn a_server_that_does_not_answer_fails_the_run_and_names_the_step() {
    let s = server(
        "mcp-silent",
        vec![PeerStep::Expect(json!({"method": "nothing-ever"}))],
    );
    let script = steps(json!([
        {"call": "initialize", "params": {}, "timeout_ms": 300}
    ]));
    let err = mcp::run(&s, &script).unwrap_err();
    assert!(err.contains("step 1"), "{err}");
    assert!(err.contains("initialize"), "{err}");
}

#[test]
fn a_poll_that_never_reaches_its_state_fails_with_the_last_answer() {
    // 2,000 ms at one poll per 20 ms is at most 100 polls, well inside the 200
    // answers scripted here, and long enough for a first answer under load.
    let mut script = vec![PeerStep::Expect(json!({"method": "tools/call"}))];
    for _ in 0..200 {
        script.push(PeerStep::Send(text("{{id}}", json!({"state": "running"}))));
        script.push(PeerStep::Expect(json!({"method": "tools/call"})));
    }
    let s = server("mcp-poll", script);
    let steps = steps(json!([
        {"tool": "agent_status", "arguments": {}, "until": {"state": "completed"}, "poll_ms": 20, "timeout_ms": 2000}
    ]));
    let err = mcp::run(&s, &steps).unwrap_err();
    assert!(err.contains("running"), "{err}");
}

#[test]
fn a_capture_that_names_nothing_is_an_error() {
    let s = server(
        "mcp-capture",
        vec![
            PeerStep::Expect(json!({"method": "tools/call"})),
            PeerStep::Send(text("{{id}}", json!({"jobId": "j1"}))),
        ],
    );
    let steps = steps(json!([
        {"tool": "agent_submit", "arguments": {}, "capture": {"job": "missing"}}
    ]));
    let err = mcp::run(&s, &steps).unwrap_err();
    assert!(err.contains("missing"), "{err}");
}
