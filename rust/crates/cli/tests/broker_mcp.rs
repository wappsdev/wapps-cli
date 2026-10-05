//! Slice 13.1 exercises the real stdio binary, with broker-oracle's strict HTTP peer.
use broker_oracle::{
    cloud::{Envelope, Exchange, FakeCloud, Request},
    mcp::{self, Server, Step},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const SECRET: &str = "fixture-access-secret-never-disclose";
struct Home(PathBuf);
impl Home {
    fn new(endpoint: &str) -> Self {
        let root = broker_oracle::hermetic::temp_root(&format!(
            "bridge-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("project")).unwrap();
        fs::create_dir_all(root.join(".agent-broker")).unwrap();
        fs::create_dir_all(root.join(".config/wapps-broker")).unwrap();
        fs::write(
            root.join(".agent-broker/projects.json"),
            json!({"version":1,"projects":{"local-project":{"root":root.join("project")}}})
                .to_string(),
        )
        .unwrap();
        fs::write(
            root.join(".config/wapps-broker/client.yaml"),
            format!("clientId: fixture-client\nendpoint: {endpoint}\n"),
        )
        .unwrap();
        let secret = root.join(".config/wapps-broker/agents.secret");
        fs::write(&secret, SECRET).unwrap();
        fs::set_permissions(secret, fs::Permissions::from_mode(0o600)).unwrap();
        Self(root)
    }
    fn run(&self, steps: Value) -> String {
        let script: Vec<Step> = serde_json::from_value(steps).unwrap();
        mcp::run(
            &Server {
                program: env!("CARGO_BIN_EXE_wapps").into(),
                args: vec!["broker".into(), "serve".into()],
                cwd: self.0.join("project"),
                env: vec![
                    ("HOME".into(), self.0.to_string_lossy().into()),
                    ("PATH".into(), "/usr/bin:/bin".into()),
                ],
            },
            &script,
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
// Raw peer for malformed frames and in-flight cancellation, which the sequential
// oracle runner deliberately cannot express. Every receive has a hard deadline.
struct Peer {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    output: std::sync::mpsc::Receiver<Value>,
}
impl Peer {
    fn new(home: &Home) -> Self {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let mut child = Command::new(env!("CARGO_BIN_EXE_wapps"))
            .args(["broker", "serve"])
            .current_dir(home.0.join("project"))
            .env_clear()
            .env("HOME", &home.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(value) = serde_json::from_str(&line) else {
                    break;
                };
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            output,
        }
    }
    fn send(&mut self, frame: &str) {
        use std::io::Write;
        writeln!(self.stdin.as_mut().unwrap(), "{frame}").unwrap();
    }
    fn receive(&self) -> Value {
        self.output
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("one bounded MCP reply")
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn answers(transcript: &str) -> Vec<Value> {
    transcript
        .lines()
        .filter_map(|s| s.strip_prefix("out "))
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn exchange(id: u64, mission: &str, tool: &str, args: Value, result: Value) -> Exchange {
    Exchange { id: format!("{id}-{mission}-{tool}"), route: String::new(), principal: None, request: Request { method: "POST".into(), path: format!("/v1/missions/{mission}/mcp"), body: Some(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}}).to_string()) }, status:200, envelope:Envelope {content_type:"text/event-stream".into(), retry_after:None}, body:format!("event: message\ndata: {}\n\n",json!({"jsonrpc":"2.0","id":id,"result":result})) }
}
fn result(v: Value) -> Value {
    json!({"content":[{"type":"text","text":v.to_string()}],"structuredContent":v})
}
fn frozen() -> Value {
    serde_json::from_str(include_str!("fixtures/broker/mcp-transcript.json")).unwrap()
}

#[test]
fn forwards_every_available_cloud_shape_and_result() {
    let fixture = frozen();
    let mut exchanges = vec![];
    let mut steps = vec![];
    let mut expected = vec![];
    for tool in fixture["tools/list"]["messages"][0]["result"]["tools"]
        .as_array()
        .unwrap()
    {
        let name = tool["name"].as_str().unwrap();
        if [
            "agent_submit",
            "agent_cancel",
            "agent_attach",
            "agent_report",
            "agent_await",
        ]
        .contains(&name)
        {
            continue;
        }
        for outcome in ["success", "refusal"] {
            let case = &fixture[format!("{name} {outcome}")];
            let args = case["args"].clone();
            let answer = case["result"].clone();
            // These two frozen refusals reject missionId as an unknown cloud
            // field. It is required local routing metadata now, so their exact
            // cloud call is unrepresentable; local mission refusals cover it.
            if args.get("missionId").is_some() {
                continue;
            }
            let id = steps.len() as u64;
            exchanges.push(exchange(
                id,
                "mcp-transcript",
                name,
                args.clone(),
                answer.clone(),
            ));
            let mut local = args;
            local["missionId"] = json!("mcp-transcript");
            steps.push(json!({"tool":name,"arguments":local}));
            expected.push(answer);
        }
    }
    let cloud = FakeCloud::start(exchanges, Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let output = answers(&home.run(json!(steps)));
    assert_eq!(output.len(), 36);
    assert_eq!(output.len(), expected.len());
    for (actual, expected) in output.iter().zip(expected) {
        assert_eq!(actual["result"], expected);
    }
    assert!(cloud.unanswered().is_empty());
    assert!(cloud
        .requests()
        .iter()
        .all(|r| r.access && !r.leaked && r.answered.is_some()));
}

#[test]
fn rejects_invalid_missions_without_network_or_ambient_fallback() {
    let cloud = FakeCloud::start(vec![], Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let mut steps = vec![json!({"tool":"work_list","arguments":{}})];
    for mission in [
        "",
        "../beta",
        "alpha/beta",
        "ALPHA",
        "a%2fb",
        "a?x",
        "a#x",
        " a",
        "a\\nb",
        &"a".repeat(129),
    ] {
        steps.push(json!({"tool":"work_list","arguments":{"missionId":mission}}));
    }
    let output = answers(&home.run(json!(steps)));
    assert!(output.iter().all(|r| r["result"]["isError"] == true
        && r["result"]["structuredContent"]["error"] == "INVALID_ARGUMENT"));
    assert!(cloud.requests().is_empty());
}

#[test]
fn execution_tools_are_explicitly_unavailable_and_handoffs_unknown() {
    let cloud = FakeCloud::start(vec![], None).unwrap();
    let home = Home::new(cloud.url());
    let fixture = frozen();
    let mut steps = Vec::new();
    for name in [
        "agent_submit",
        "agent_cancel",
        "agent_attach",
        "agent_report",
    ] {
        for outcome in ["success", "refusal"] {
            let mut args = fixture[format!("{name} {outcome}")]["args"].clone();
            args["missionId"] = json!("alpha");
            steps.push(json!({"tool":name,"arguments":args}));
        }
    }
    for name in ["orchestrator_prepare_handoff", "orchestrator_takeover"] {
        steps.push(json!({"tool":name,"arguments":{"missionId":"alpha"}}));
    }
    let output = answers(&home.run(json!(steps)));
    assert_eq!(output.len(), 10);
    for r in &output[..8] {
        assert_eq!(
            r["result"]["structuredContent"]["error"],
            "ACTION_UNAVAILABLE"
        );
    }
    for r in &output[8..] {
        assert_eq!(r["error"]["code"], -32602);
    }
    assert!(cloud.requests().is_empty());
}

#[test]
fn catalog_keeps_all_cloud_required_fields_and_targeting_shapes() {
    let cloud = FakeCloud::start(vec![], None).unwrap();
    let home = Home::new(cloud.url());
    let output = answers(&home.run(json!([{"call":"tools/list"}])));
    let fixture = frozen();
    for (local, cloud) in output[0]["result"]["tools"].as_array().unwrap().iter().zip(
        fixture["tools/list"]["messages"][0]["result"]["tools"]
            .as_array()
            .unwrap(),
    ) {
        let mut shape = local["inputSchema"].clone();
        shape["properties"]
            .as_object_mut()
            .unwrap()
            .remove("missionId");
        shape["required"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v != "missionId");
        if cloud["name"] == "agent_await" {
            shape["properties"]
                .as_object_mut()
                .unwrap()
                .remove("waitMs");
        }
        if cloud["inputSchema"].get("required").is_none() {
            shape.as_object_mut().unwrap().remove("required");
        }
        assert_eq!(shape, cloud["inputSchema"], "{}", cloud["name"]);
    }
}

#[test]
fn await_bounds_wait_and_strips_only_local_wait_metadata() {
    let cloud = FakeCloud::start(
        vec![exchange(
            0,
            "alpha",
            "agent_await",
            json!({"sinceDigest":"cursor"}),
            result(json!({"changed":false,"attention":{"digest":"cursor"}})),
        )],
        None,
    )
    .unwrap();
    let home = Home::new(cloud.url());
    let started = std::time::Instant::now();
    let output = answers(&home.run(json!([
        {"tool":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"cursor","waitMs":30}},
        {"tool":"agent_await","arguments":{"missionId":"alpha","waitMs":55001}},
        {"tool":"agent_await","arguments":{"missionId":"alpha","waitMs":-1}}
    ])));
    assert_eq!(output[0]["result"]["structuredContent"]["changed"], false);
    assert!(
        output[0]["result"]["structuredContent"]["waitedMs"]
            .as_u64()
            .unwrap()
            >= 30
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    for r in &output[1..] {
        assert_eq!(
            r["result"]["structuredContent"]["error"],
            "INVALID_ARGUMENT"
        );
    }
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 1);
}

#[test]
fn redacts_read_secrets_and_exact_runtime_secret_in_both_result_representations() {
    let cloud=FakeCloud::start(vec![exchange(0,"alpha","agent_status",json!({"jobId":"job-a"}), result(json!({"job":{"id":"job-a","capability":"job-secret","apiToken":"private-token","output":format!("echo {SECRET}")}}))),exchange(1,"alpha","orchestrator_claim",json!({"provider":"claude"}), result(json!({"capability":"new-lease-capability","fencingToken":1})))],Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let transcript = home.run(json!([
        {"tool":"agent_status","arguments":{"missionId":"alpha","jobId":"job-a"}},
        {"tool":"orchestrator_claim","arguments":{"missionId":"alpha","provider":"claude"}}
    ]));
    assert!(!transcript.contains(SECRET));
    assert!(!transcript.contains("job-secret"));
    assert!(!transcript.contains("private-token"));
    assert_eq!(
        answers(&transcript)[1]["result"]["structuredContent"]["capability"],
        "new-lease-capability"
    );
}

#[test]
fn credentials_and_enrollment_fail_closed_without_printing_secrets() {
    use std::process::Command;
    for case in [
        "missing-secret",
        "public-secret",
        "symlink-secret",
        "missing-enrollment",
        "bad-enrollment",
        "unenrolled",
        "missing-client",
        "invalid-client",
        "bad-secret",
    ] {
        let home = Home::new("http://127.0.0.1:9");
        let secret = home.0.join(".config/wapps-broker/agents.secret");
        match case {
            "missing-secret" => fs::remove_file(&secret).unwrap(),
            "public-secret" => {
                fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "symlink-secret" => {
                fs::rename(&secret, secret.with_extension("real")).unwrap();
                std::os::unix::fs::symlink(secret.with_extension("real"), &secret).unwrap();
            }
            "missing-enrollment" => {
                fs::remove_file(home.0.join(".agent-broker/projects.json")).unwrap()
            }
            "bad-enrollment" => {
                fs::write(home.0.join(".agent-broker/projects.json"), SECRET).unwrap()
            }
            "unenrolled" => fs::write(
                home.0.join(".agent-broker/projects.json"),
                r#"{"version":1,"projects":{}}"#,
            )
            .unwrap(),
            "missing-client" => {
                fs::remove_file(home.0.join(".config/wapps-broker/client.yaml")).unwrap()
            }
            "invalid-client" => fs::write(
                home.0.join(".config/wapps-broker/client.yaml"),
                format!("clientId: [\"{SECRET}\"]"),
            )
            .unwrap(),
            "bad-secret" => fs::write(&secret, format!("{SECRET}\nheader: attack")).unwrap(),
            _ => unreachable!(),
        }
        let output = Command::new(env!("CARGO_BIN_EXE_wapps"))
            .args(["broker", "serve"])
            .current_dir(home.0.join("project"))
            .env_clear()
            .env("HOME", &home.0)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(output.stdout.is_empty(), "{case}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(SECRET), "{case}");
        assert!(stderr.contains("broker:"), "{case}: {stderr}");
        assert!(
            !home.0.join(".claude").exists(),
            "serve must not auto-install a skill"
        );
    }
}

#[test]
fn lists_without_choosing_or_creating_a_mission() {
    let cloud = FakeCloud::start(vec![], Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let output = answers(&home.run(json!([
        {"call":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}},
        {"notify":"notifications/initialized"}, {"call":"tools/list"}
    ])));
    assert_eq!(output[0]["result"]["protocolVersion"], "2025-06-18");
    let tools = output[1]["result"]["tools"]
        .as_array()
        .expect("a tool list");
    assert_eq!(tools.len(), 24);
    for tool in tools {
        assert!(!tool["name"].as_str().unwrap().contains("handoff"));
        assert!(tool["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("missionId")));
    }
    assert!(
        cloud.requests().is_empty(),
        "listing must not manufacture a mission"
    );
}

#[test]
fn routes_two_missions_and_preserves_work_and_job_selection() {
    let authority = json!({"capability":"lease-capability", "fencingToken":1});
    let cloud = FakeCloud::start(
        vec![
            exchange(
                0,
                "alpha",
                "work_close",
                json!({"authority":authority,"workItemId":"task-a","reason":"delivered"}),
                result(json!({"closed":"task-a"})),
            ),
            exchange(
                1,
                "beta",
                "agent_status",
                json!({"jobId":"job-b"}),
                result(json!({"job":{"id":"job-b"},"attention":{"digest":"beta-digest"}})),
            ),
        ],
        Some(SECRET.into()),
    )
    .unwrap();
    let home = Home::new(cloud.url());
    let output=answers(&home.run(json!([
        {"tool":"work_close","arguments":{"missionId":"alpha","authority":authority,"workItemId":"task-a","reason":"delivered"}},
        {"tool":"agent_status","arguments":{"missionId":"beta","jobId":"job-b"}}
    ])));
    assert_eq!(output[0]["result"]["structuredContent"]["closed"], "task-a");
    assert_eq!(
        output[1]["result"]["structuredContent"]["job"]["id"],
        "job-b"
    );
    assert!(cloud.unanswered().is_empty());
    assert!(cloud
        .requests()
        .iter()
        .all(|r| r.access && !r.leaked && r.answered.is_some()));
}

#[test]
fn malformed_frames_are_refused_without_echo_and_stream_recovers() {
    let cloud = FakeCloud::start(vec![], None).unwrap();
    let home = Home::new(cloud.url());
    let mut peer = Peer::new(&home);
    for (frame, code) in [
        (format!("{{{SECRET}"), -32700),
        ("[]".into(), -32600),
        (r#"{"id":1,"method":"ping"}"#.into(), -32600),
        (
            r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#.into(),
            -32600,
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"unknown"}"#.into(),
            -32601,
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}"#.into(),
            -32602,
        ),
    ] {
        peer.send(&frame);
        let reply = peer.receive();
        assert_eq!(reply["error"]["code"], code);
        assert!(!reply.to_string().contains(SECRET));
    }
    peer.send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
    assert_eq!(peer.receive(), json!({"jsonrpc":"2.0","id":2,"result":{}}));
    assert!(cloud.requests().is_empty());
}

#[test]
fn cancellation_interrupts_await_and_does_not_cancel_another_mission() {
    let cloud = FakeCloud::start(
        vec![
            exchange(
                1,
                "alpha",
                "agent_await",
                json!({"sinceDigest":"cursor"}),
                result(json!({"changed":false,"attention":{"digest":"cursor"}})),
            ),
            exchange(
                2,
                "beta",
                "agent_status",
                json!({"jobId":"job-b"}),
                result(json!({"job":{"id":"job-b"}})),
            ),
        ],
        None,
    )
    .unwrap();
    let home = Home::new(cloud.url());
    let mut peer = Peer::new(&home);
    peer.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"cursor"}}}).to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while cloud.requests().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(cloud.requests().len(), 1);
    peer.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#);
    let reply = peer.receive();
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["structuredContent"]["error"], "CANCELLED");
    peer.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"agent_status","arguments":{"missionId":"beta","jobId":"job-b"}}}"#);
    assert_eq!(
        peer.receive()["result"]["structuredContent"]["job"]["id"],
        "job-b"
    );
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 2);
}

#[test]
fn runtime_secret_never_escapes_in_rpc_ids() {
    let cloud = FakeCloud::start(vec![], Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let mut peer = Peer::new(&home);
    peer.send(&json!({"jsonrpc":"2.0","id":SECRET,"method":"ping"}).to_string());
    let reply = peer.receive();
    assert!(!reply.to_string().contains(SECRET));
    assert!(reply["id"].is_null());
}

#[test]
fn oversized_secret_is_not_silently_truncated_into_a_valid_credential() {
    let home = Home::new("http://127.0.0.1:9");
    fs::write(
        home.0.join(".config/wapps-broker/agents.secret"),
        format!("{SECRET}{}", "\n".repeat(5000)),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wapps"))
        .args(["broker", "serve"])
        .current_dir(home.0.join("project"))
        .env_clear()
        .env("HOME", &home.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

#[test]
fn wrong_mission_task_and_job_refusals_are_not_retried_elsewhere() {
    let authority = json!({"capability":"beta-lease","fencingToken":2});
    // Source-backed NOT_FOUND envelopes, with synthetic mission/item identifiers:
    // platform's frozen surface-transcript.json:4607 and mcp-transcript.json's
    // agent_status refusal. This tests bridge routing, not a fake's authorization.
    let mut denied_task = result(
        json!({"error":"NOT_FOUND","message":"no work item task-a in this mission","recovery":"check the id against GET /v1/missions/<mission>/work; nothing was changed","retryable":false,"details":{"refusal":"unknown_work_item","mission":"beta","missing":["task-a"]}}),
    );
    denied_task["isError"] = json!(true);
    let mut denied_job = result(
        json!({"error":"NOT_FOUND","message":"no job job-a in this mission","recovery":"check the id against GET /v1/missions/<mission>/jobs; nothing was changed","retryable":false,"details":{"refusal":"unknown_job","mission":"beta","missing":["job-a"]}}),
    );
    denied_job["isError"] = json!(true);
    let cloud = FakeCloud::start(
        vec![
            exchange(
                0,
                "alpha",
                "agent_status",
                json!({"jobId":"job-a"}),
                result(json!({"job":{"id":"job-a"}})),
            ),
            exchange(
                1,
                "beta",
                "agent_status",
                json!({"jobId":"job-a"}),
                denied_job.clone(),
            ),
            exchange(
                2,
                "beta",
                "work_close",
                json!({"authority":authority,"workItemId":"task-a","reason":"delivered"}),
                denied_task.clone(),
            ),
        ],
        None,
    )
    .unwrap();
    let home = Home::new(cloud.url());
    let output=answers(&home.run(json!([
        {"tool":"agent_status","arguments":{"missionId":"alpha","jobId":"job-a"}},
        {"tool":"agent_status","arguments":{"missionId":"beta","jobId":"job-a"}},
        {"tool":"work_close","arguments":{"missionId":"beta","authority":authority,"workItemId":"task-a","reason":"delivered"}}
    ])));
    assert_eq!(
        output[0]["result"]["structuredContent"]["job"]["id"],
        "job-a"
    );
    assert_eq!(output[1]["result"], denied_job);
    assert_eq!(output[2]["result"], denied_task);
    assert!(output[1]["result"]["isError"] == true && output[2]["result"]["isError"] == true);
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 3);
}

#[test]
fn relay_is_forwarded_but_human_confirmation_is_not_an_agent_tool() {
    let fixture = frozen();
    let args = fixture["work_relay_answer success"]["args"].clone();
    let cloud = FakeCloud::start(
        vec![exchange(
            0,
            "alpha",
            "work_relay_answer",
            args.clone(),
            fixture["work_relay_answer success"]["result"].clone(),
        )],
        None,
    )
    .unwrap();
    let mut local = args;
    local["missionId"] = json!("alpha");
    let home = Home::new(cloud.url());
    let output = answers(&home.run(json!([
        {"tool":"work_relay_answer","arguments":local},
        {"tool":"work_confirm","arguments":{"missionId":"alpha","questionId":"q"}},
        {"tool":"work_answer","arguments":{"missionId":"alpha","questionId":"q","answer":"yes"}},
        {"tool":"work_accept","arguments":{"missionId":"alpha","questionId":"q"}}
    ])));
    assert_ne!(output[0]["result"]["isError"], true);
    for reply in &output[1..] {
        assert_eq!(reply["error"]["code"], -32602);
    }
    assert_eq!(cloud.requests().len(), 1);
    assert!(cloud.unanswered().is_empty());
}

#[test]
fn await_polls_until_changed_and_preserves_cloud_attention_projection() {
    let mut changed = frozen()["agent_await success"]["result"].clone();
    changed["structuredContent"]["changed"] = json!(true);
    let cloud = FakeCloud::start(
        vec![
            exchange(
                0,
                "alpha",
                "agent_await",
                json!({"sinceDigest":"cursor"}),
                result(json!({"changed":false,"attention":{"digest":"cursor"}})),
            ),
            exchange(
                0,
                "alpha",
                "agent_await",
                json!({"sinceDigest":"cursor"}),
                changed.clone(),
            ),
        ],
        None,
    )
    .unwrap();
    let home = Home::new(cloud.url());
    let output=answers(&home.run(json!([
        {"tool":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"cursor","waitMs":3000}}
    ])));
    assert_eq!(
        output[0]["result"]["structuredContent"]["attention"],
        changed["structuredContent"]["attention"]
    );
    assert_eq!(output[0]["result"]["structuredContent"]["changed"], true);
    assert!(
        output[0]["result"]["structuredContent"]["waitedMs"]
            .as_u64()
            .unwrap()
            >= 2000
    );
    assert_eq!(cloud.requests().len(), 2);
    assert!(cloud.unanswered().is_empty());
}

#[test]
fn refuses_http_and_malformed_responses_without_echoing_bodies_or_retrying() {
    for (status, content_type, body, code) in [
        (302, "text/html", SECRET.to_owned(), "CLOUD_HTTP"),
        (
            403,
            "application/json",
            format!("{{\"secret\":\"{SECRET}\"}}"),
            "CLOUD_HTTP",
        ),
        (200, "text/html", SECRET.to_owned(), "CLOUD_PROTOCOL"),
        (200, "application/json", SECRET.to_owned(), "CLOUD_PROTOCOL"),
        (
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":99,"result":{}}"#.into(),
            "CLOUD_PROTOCOL",
        ),
        (
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":0,"result":{},"error":{}}"#.into(),
            "CLOUD_PROTOCOL",
        ),
        (
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":0,"result":null}"#.into(),
            "CLOUD_PROTOCOL",
        ),
        (
            200,
            "application/json",
            "x".repeat(4 * 1024 * 1024 + 1),
            "CLOUD_PROTOCOL",
        ),
    ] {
        let mut case = exchange(0, "alpha", "work_list", json!({}), json!({}));
        case.status = status;
        case.envelope.content_type = content_type.into();
        case.body = body;
        let cloud = FakeCloud::start(vec![case], Some(SECRET.into())).unwrap();
        let home = Home::new(cloud.url());
        let transcript = home.run(json!([{"tool":"work_list","arguments":{"missionId":"alpha"}}]));
        assert_eq!(
            answers(&transcript)[0]["result"]["structuredContent"]["error"],
            code,
            "{status} {content_type}"
        );
        assert!(!transcript.contains(SECRET));
        assert_eq!(cloud.requests().len(), 1);
    }
}

#[test]
fn stalled_http_is_bounded_by_the_await_deadline() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let home = Home::new(&format!("http://{}", listener.local_addr().unwrap()));
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let _ = stream.read(&mut [0; 4096]);
        std::thread::sleep(std::time::Duration::from_millis(150));
    });
    let started = std::time::Instant::now();
    let output=answers(&home.run(json!([{"tool":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"cursor","waitMs":50}}])));
    assert_eq!(
        output[0]["result"]["structuredContent"]["error"],
        "CLOUD_TRANSPORT"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    server.join().unwrap();
}

#[test]
fn escaped_runtime_credentials_are_rejected_before_http_serialization() {
    let escaped = "fixture-with-quote\"and-backslash\\";
    let cloud = FakeCloud::start(vec![], Some(escaped.into())).unwrap();
    let home = Home::new(cloud.url());
    fs::write(home.0.join(".config/wapps-broker/agents.secret"), escaped).unwrap();
    let output = answers(&home.run(json!([
        {"tool":"work_ask","arguments":{"missionId":"alpha","question":escaped}},
        {"tool":"work_ask","arguments":{"missionId":"alpha","items":[{"note":escaped}]}}
    ])));
    for reply in output {
        assert_eq!(
            reply["result"]["structuredContent"]["error"],
            "INVALID_ARGUMENT"
        );
    }
    assert!(cloud.requests().is_empty());
}

#[test]
fn runtime_credential_cannot_be_used_as_a_mission_url_segment() {
    let cloud = FakeCloud::start(vec![], Some(SECRET.into())).unwrap();
    let home = Home::new(cloud.url());
    let output = answers(&home.run(json!([{"tool":"work_list","arguments":{"missionId":SECRET}}])));
    assert_eq!(
        output[0]["result"]["structuredContent"]["error"],
        "INVALID_ARGUMENT"
    );
    assert!(cloud.requests().is_empty());
}

#[test]
fn rejects_hardlinks_repository_metadata_and_overlapping_roots() {
    for case in [
        "hardlink",
        "metadata",
        "overlap",
        "config-root",
        "http-origin",
    ] {
        let home = Home::new("http://127.0.0.1:9");
        let config = home.0.join(".config/wapps-broker");
        match case {
            "hardlink" => fs::hard_link(config.join("agents.secret"), home.0.join("project/secret-link")).unwrap(),
            "metadata" => {
                fs::rename(config.join("client.yaml"),home.0.join("project/client.yaml")).unwrap();
                std::os::unix::fs::symlink(home.0.join("project/client.yaml"),config.join("client.yaml")).unwrap();
            },
            "overlap" => fs::write(home.0.join(".agent-broker/projects.json"),json!({"version":1,"projects":{"first":{"root":home.0.join("project")},"second":{"root":home.0.join("project")}}}).to_string()).unwrap(),
            "config-root" => fs::write(home.0.join(".agent-broker/projects.json"),json!({"version":1,"projects":{"first":{"root":home.0}}}).to_string()).unwrap(),
            "http-origin" => fs::write(config.join("client.yaml"),"clientId: fixture\nendpoint: http://example.com\n").unwrap(),
            _ => unreachable!(),
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_wapps"))
            .args(["broker", "serve"])
            .current_dir(home.0.join("project"))
            .env_clear()
            .env("HOME", &home.0)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    }
}

#[test]
fn in_flight_limit_and_duplicate_ids_do_not_block_ping_or_cancellation() {
    let exchanges = (0..16)
        .map(|id| {
            exchange(
                id,
                "alpha",
                "agent_await",
                json!({"sinceDigest":"cursor"}),
                result(json!({"changed":false,"attention":{"digest":"cursor"}})),
            )
        })
        .collect();
    let cloud = FakeCloud::start(exchanges, None).unwrap();
    let home = Home::new(cloud.url());
    let mut peer = Peer::new(&home);
    for id in 0..16 {
        peer.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"cursor"}}}).to_string());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while cloud.requests().len() < 16 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(cloud.requests().len(), 16);
    peer.send(r#"{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"work_list","arguments":{"missionId":"beta"}}}"#);
    assert_eq!(
        peer.receive()["result"]["structuredContent"]["error"],
        "SERVER_BUSY"
    );
    peer.send(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#);
    assert_eq!(peer.receive()["error"]["code"], -32600);
    peer.send(r#"{"jsonrpc":"2.0","id":17,"method":"ping"}"#);
    assert_eq!(peer.receive()["result"], json!({}));
    for id in 0..16 {
        peer.send(
            &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}})
                .to_string(),
        );
    }
    let mut cancelled = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let reply = peer.receive();
        assert_eq!(reply["result"]["structuredContent"]["error"], "CANCELLED");
        cancelled.insert(reply["id"].as_u64().unwrap());
    }
    assert_eq!(cancelled.len(), 16);
    assert_eq!(cloud.requests().len(), 16);
}

#[test]
fn oversized_input_terminates_without_echoing_the_frame() {
    use std::io::Write;
    let home = Home::new("http://127.0.0.1:9");
    let mut peer = Peer::new(&home);
    let _ = peer
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&vec![b'x'; 1024 * 1024 + 2]);
    peer.stdin.take();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = peer.child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "oversize frame did not terminate"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(peer
        .output
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
}
