//! Source-only catalog sync from wapps-platform feefd2d3da990dce70e71899ac0cf77ff18e2c64.
//! body.rs WORK_ITEMS / ASK include OPERATION_KEY; broker_mcp.rs uses those readers.
//! Frozen services/broker/test/frozen/mcp-transcript.json SHA256:
//! 22d6f6f28d7ac53bf6d33ecf2e7261520788752b71707e1fe37c1875fae4e7a8.
//! This updates the SOURCE contract, not a deployed feature or hosted MCP rollout.
use broker_oracle::{
    cloud::{Envelope, Exchange, FakeCloud, Request},
    mcp::{self, Server},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Home(PathBuf);
impl Home {
    fn new(endpoint: &str) -> Self {
        let root = broker_oracle::hermetic::temp_root(&format!(
            "catalog-key-sync-{}",
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
        fs::write(&secret, "fixture-catalog-secret").unwrap();
        fs::set_permissions(secret, fs::Permissions::from_mode(0o600)).unwrap();
        Self(root)
    }

    fn run(&self, steps: Value) -> Vec<Value> {
        let transcript = mcp::run(
            &Server {
                program: env!("CARGO_BIN_EXE_wapps").into(),
                args: vec!["broker".into(), "serve".into()],
                cwd: self.0.join("project"),
                env: vec![
                    ("HOME".into(), self.0.to_string_lossy().into()),
                    ("PATH".into(), "/usr/bin:/bin".into()),
                ],
            },
            &serde_json::from_value::<Vec<mcp::Step>>(steps).unwrap(),
        )
        .unwrap();
        transcript
            .lines()
            .filter_map(|line| line.strip_prefix("out "))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn frozen() -> Value {
    serde_json::from_str(include_str!("fixtures/broker/mcp-transcript.json")).unwrap()
}

fn assert_operation_key_schema(tools: &Value) {
    for name in ["work_add", "work_ask"] {
        let tool = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap();
        let schema = &tool["inputSchema"];
        // body.rs OPERATION_KEY: opaque ASCII identity, optional, never trimmed.
        assert_eq!(
            schema["properties"]["operationKey"],
            json!({"type":"string","minLength":1,"maxLength":128,
                "pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}),
            "{name} must advertise the body-generated operationKey contract"
        );
        assert!(!schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("operationKey")));
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[test]
fn frozen_creation_schemas_match_the_body_generated_operation_key_contract() {
    assert_operation_key_schema(&frozen()["tools/list"]["messages"][0]["result"]["tools"]);
}

#[test]
fn offline_catalog_advertises_optional_operation_keys_and_preserves_mission_routing() {
    let cloud = FakeCloud::start(vec![], None).unwrap();
    let home = Home::new(cloud.url());
    let output = home.run(json!([{"call":"tools/list"}]));
    let tools = &output[0]["result"]["tools"];
    assert_eq!(tools.as_array().unwrap().len(), 24);
    assert_operation_key_schema(tools);
    for tool in tools.as_array().unwrap() {
        assert_eq!(
            tool["inputSchema"]["properties"]["missionId"],
            json!({"type":"string","pattern":"^[a-z0-9][a-z0-9._-]{0,127}$","maxLength":128})
        );
        assert!(tool["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("missionId")));
        if !["work_add", "work_ask"].contains(&tool["name"].as_str().unwrap()) {
            assert!(tool["inputSchema"]["properties"]
                .get("operationKey")
                .is_none());
        }
    }
    assert!(
        cloud.requests().is_empty(),
        "listing must not discover tools or create a mission"
    );
}

#[test]
fn creation_calls_preserve_opaque_operation_keys_and_unchanged_legacy_results() {
    let fixture = frozen();
    let mut exchanges = Vec::new();
    let mut steps = Vec::new();
    let mut expected = Vec::new();
    for name in ["work_add", "work_ask"] {
        for key in [
            None,
            Some("Operation.1_:-".to_owned()),
            Some("A".repeat(128)),
        ] {
            let case = &fixture[format!("{name} success")];
            let mut args = case["args"].clone();
            if let Some(key) = key {
                args["operationKey"] = json!(key);
            }
            let id = steps.len();
            let answer = case["result"].clone();
            exchanges.push(Exchange {
                id: format!("catalog-{id}"),
                route: String::new(),
                principal: None,
                request: Request {
                    method: "POST".into(),
                    path: "/v1/missions/catalog-key-sync/mcp".into(),
                    body: Some(
                        json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                        "params":{"name":name,"arguments":args}})
                        .to_string(),
                    ),
                },
                status: 200,
                envelope: Envelope {
                    content_type: "text/event-stream".into(),
                    retry_after: None,
                },
                body: format!(
                    "event: message\ndata: {}\n\n",
                    json!({"jsonrpc":"2.0","id":id,"result":answer})
                ),
            });
            args["missionId"] = json!("catalog-key-sync");
            steps.push(json!({"tool":name,"arguments":args}));
            expected.push(answer);
        }
    }
    let cloud = FakeCloud::start(exchanges, None).unwrap();
    let home = Home::new(cloud.url());
    let output = home.run(json!(steps));
    assert_eq!(output.len(), 6);
    for (actual, expected) in output.iter().zip(expected) {
        assert_eq!(actual["result"], expected);
    }
    assert!(cloud.unanswered().is_empty());
    assert!(cloud
        .requests()
        .iter()
        .all(|request| request.answered.is_some() && !request.leaked));
}
