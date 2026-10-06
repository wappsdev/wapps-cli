//! Offline source-reference checks, not skill installation or agent-behavior evaluations.
//! Examples are parsed against the accepted catalog and public CLI tree without dispatch.
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path};

fn source() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    std::fs::read_to_string(root.join("internal/skill/assets/agent-broker/SKILL.md"))
        .expect("source-only agent-broker asset must exist")
}

fn blocks(source: &str) -> Vec<(&str, &str)> {
    let mut blocks = Vec::new();
    let mut rest = source;
    while let Some((_, after)) = rest.split_once("```") {
        let (language, after) = after.split_once('\n').expect("fence language");
        let (body, after) = after.split_once("```").expect("closed fence");
        blocks.push((language, body.trim()));
        rest = after;
    }
    blocks
}

fn calls(source: &str) -> Vec<Value> {
    blocks(source)
        .into_iter()
        .filter(|(language, _)| *language == "json")
        .map(|(_, body)| serde_json::from_str(body).expect("MCP params JSON"))
        .collect()
}

fn catalog() -> Value {
    serde_json::from_str(include_str!("../src/broker/cloud-tools.json")).unwrap()
}

fn valid_mission(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn exact_id(id: &str) -> bool {
    !id.is_empty()
        && id.encode_utf16().count() <= 128
        && id.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}') == id
        && !id.chars().any(char::is_control)
}

// Only the schema vocabulary exercised by this reference is needed. Fail on
// unsupported types rather than silently accepting a newly changed contract.
fn check_schema(schema: &Value, value: &Value) -> Result<(), String> {
    if let Some(choices) = schema["enum"].as_array() {
        if !choices.contains(value) {
            return Err(format!("not an allowed value: {value}"));
        }
    }
    match schema["type"].as_str() {
        Some("object") => {
            let object = value.as_object().ok_or("expected object")?;
            if let Some(required) = schema["required"].as_array() {
                for key in required {
                    let key = key.as_str().unwrap();
                    if !object.contains_key(key) {
                        return Err(format!("missing {key}"));
                    }
                }
            }
            for (key, value) in object {
                if key.ends_with("Id") && !value.as_str().is_some_and(exact_id) {
                    return Err(format!("{key}: exact identity required"));
                }
                if let Some(property) = schema["properties"].get(key) {
                    check_schema(property, value).map_err(|error| format!("{key}: {error}"))?;
                } else if schema["additionalProperties"] == false {
                    return Err(format!("unknown {key}"));
                }
            }
        }
        Some("array") => {
            let items = value.as_array().ok_or("expected array")?;
            check_bounds(schema, items.len() as f64, "minItems", "maxItems")?;
            for item in items {
                check_schema(&schema["items"], item)?;
            }
        }
        Some("string") => {
            let text = value.as_str().ok_or("expected string")?;
            check_bounds(
                schema,
                text.encode_utf16().count() as f64,
                "minLength",
                "maxLength",
            )?;
            if schema.get("pattern").is_some() {
                // operationKey is the only patterned cloud field in the examples.
                if schema["pattern"] != "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
                    || !text
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                {
                    return Err("invalid or unsupported pattern".into());
                }
            }
        }
        Some("integer") => {
            let number = value.as_i64().ok_or("expected integer")? as f64;
            check_bounds(schema, number, "minimum", "maximum")?;
            if schema["exclusiveMinimum"]
                .as_f64()
                .is_some_and(|min| number <= min)
            {
                return Err("below exclusive minimum".into());
            }
        }
        other => return Err(format!("unsupported type {other:?}")),
    }
    Ok(())
}

fn check_bounds(schema: &Value, value: f64, min: &str, max: &str) -> Result<(), String> {
    if schema[min].as_f64().is_some_and(|min| value < min)
        || schema[max].as_f64().is_some_and(|max| value > max)
    {
        Err("outside schema bounds".into())
    } else {
        Ok(())
    }
}

fn check_call(call: &Value) -> Result<(), String> {
    let name = call["name"].as_str().ok_or("missing tool name")?;
    let catalog = catalog();
    let tool = catalog["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .ok_or("unknown tool")?;
    if [
        "agent_submit",
        "agent_attach",
        "agent_report",
        "agent_cancel",
    ]
    .contains(&name)
    {
        return Err("execution is ACTION_UNAVAILABLE, not a runnable example".into());
    }
    let mut args = call["arguments"]
        .as_object()
        .ok_or("missing arguments")?
        .clone();
    let mission = args
        .remove("missionId")
        .ok_or("explicit missionId required")?;
    if !mission.as_str().is_some_and(valid_mission) {
        return Err("invalid missionId".into());
    }
    let mut schema = tool["inputSchema"].clone();
    // broker/mod.rs adds this local polling control; missionId is routing
    // metadata removed before the cloud schema sees the arguments.
    if name == "agent_await" {
        schema["properties"]["waitMs"] = json!({"type":"integer","minimum":0,"maximum":55000});
    }
    check_schema(&schema, &Value::Object(args))
}

// The reference uses literal words and simple double-quoted strings, not shell
// programs. Parsing never executes a shell, expands variables, or loads HOME.
fn argv(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').ok_or("unclosed quote")?;
            let word = &quoted[..end];
            if word.chars().any(|c| "$`\\".contains(c) || c.is_control()) {
                return Err("quoted expansion or escape is not a literal argument".into());
            }
            words.push(word.into());
            rest = &quoted[end + 1..];
            if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                return Err("quoted arguments require a word boundary".into());
            }
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let word = &rest[..end];
            if !word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(&b))
            {
                return Err("shell expansion or command syntax is not an example argument".into());
            }
            words.push(word.into());
            rest = &rest[end..];
        }
        rest = rest.trim_start();
    }
    Ok(words)
}

fn commands(source: &str) -> Vec<Vec<String>> {
    blocks(source)
        .into_iter()
        .filter(|(language, _)| *language == "sh")
        .flat_map(|(_, body)| {
            body.lines()
                .map(|line| argv(line).expect("literal command"))
        })
        .collect()
}

#[test]
fn source_frontmatter_identifies_an_english_source_only_reference() {
    let source = source();
    let after = source.strip_prefix("---\n").expect("frontmatter");
    let (frontmatter, _) = after.split_once("\n---\n").unwrap();
    let fields: serde_yaml_ng::Value = serde_yaml_ng::from_str(frontmatter).unwrap();
    assert_eq!(fields["name"].as_str(), Some("agent-broker"));
    assert!(fields["description"]
        .as_str()
        .unwrap()
        .starts_with("Use when "));
    assert!(
        source.is_ascii(),
        "English reference uses ASCII literal examples"
    );
    assert!(source.contains("source-only") && source.contains("not installed"));
    for (language, _) in blocks(&source) {
        assert!(
            ["json", "sh"].contains(&language),
            "unvalidated example format {language}"
        );
    }
}

#[test]
fn every_mcp_example_resolves_to_current_tool_fields_and_exact_selectors() {
    let source = source();
    let calls = calls(&source);
    assert!(!calls.is_empty(), "reference needs concrete MCP examples");
    for call in &calls {
        check_call(call).unwrap_or_else(|error| panic!("{}: {error}", call["name"]));
        if call["name"] == "work_add" {
            for item in call["arguments"]["items"].as_array().unwrap() {
                assert!(
                    item["intent"].as_str().unwrap().len() > item["title"].as_str().unwrap().len(),
                    "MCP filing must retain a full intent distinct from its short title"
                );
            }
        }
    }
    for required in [
        "work_add",
        "work_ask",
        "agent_status",
        "agent_await",
        "agent_result",
    ] {
        assert!(
            calls.iter().any(|call| call["name"] == required),
            "missing usable {required} example"
        );
    }
    // Inline tool references are checked too: a stale handoff must not survive
    // merely by moving outside a code fence.
    let catalog = catalog();
    for reference in source.split('`').skip(1).step_by(2) {
        if ["orchestrator_", "work_", "roles_", "agent_"]
            .iter()
            .any(|prefix| reference.starts_with(prefix))
        {
            assert!(
                catalog["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tool| tool["name"] == reference),
                "unknown inline tool {reference}"
            );
        }
    }
}

#[test]
fn owner_examples_parse_as_human_commands_with_bound_question_and_filing_intent() {
    let source = source();
    let commands = commands(&source);
    assert!(!commands.is_empty());
    let mut seen = BTreeSet::new();
    for command in commands {
        assert_eq!(&command[..2], &["wapps", "broker"]);
        let matches = wapps::cli::build().try_get_matches_from(&command).unwrap();
        let broker = matches.subcommand_matches("broker").unwrap();
        let (name, args) = broker.subcommand().unwrap();
        assert!(
            [
                "list",
                "questions",
                "relayed",
                "running",
                "answer",
                "accept",
                "confirm",
                "file",
                "move"
            ]
            .contains(&name),
            "setup, absent, or non-owner command in human examples"
        );
        seen.insert(name.to_owned());
        assert!(args
            .get_one::<String>("mission")
            .is_some_and(|id| valid_mission(id)));
        if ["questions", "relayed", "answer", "accept", "confirm"].contains(&name) {
            assert!(
                args.get_one::<String>("work-item")
                    .is_some_and(|id| exact_id(id)),
                "exact work item selector required"
            );
        }
        if ["answer", "accept", "confirm"].contains(&name) {
            assert!(
                args.get_one::<String>("question")
                    .is_some_and(|id| exact_id(id)),
                "exact question required"
            );
        }
        if name == "accept" {
            let digest = args.get_one::<String>("digest").unwrap();
            assert!(!digest.is_empty() && digest.encode_utf16().count() <= 64);
            assert!(
                !digest.contains('<'),
                "copy the returned opaque proposal digest"
            );
        }
        if name == "file" {
            let title = args
                .get_one::<String>("title")
                .expect("explicit short title");
            let intent = args.get_one::<String>("intent").expect("full intent");
            assert!(title.encode_utf16().count() <= 500);
            assert!(
                intent.len() > title.len() && intent != title,
                "filing must not discard the brief"
            );
        }
        if name == "move" {
            assert!(args
                .get_many::<String>("items")
                .expect("exact work items")
                .all(|id| exact_id(id)));
        }
    }
    for required in [
        "questions",
        "relayed",
        "answer",
        "accept",
        "confirm",
        "file",
        "move",
    ] {
        assert!(seen.contains(required), "missing human {required} example");
    }
    assert!(
        !source.contains("agent-broker "),
        "legacy owner executable is not this CLI"
    );
}

#[test]
fn relay_example_requires_separate_human_confirmation_of_the_same_decision() {
    let source = source();
    let calls = calls(&source);
    let relay = calls
        .iter()
        .find(|call| call["name"] == "work_relay_answer")
        .expect("relay example");
    let confirm = commands(&source)
        .into_iter()
        .find(|command| command.get(2).is_some_and(|verb| verb == "confirm"))
        .expect("human confirm example");
    let matches = wapps::cli::build().try_get_matches_from(confirm).unwrap();
    let args = matches
        .subcommand_matches("broker")
        .unwrap()
        .subcommand_matches("confirm")
        .unwrap();
    assert_eq!(
        args.get_one::<String>("mission").unwrap(),
        relay["arguments"]["missionId"].as_str().unwrap()
    );
    assert_eq!(
        args.get_one::<String>("question").unwrap(),
        relay["arguments"]["questionId"].as_str().unwrap()
    );
    let ask = calls
        .iter()
        .find(|call| call["name"] == "work_ask")
        .expect("exact source question");
    assert_eq!(
        ask["arguments"]["missionId"],
        relay["arguments"]["missionId"]
    );
    assert_eq!(
        args.get_one::<String>("work-item").unwrap(),
        ask["arguments"]["workItemId"].as_str().unwrap()
    );
    let relay_body = blocks(&source)
        .into_iter()
        .find(|(language, body)| {
            *language == "json"
                && serde_json::from_str::<Value>(body).unwrap()["name"] == "work_relay_answer"
        })
        .unwrap()
        .1;
    let relay_position = source.find(relay_body).unwrap();
    let confirm_position = source.find("wapps broker confirm").unwrap();
    assert!(
        relay_position < confirm_position,
        "relay precedes separate human confirmation"
    );
    assert!(
        source[relay_position..confirm_position].contains("HUMAN"),
        "confirmation is not agent authority"
    );
}

#[test]
fn availability_table_separates_observation_consumption_and_unimplemented_execution() {
    let source = source();
    // A structured reference contract makes misclassification (for example
    // calling agent_result observational) fail independently of nearby prose.
    let rows: Vec<Vec<&str>> = source
        .lines()
        .filter(|line| line.starts_with('|'))
        .map(|line| {
            line.split('|')
                .map(str::trim)
                .filter(|cell| !cell.is_empty())
                .collect()
        })
        .collect();
    for (surface, effect) in [
        ("`agent_status`", "observational"),
        ("`agent_result`", "consumes unread result"),
        ("`agent_submit`", "ACTION_UNAVAILABLE"),
        ("`agent_attach`", "ACTION_UNAVAILABLE"),
        ("`agent_report`", "ACTION_UNAVAILABLE"),
        ("`agent_cancel`", "ACTION_UNAVAILABLE"),
        ("pause / unpause", "refuse; nothing changed"),
        ("role apply", "refuse; nothing changed"),
        ("project enroll", "root registry only"),
        ("explore / broker install", "absent"),
    ] {
        assert!(
            rows.iter().any(|row| row.as_slice() == [surface, effect]),
            "wrong reference effect for {surface}"
        );
    }
    let tree = wapps::cli::build();
    let broker = tree.find_subcommand("broker").unwrap();
    assert!(
        broker.find_subcommand("explore").is_none() && broker.find_subcommand("install").is_none()
    );
    let skill = tree.find_subcommand("skill").unwrap();
    assert!(skill
        .find_subcommand("install")
        .unwrap()
        .get_arguments()
        .all(|arg| arg.get_id() != "name"));
    assert_eq!(wapps::skill::SKILL_NAME, "wapps-secrets");
}

#[test]
fn contract_checks_reject_known_stale_or_ambiguous_examples() {
    assert!(check_call(
        &json!({"name":"orchestrator_prepare_handoff","arguments":{"missionId":"demo-mission"}})
    )
    .is_err());
    assert!(check_call(&json!({"name":"agent_status","arguments":{"jobId":"job-23"}})).is_err());
    assert!(check_call(
        &json!({"name":"agent_status","arguments":{"missionId":"demo-mission","jobId":" job-23 "}})
    )
    .is_err());
    assert!(check_call(
        &json!({"name":"agent_status","arguments":{"missionId":"demo-mission","id":"job-23"}})
    )
    .is_err());
    assert!(check_call(&json!({"name":"work_ask","arguments":{"missionId":"demo-mission","authority":{"capability":"fixture","fencingToken":1},"workItemId":"work-17","question":"Proceed?","status":"ready"}})).is_err());
    assert!(
        check_call(&json!({"name":"agent_submit","arguments":{"missionId":"demo-mission"}}))
            .is_err()
    );
    assert!(check_call(
        &json!({"name":"agent_await","arguments":{"missionId":"demo-mission","waitMs":55001}})
    )
    .is_err());
    let args =
        argv("wapps broker confirm --mission demo-mission --work-item work-17 question-5").unwrap();
    let matches = wapps::cli::build().try_get_matches_from(args).unwrap();
    assert_eq!(
        matches
            .subcommand_matches("broker")
            .unwrap()
            .subcommand_matches("confirm")
            .unwrap()
            .get_one::<String>("question")
            .map(String::as_str),
        Some("question-5")
    );
    assert!(wapps::cli::build()
        .try_get_matches_from(["wapps", "broker", "confirm", "--task", "work-17"])
        .is_err());
    assert!(argv("WAPPS_AGENT_MODE=0 wapps broker confirm question-5").is_err());
    assert!(argv("wapps broker confirm $(cat token)").is_err());
    assert!(argv("wapps broker answer \"$(cat token)\"").is_err());
    assert!(argv("wapps broker answer \"first\"second").is_err());
    assert!(argv("wapps broker confirm question-*").is_err());
    assert!(argv("wapps broker confirm q\"5\"").is_err());
}
