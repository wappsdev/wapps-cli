//! The human CLI. Cloud ownership is authoritative; no agent credential or lease is used.
mod http;
mod project;
use clap::{Arg, ArgMatches, Command};
use serde_json::{json, Value};
use std::io::Write;

pub fn commands() -> Vec<Command> {
    let mission = || {
        Arg::new("mission")
            .long("mission")
            .help("Explicit cloud mission id (required)")
    };
    let task = || {
        Arg::new("work-item")
            .long("work-item")
            .help("Require this exact work item id")
    };
    let mut commands = vec![];
    for (name, about) in [
        ("list", "List this mission's work and progress"),
        ("questions", "List open questions and proposal digests"),
        (
            "relayed",
            "List relayed answers awaiting human confirmation",
        ),
        (
            "running",
            "List reserved and running cloud jobs (no local quota)",
        ),
    ] {
        let mut command = Command::new(name).about(about).arg(mission());
        if matches!(name, "questions" | "relayed") {
            command = command.arg(task());
        }
        commands.push(command);
    }
    for (name, about, value) in [
        (
            "answer",
            "Answer a question as the human owner",
            Some("answer"),
        ),
        (
            "accept",
            "Accept the proposal bound to the digest you read",
            Some("digest"),
        ),
        ("confirm", "Vouch for an agent's relayed answer", None),
    ] {
        let mut command = Command::new(name)
            .about(about)
            .arg(mission())
            .arg(task())
            .arg(Arg::new("question"));
        if let Some(value) = value {
            command = command.arg(Arg::new(value));
        }
        commands.push(command);
    }
    commands.push(
        Command::new("file")
            .about("File work without a lease; full intent is retained")
            .arg(mission())
            .arg(Arg::new("intent").help("Full intent; also the title unless --title is supplied"))
            .arg(Arg::new("title").long("title").help(
                "Short title, required when intent exceeds 500 UTF-16 units; never truncated",
            ))
            .arg(
                Arg::new("horizon")
                    .long("horizon")
                    .value_parser(["now", "next", "later", "someday"]),
            )
            .arg(
                Arg::new("parent")
                    .long("parent")
                    .conflicts_with("horizon")
                    .help("Exact parent work item in this mission"),
            ),
    );
    commands.push(
        Command::new("move")
            .about("Move work through the owner's leaseless door; a part detaches")
            .arg(mission())
            .arg(Arg::new("horizon").value_parser(["now", "next", "later", "someday"]))
            .arg(
                Arg::new("items")
                    .num_args(1..)
                    .help("Exact work item ids in this mission"),
            ),
    );
    commands.push(project::command());
    commands
}

pub fn handles(name: &str) -> bool {
    matches!(
        name,
        "list"
            | "questions"
            | "relayed"
            | "running"
            | "answer"
            | "accept"
            | "confirm"
            | "file"
            | "move"
            | "project"
    )
}

pub fn run(name: &str, args: &ArgMatches) -> Result<(), String> {
    // Unlike a general CLI override, owner authority must not become reachable
    // from an agent terminal by setting WAPPS_AGENT_MODE=0.
    if (crate::agentmode::Detector {
        env: &|key| std::env::var(key).ok(),
        stdin_is_tty: crate::agentmode::stdin_is_tty(),
        allow_override: false,
    })
    .is_agent()
        // Provider daemon/launcher hints belong to this owner guard, not the
        // shared Go/Rust detector. Like TTY, these are context hints, not proof
        // of human intent or a boundary against a hostile same-UID process.
        || ["AGENT_BROKER_DAEMON", "AGENT_BROKER_LAUNCHER_PROVIDER"]
            .iter()
            .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
    {
        return Err(
            "owner commands require a human terminal; agents must relay answers over MCP".into(),
        );
    }
    if name == "project" {
        return project::run(args);
    }
    let mission = required(args, "mission")?;
    if !valid_mission(mission) {
        return Err("invalid mission id".into());
    }
    // Validate all input before loading a credential or reaching the network.
    // IDs stay JSON data, but must not silently become another ID when the
    // backend applies its trimmed-string schema.
    for key in ["question", "work-item", "parent"] {
        if let Some(value) = args.try_get_one::<String>(key).ok().flatten() {
            identifier(value)?;
        }
    }
    let body = match name {
        "answer" => Some(
            json!({"questionId":bounded(args,"question",128)?,"answer":bounded(args,"answer",20_000)?}),
        ),
        "accept" => Some(
            json!({"questionId":bounded(args,"question",128)?,"digest":bounded(args,"digest",64)?}),
        ),
        "confirm" => Some(json!({"questionId":bounded(args,"question",128)?})),
        "file" => {
            let intent = bounded(args, "intent", 100_000)?;
            let title = args
                .get_one::<String>("title")
                .map(String::as_str)
                .unwrap_or(intent);
            text(title, "title", 500)?;
            let mut item = json!({"title":title,"intent":intent});
            if let Some(horizon) = args.get_one::<String>("horizon") {
                item["horizon"] = json!(horizon);
            }
            if let Some(parent) = args.get_one::<String>("parent") {
                text(parent, "parent", 128)?;
                item["parentId"] = json!(parent);
            }
            Some(json!({"items":[item]}))
        }
        "move" => {
            let horizon = required(args, "horizon")?;
            let ids: Vec<_> = args
                .get_many::<String>("items")
                .ok_or("work item ids are required")?
                .collect();
            if ids.len() > 500 {
                return Err("at most 500 work items may move together".into());
            }
            for id in &ids {
                identifier(id)?;
            }
            Some(
                json!({"moves":ids.iter().map(|id| json!({"workItemId":id,"horizon":horizon})).collect::<Vec<_>>()}),
            )
        }
        _ => None,
    };
    let task = args.try_get_one::<String>("work-item").ok().flatten();
    if let Some(task) = task {
        text(task, "work item id", 128)?;
    }
    let client = http::Client::load()?;
    let mut result = match name {
        "list" => {
            let value = client.request(mission, "work", None)?;
            rows(&value, "items")?;
            value
        }
        "running" => {
            let mut value = client.request(mission, "jobs", None)?;
            let jobs = rows(&value, "jobs")?;
            if jobs
                .iter()
                .any(|job| !job["jobId"].is_string() || !job["state"].is_string())
            {
                return Err("cloud protocol: invalid job row".into());
            }
            value["jobs"] = json!(jobs
                .iter()
                .filter(|job| matches!(job["state"].as_str(), Some("reserved" | "running")))
                .collect::<Vec<_>>());
            value
        }
        "questions" | "relayed" => {
            let mut value = client.request(mission, "work/questions", None)?;
            let questions = questions(&value)?;
            value["questions"] = json!(questions
                .iter()
                .filter(|q| task.is_none_or(|id| q["workItemId"] == *id)
                    && if name == "questions" {
                        open(q)
                    } else {
                        unconfirmed(q)
                    })
                .collect::<Vec<_>>());
            value
        }
        "answer" | "accept" | "confirm" => {
            let value = client.request(mission, "work/questions", None)?;
            let id = required(args, "question")?;
            let matches: Vec<_> = questions(&value)?
                .iter()
                .filter(|q| q["questionId"] == id)
                .collect();
            let [question] = matches.as_slice() else {
                return Err("question not uniquely found in the selected mission".into());
            };
            if task.is_some_and(|id| question["workItemId"] != *id) {
                return Err("question does not belong to the selected work item".into());
            }
            if name == "confirm" {
                if !unconfirmed(question) {
                    return Err("question has no unconfirmed relayed answer".into());
                }
            } else {
                if !open(question) {
                    return Err("question is already answered or withdrawn".into());
                }
                if name == "accept"
                    && (!question["proposal"].is_string()
                        || question["proposalDigest"] != required(args, "digest")?)
                {
                    return Err(
                        "proposal digest changed or no proposal exists; read questions again"
                            .into(),
                    );
                }
            }
            let response =
                client.request(mission, &format!("work/questions/{name}"), body.as_ref())?;
            if response["questionId"] != id
                || if name == "confirm" {
                    !response["confirmedBy"].is_string()
                } else {
                    response["answeredBy"]
                        != if name == "accept" {
                            "proposal"
                        } else {
                            "owner"
                        }
                }
            {
                return Err(
                    "cloud protocol: invalid question acknowledgement; outcome may be unknown"
                        .into(),
                );
            }
            response
        }
        "file" | "move" => {
            let response = client.request(mission, &format!("work/owner/{name}"), body.as_ref())?;
            let acknowledged = if name == "file" {
                response["workItemIds"].as_array().is_some_and(|ids| {
                    ids.len() == 1 && ids[0].as_str().is_some_and(|id| identifier(id).is_ok())
                })
            } else {
                let moves = body.as_ref().expect("validated move")["moves"]
                    .as_array()
                    .expect("constructed moves");
                response["moved"].as_array().is_some_and(|moved| {
                    moved.len() == moves.len()
                        && moved.iter().zip(moves).all(|(got, sent)| {
                            got["id"] == sent["workItemId"]
                                && got["horizon"] == sent["horizon"]
                                && got
                                    .get("detachedFrom")
                                    .is_some_and(|v| v.is_null() || v.is_string())
                        })
                })
            };
            if !acknowledged {
                return Err(
                    "cloud protocol: invalid work acknowledgement; outcome may be unknown".into(),
                );
            }
            response
        }
        _ => return Err("unknown owner command".into()),
    };
    client.redact(&mut result);
    let output =
        serde_json::to_string_pretty(&result).map_err(|_| "cannot encode owner response")?;
    writeln!(std::io::stdout().lock(), "{output}").map_err(|_| "cannot write owner response".into())
}
fn required<'a>(args: &'a ArgMatches, key: &str) -> Result<&'a str, String> {
    args.get_one::<String>(key)
        .map(String::as_str)
        .ok_or_else(|| format!("{key} is required"))
}
fn bounded<'a>(args: &'a ArgMatches, key: &str, max: usize) -> Result<&'a str, String> {
    let value = required(args, key)?;
    text(value, key, max)?;
    Ok(value)
}
fn text(value: &str, key: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.trim().encode_utf16().count() > max {
        Err(format!(
            "{key} must contain 1–{max} UTF-16 units; supply --title for a longer intent"
        ))
    } else {
        Ok(())
    }
}
fn identifier(value: &str) -> Result<(), String> {
    text(value, "identifier", 128)?;
    if value.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}') != value
        || value.chars().any(char::is_control)
    {
        return Err(
            "identifier must be exact, without surrounding whitespace or control characters".into(),
        );
    }
    Ok(())
}
fn valid_mission(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn rows<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("cloud protocol: missing {key} list"))
}
fn questions(value: &Value) -> Result<&Vec<Value>, String> {
    let questions = rows(value, "questions")?;
    for q in questions {
        if !q["questionId"].is_string()
            || !q["workItemId"].is_string()
            || !q["question"].is_string()
            || ["answeredAt", "withdrawnAt", "confirmedAt"]
                .iter()
                .any(|key| !q.get(key).is_some_and(|v| v.is_null() || v.is_i64()))
            || ["answeredBy", "proposal", "proposalDigest", "answer"]
                .iter()
                .any(|key| !q.get(key).is_some_and(|v| v.is_null() || v.is_string()))
        {
            return Err("cloud protocol: invalid question row".into());
        }
    }
    Ok(questions)
}
fn open(q: &Value) -> bool {
    q["answeredAt"].is_null() && q["withdrawnAt"].is_null()
}
fn unconfirmed(q: &Value) -> bool {
    q["answeredBy"] == "relay"
        && q["answeredAt"].is_i64()
        && q["answer"].is_string()
        && q["confirmedAt"].is_null()
        && q["withdrawnAt"].is_null()
}
