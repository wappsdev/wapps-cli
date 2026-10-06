//! Owner commands use the real binary, hermetic terminals and an HTTP boundary peer.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[path = "support/broker_daemon_cleanup.rs"]
mod broker_daemon_cleanup;
use broker_daemon_cleanup::DaemonCleanup;

static NEXT: AtomicUsize = AtomicUsize::new(0);
// Unsigned fixture only. The real Access edge verifies signatures and owner permissions.
const TOKEN: &str = "eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im93bmVyQGV4YW1wbGUudGVzdCIsImV4cCI6NDEwMjQ0NDgwMH0.b3duZXItc2lnbmF0dXJl";
const AGENT: &str = "fixture-agent-secret-never-owner";
struct Home(PathBuf, DaemonCleanup);
impl Home {
    fn new(endpoint: &str) -> Self {
        let root = broker_oracle::hermetic::temp_root(&format!(
            "owner-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("project")).unwrap();
        fs::create_dir_all(root.join(".config/wapps-broker")).unwrap();
        fs::write(
            root.join(".config/wapps-broker/client.yaml"),
            format!("clientId: agent-only\nendpoint: {endpoint}\n"),
        )
        .unwrap();
        fs::write(root.join(".config/wapps-broker/agents.secret"), AGENT).unwrap();
        let home = Self(root, DaemonCleanup::default());
        home.session(endpoint, TOKEN);
        home
    }
    fn session(&self, endpoint: &str, token: &str) {
        wapps::session::save_with(
            &|k| (k == "HOME").then(|| self.0.to_string_lossy().into_owned()),
            &wapps::session::host_of(endpoint),
            &wapps::session::State {
                token: token.into(),
                expires_at: 4102444800,
            },
        )
        .unwrap();
    }
    fn run(&self, args: &[&str], agent: bool) -> (i64, String, String) {
        self.run_env(args, if agent { &[("CLAUDECODE", "1")] } else { &[] })
    }
    fn run_env(&self, args: &[&str], context: &[(&str, &str)]) -> (i64, String, String) {
        let mut argv = vec![env!("CARGO_BIN_EXE_wapps"), "broker"];
        argv.extend(args);
        let mut env = json!({"HOME":self.0,"PATH":"/usr/bin:/bin", "WAPPS_NO_UPDATE_CHECK":"1"});
        for (key, value) in context {
            env[*key] = json!(value);
        }
        let spec = json!({"argv":argv,"env":env,"cwd":self.0.join("project")});
        let mut child = Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/ptyrun.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(spec.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let out: Value = serde_json::from_slice(&out.stdout).unwrap();
        let decode = |name: &str| {
            let hex = out[name].as_str().unwrap();
            String::from_utf8(
                (0..hex.len())
                    .step_by(2)
                    .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
                    .collect(),
            )
            .unwrap()
        };
        let stdout = decode("stdout_hex");
        let stderr = decode("stderr_hex");
        for secret in [TOKEN, AGENT].into_iter().chain(TOKEN.split('.')) {
            assert!(
                !stdout.contains(secret) && !stderr.contains(secret),
                "credential leaked"
            );
        }
        (out["exit"].as_i64().unwrap(), stdout, stderr)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        self.1.remove_home(&self.0);
    }
}
#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: String,
    body: Value,
}
struct Cloud {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Cloud {
    fn new(responses: Vec<(u16, Value)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(vec![]));
        let captured = Arc::clone(&requests);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut responses = responses.into_iter();
            while !stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let words: Vec<_> = first.split_whitespace().collect();
                let mut headers = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        if key.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    headers.push_str(&line);
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                captured.lock().unwrap().push(Request {
                    method: words[0].into(),
                    path: words[1].into(),
                    headers,
                    body: serde_json::from_slice(&body).unwrap_or(Value::Null),
                });
                let (status, body) = responses
                    .next()
                    .unwrap_or((500, json!({"error":"unexpected request"})));
                let body = body.to_string();
                write!(stream,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            endpoint,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn assert_owner(&self, expected: &[(&str, &str, Value)]) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), expected.len());
        for (actual, (method, path, body)) in requests.iter().zip(expected) {
            assert_eq!(&actual.method, method);
            assert_eq!(&actual.path, path);
            assert_eq!(&actual.body, body);
            let headers = actual.headers.to_ascii_lowercase();
            assert!(headers.contains(&format!("cf-access-token: {}", TOKEN.to_ascii_lowercase())));
            assert!(!headers.contains("cf-access-client-") && !headers.contains(AGENT));
        }
    }
}
impl Drop for Cloud {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn question(id: &str) -> Value {
    json!({"questionId":id,"workItemId":"task-1","question":"Which path?","proposal":"Keep full intent","proposalDigest":"p-1234","raisedAt":100,"delegateProvider":null,"answeredAt":null,"answer":null,"answeredBy":null,"answeredByPrincipal":null,"answerJobId":null,"confirmedAt":null,"confirmedBy":null,"withdrawnAt":null,"withdrawnReason":null})
}
#[test]
fn owner_reads_use_sso_and_filter_pending_questions_relays_and_live_jobs() {
    let mut relayed = question("relay-1");
    relayed["answeredAt"] = json!(110);
    relayed["answer"] = json!("Agreed");
    relayed["answeredBy"] = json!("relay");
    relayed["answeredByPrincipal"] = json!("svc:agent");
    let mut confirmed = relayed.clone();
    confirmed["questionId"] = json!("confirmed");
    confirmed["confirmedAt"] = json!(120);
    let mut withdrawn = question("withdrawn");
    withdrawn["withdrawnAt"] = json!(121);
    let qs = json!({"questions":[question("q-1"),relayed,confirmed,withdrawn]});
    let cloud = Cloud::new(vec![
        (
            200,
            json!({"items":[],"progress":{"now":0,"next":0,"later":0,"someday":0,"unplaced":0,"delivered":0}}),
        ),
        (200, qs.clone()),
        (200, qs),
        (
            200,
            json!({"jobs":[{"jobId":"live","state":"running"},{"jobId":"reserved","state":"reserved"},{"jobId":"review","state":"review_pending"},{"jobId":"done","state":"succeeded"}],"digest":"d"}),
        ),
    ]);
    let home = Home::new(&cloud.endpoint);
    let list = home.run(&["list", "--mission", "mission-a"], false);
    assert_eq!(list.0, 0, "{}", list.2);
    let q = home.run(&["questions", "--mission", "mission-a"], false);
    assert_eq!(q.0, 0, "{}", q.2);
    let q: Value = serde_json::from_str(&q.1).unwrap();
    assert_eq!(q["questions"].as_array().unwrap().len(), 1);
    assert_eq!(q["questions"][0]["questionId"], "q-1");
    assert_eq!(q["questions"][0]["proposalDigest"], "p-1234");
    let r = home.run(&["relayed", "--mission", "mission-a"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    let r: Value = serde_json::from_str(&r.1).unwrap();
    assert_eq!(r["questions"].as_array().unwrap().len(), 1);
    assert_eq!(r["questions"][0]["questionId"], "relay-1");
    let r = home.run(&["running", "--mission", "mission-b"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    let r: Value = serde_json::from_str(&r.1).unwrap();
    assert_eq!(r["jobs"].as_array().unwrap().len(), 2);
    cloud.assert_owner(&[
        ("GET", "/v1/missions/mission-a/work", Value::Null),
        ("GET", "/v1/missions/mission-a/work/questions", Value::Null),
        ("GET", "/v1/missions/mission-a/work/questions", Value::Null),
        ("GET", "/v1/missions/mission-b/jobs", Value::Null),
    ]);
}
#[test]
fn agent_missing_session_and_ambiguous_mission_never_send_a_request() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    let r = home.run(&["list", "--mission", "mission-a"], true);
    assert_ne!(r.0, 0);
    assert!(r.2.contains("human"));
    let r = home.run(&["list"], false);
    assert_ne!(r.0, 0);
    assert!(r.2.contains("mission"));
    fs::remove_dir_all(home.0.join(".config/wapps/session")).unwrap();
    let r = home.run(&["list", "--mission", "mission-a"], false);
    assert_ne!(r.0, 0);
    assert!(r.2.contains("SSO"));
    cloud.assert_owner(&[]);
}
#[test]
fn explicit_agent_contexts_refuse_pty_owner_reads_and_writes_even_with_override_zero() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    // These are the daemon spawn and generated launcher config markers, not
    // ordinary configuration such as CODEX_HOME. Test each independently.
    for marker in [
        ("CLAUDECODE", "1"),
        ("CLAUDE_CODE", "1"),
        ("CI", "1"),
        ("AGENT_BROKER_DAEMON", "1"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "claude"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "codex"),
    ] {
        for override_zero in [false, true] {
            let mut context = vec![marker];
            if override_zero {
                context.push(("WAPPS_AGENT_MODE", "0"));
            }
            for args in [
                vec!["list", "--mission", "a"],
                vec!["file", "--mission", "a", "brief"],
                vec!["answer", "--mission", "a", "q-1", "yes"],
                vec!["confirm", "--mission", "a", "q-1"],
            ] {
                let r = home.run_env(&args, &context);
                assert_eq!(r.0, 1, "{context:?} {args:?}: {}", r.2);
                assert!(
                    r.2.contains("owner commands require a human terminal"),
                    "{context:?}: {}",
                    r.2
                );
                assert!(r.1.is_empty());
                cloud.assert_owner(&[]);
            }
        }
    }
}

#[test]
fn broker_context_refusal_precedes_metadata_and_session_loading() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    for marker in [
        ("AGENT_BROKER_DAEMON", "1"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "claude"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "codex"),
    ] {
        let context = [marker, ("WAPPS_AGENT_MODE", "0")];
        home.session(&cloud.endpoint, "malformed-session");
        let r = home.run_env(&["list", "--mission", "a"], &context);
        assert_eq!(r.0, 1);
        assert!(
            r.2.contains("owner commands require a human terminal"),
            "{}",
            r.2
        );
        let metadata = home.0.join(".config/wapps-broker/client.yaml");
        let before = fs::read(&metadata).unwrap();
        fs::write(&metadata, "endpoint: [").unwrap();
        let r = home.run_env(&["list", "--mission", "a"], &context);
        assert_eq!(r.0, 1);
        assert!(
            r.2.contains("owner commands require a human terminal"),
            "{}",
            r.2
        );
        fs::write(metadata, before).unwrap();
        cloud.assert_owner(&[]);
    }
}

#[test]
fn broker_context_refusal_never_creates_or_changes_local_enrollment() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    let root = home.0.join("project");
    let state = home.0.join(".agent-broker");
    for marker in [
        ("AGENT_BROKER_DAEMON", "1"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "claude"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "codex"),
    ] {
        let r = home.run_env(
            &["project", "enroll", "local-project", root.to_str().unwrap()],
            &[marker, ("WAPPS_AGENT_MODE", "0")],
        );
        assert_eq!(r.0, 1);
        assert!(
            r.2.contains("owner commands require a human terminal"),
            "{}",
            r.2
        );
        assert!(
            !state.exists(),
            "refusal must not create registry or lock directories"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
    assert_eq!(
        home.run(
            &["project", "enroll", "local-project", root.to_str().unwrap()],
            false
        )
        .0,
        0
    );
    let before = fs::read(state.join("projects.json")).unwrap();
    let other = home.0.join("other-project");
    fs::create_dir(&other).unwrap();
    for marker in [
        ("AGENT_BROKER_DAEMON", "1"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "claude"),
        ("AGENT_BROKER_LAUNCHER_PROVIDER", "codex"),
    ] {
        let r = home.run_env(
            &["project", "enroll", "other", other.to_str().unwrap()],
            &[marker, ("WAPPS_AGENT_MODE", "0")],
        );
        assert_eq!(r.0, 1);
        assert!(
            r.2.contains("owner commands require a human terminal"),
            "{}",
            r.2
        );
        assert_eq!(before, fs::read(state.join("projects.json")).unwrap());
        assert_eq!(
            fs::read_dir(&state).unwrap().count(),
            1,
            "no lock or temporary files"
        );
        assert_eq!(fs::read_dir(&other).unwrap().count(), 0);
    }
    cloud.assert_owner(&[]);
}

#[test]
fn human_configuration_is_not_agent_context_and_empty_broker_hints_do_not_refuse() {
    let cloud = Cloud::new(vec![(200, json!({"items":[]}))]);
    let home = Home::new(&cloud.endpoint);
    let r = home.run_env(
        &["list", "--mission", "a"],
        &[
            ("WAPPS_AGENT_MODE", "0"),
            ("CODEX_HOME", "/fixture/normal-codex-config"),
            ("AGENT_BROKER_DAEMON", ""),
            ("AGENT_BROKER_LAUNCHER_PROVIDER", ""),
        ],
    );
    assert_eq!(r.0, 0, "{}", r.2);
    cloud.assert_owner(&[("GET", "/v1/missions/a/work", Value::Null)]);
}

#[test]
fn owner_missing_session_cannot_fall_back_to_environment_or_service_tokens() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    fs::remove_dir_all(home.0.join(".config/wapps/session")).unwrap();
    for context in [
        vec![],
        vec![("WAPPS_SESSION_TOKEN", TOKEN)],
        vec![
            ("CF_ACCESS_CLIENT_ID", "fixture-id"),
            ("CF_ACCESS_CLIENT_SECRET", AGENT),
        ],
        vec![("AGENT_BROKER_DAEMON", "1"), ("WAPPS_AGENT_MODE", "0")],
        vec![
            ("AGENT_BROKER_LAUNCHER_PROVIDER", "codex"),
            ("WAPPS_AGENT_MODE", "0"),
        ],
    ] {
        let r = home.run_env(&["list", "--mission", "a"], &context);
        assert_eq!(r.0, 1);
        let expected = if context
            .iter()
            .any(|(key, _)| key.starts_with("AGENT_BROKER_"))
        {
            "owner commands require a human terminal"
        } else {
            "SSO session required"
        };
        assert!(r.2.contains(expected), "{}", r.2);
        cloud.assert_owner(&[]);
    }
}

#[test]
fn answer_and_accept_are_exact_mission_question_and_digest_writes() {
    let cloud = Cloud::new(vec![
        (200, json!({"questions":[question("q-1")]})),
        (200, json!({"questionId":"q-1","answeredBy":"owner"})),
        (200, json!({"questions":[question("q-2")]})),
        (
            200,
            json!({"questionId":"q-2","answeredBy":"proposal","answer":"Keep full intent"}),
        ),
    ]);
    let home = Home::new(&cloud.endpoint);
    let r = home.run(
        &[
            "answer",
            "--mission",
            "a",
            "--work-item",
            "task-1",
            "q-1",
            "My own words",
        ],
        false,
    );
    assert_eq!(r.0, 0, "{}", r.2);
    let r = home.run(&["accept", "--mission", "b", "q-2", "p-1234"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    cloud.assert_owner(&[
        ("GET", "/v1/missions/a/work/questions", Value::Null),
        (
            "POST",
            "/v1/missions/a/work/questions/answer",
            json!({"questionId":"q-1","answer":"My own words"}),
        ),
        ("GET", "/v1/missions/b/work/questions", Value::Null),
        (
            "POST",
            "/v1/missions/b/work/questions/accept",
            json!({"questionId":"q-2","digest":"p-1234"}),
        ),
    ]);
}
#[test]
fn stale_digest_cross_mission_and_cross_task_selection_do_not_write() {
    let cloud = Cloud::new(vec![
        (200, json!({"questions":[question("q-1")]})),
        (200, json!({"questions":[]})),
        (200, json!({"questions":[question("q-1")]})),
    ]);
    let home = Home::new(&cloud.endpoint);
    for args in [
        vec!["accept", "--mission", "a", "q-1", "stale"],
        vec!["answer", "--mission", "b", "q-1", "yes"],
        vec![
            "answer",
            "--mission",
            "a",
            "--work-item",
            "other-task",
            "q-1",
            "yes",
        ],
    ] {
        let r = home.run(&args, false);
        assert_ne!(r.0, 0);
    }
    assert_eq!(cloud.requests.lock().unwrap().len(), 3);
    assert!(cloud
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.method == "GET"));
}
#[test]
fn confirm_only_vouches_for_an_unconfirmed_relay_and_preserves_backend_refusal() {
    let mut relay = question("q-1");
    relay["answeredBy"] = json!("relay");
    relay["answeredAt"] = json!(120);
    relay["answer"] = json!("Yes");
    relay["answeredByPrincipal"] = json!("svc:agent");
    let cloud = Cloud::new(vec![
        (200, json!({"questions":[question("open")]})),
        (200, json!({"questions":[relay.clone()]})),
        (
            200,
            json!({"questionId":"q-1","confirmedBy":"owner@example.test"}),
        ),
        (200, json!({"questions":[relay]})),
        (403, json!({"code":"FORBIDDEN","message":TOKEN})),
    ]);
    let home = Home::new(&cloud.endpoint);
    assert_ne!(home.run(&["confirm", "--mission", "a", "open"], false).0, 0);
    let r = home.run(&["confirm", "--mission", "a", "q-1"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    let r = home.run(&["confirm", "--mission", "a", "q-1"], false);
    assert_ne!(r.0, 0);
    assert!(r.2.contains("403"));
    cloud.assert_owner(&[
        ("GET", "/v1/missions/a/work/questions", Value::Null),
        ("GET", "/v1/missions/a/work/questions", Value::Null),
        (
            "POST",
            "/v1/missions/a/work/questions/confirm",
            json!({"questionId":"q-1"}),
        ),
        ("GET", "/v1/missions/a/work/questions", Value::Null),
        (
            "POST",
            "/v1/missions/a/work/questions/confirm",
            json!({"questionId":"q-1"}),
        ),
    ]);
}
#[test]
fn file_preserves_full_intent_and_move_uses_only_the_leaseless_owner_route() {
    let cloud = Cloud::new(vec![
        (201, json!({"workItemIds":["new-task"]})),
        (
            200,
            json!({"moved":[{"id":"task-1","horizon":"next","detachedFrom":null}]}),
        ),
    ]);
    let home = Home::new(&cloud.endpoint);
    let intent = "long brief ".repeat(100);
    let r = home.run(
        &[
            "file",
            "--mission",
            "a",
            "--horizon",
            "now",
            "--title",
            "Complete brief",
            &intent,
        ],
        false,
    );
    assert_eq!(r.0, 0, "{}", r.2);
    let r = home.run(&["move", "--mission", "b", "next", "task-1"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    cloud.assert_owner(&[
        (
            "POST",
            "/v1/missions/a/work/owner/file",
            json!({"items":[{"title":"Complete brief","intent":intent,"horizon":"now"}]}),
        ),
        (
            "POST",
            "/v1/missions/b/work/owner/move",
            json!({"moves":[{"workItemId":"task-1","horizon":"next"}]}),
        ),
    ]);
}
#[test]
fn long_titles_are_refused_not_silently_truncated_and_invalid_missions_never_route() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    for text in ["x".repeat(501), "🦀".repeat(251)] {
        let r = home.run(&["file", "--mission", "a", &text], false);
        assert_ne!(r.0, 0);
        assert!(r.2.contains("title"));
    }
    for mission in ["../a", "a/b", "A", "a?evil"] {
        assert_ne!(home.run(&["list", "--mission", mission], false).0, 0);
    }
    cloud.assert_owner(&[]);
}
#[test]
fn errors_redirects_and_success_payloads_cannot_disclose_owner_credentials() {
    let cloud = Cloud::new(vec![
        (
            200,
            json!({"items":[],"token":TOKEN,"note":TOKEN,"nested":{"capability":"private-capability"}}),
        ),
        (401, json!({"message":TOKEN})),
        (302, json!({"message":TOKEN})),
        (200, json!({"unexpected":TOKEN})),
    ]);
    let home = Home::new(&cloud.endpoint);
    let r = home.run(&["list", "--mission", "a"], false);
    assert_eq!(r.0, 0, "{}", r.2);
    assert!(!r.1.contains("private-capability"));
    for code in ["401", "302", "protocol"] {
        let r = home.run(&["list", "--mission", "a"], false);
        assert_ne!(r.0, 0);
        assert!(r.2.contains(code), "{}", r.2);
    }
    assert_eq!(cloud.requests.lock().unwrap().len(), 4);
}

#[test]
fn enroll_writes_only_the_version_one_registry_and_is_readable_by_the_stdio_bridge() {
    use std::os::unix::fs::PermissionsExt;
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    let root = home.0.join("project");
    let r = home.run(
        &["project", "enroll", "local-project", root.to_str().unwrap()],
        false,
    );
    assert_eq!(r.0, 0, "{}", r.2);
    let path = home.0.join(".agent-broker/projects.json");
    let value: Value =
        serde_json::from_slice(&fs::read(&path).expect("enrollment written")).unwrap();
    assert_eq!(
        value,
        json!({"version":1,"projects":{"local-project":{"root":fs::canonicalize(&root).unwrap()}}})
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        0,
        "enrollment must not pretend to install harnesses or roles"
    );
    let original = fs::read(&path).unwrap();
    assert_eq!(
        home.run(
            &["project", "enroll", "local-project", root.to_str().unwrap()],
            false
        )
        .0,
        0
    );
    assert_eq!(original, fs::read(&path).unwrap());
    fs::set_permissions(
        home.0.join(".config/wapps-broker/agents.secret"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    home.1.start(&home.0).expect("fixture daemon ready");
    let mut child = Command::new(env!("CARGO_BIN_EXE_wapps"))
        .args(["broker", "serve"])
        .env_clear()
        .env("HOME", &home.0)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let response: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(response["result"]["serverInfo"]["name"], "wapps-broker");
    cloud.assert_owner(&[]);
}
#[test]
fn owner_protocol_differential_against_frozen_cloud_exchanges() {
    // This is a public HTTP protocol replay, not a live authorization test or
    // byte equality with the plugin's terminal rendering. The frozen recorder
    // supplies independent response/body expectations (including no `ok` field).
    let corpus: Value = serde_json::from_str(include_str!(
        "../../broker-oracle/fixtures/cloud/surface-transcript.json"
    ))
    .unwrap();
    let exchange = |id: &str| {
        corpus["exchanges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap()
    };
    let body =
        |id: &str| serde_json::from_str::<Value>(exchange(id)["body"].as_str().unwrap()).unwrap();
    for (command, fixture, expected) in [
        ("list", "work-list", body("work-list")),
        ("questions", "questions-list", json!({"questions":[]})),
        ("relayed", "questions-list", json!({"questions":[]})),
        (
            "running",
            "jobs-list",
            json!({"jobs":[],"digest":"f6984354"}),
        ),
    ] {
        let cloud = Cloud::new(vec![(200, body(fixture))]);
        let home = Home::new(&cloud.endpoint);
        let result = home.run(&[command, "--mission", "tx-work"], false);
        assert_eq!(result.0, 0, "{}", result.2);
        let actual: Value = serde_json::from_str(&result.1).unwrap();
        assert_eq!(actual, expected, "{command}");
    }
    for (command, fixture, index, argument) in [
        ("answer", "questions-answer", 0, Some("two")),
        ("confirm", "questions-confirm", 1, None),
        ("accept", "questions-accept", 2, Some("fd785d45")),
    ] {
        let recorded = exchange(fixture);
        let request: Value =
            serde_json::from_str(recorded["request"]["body"].as_str().unwrap()).unwrap();
        let mut question = body("questions-list")["questions"][index].clone();
        // Restore the pre-write state; the frozen HTTP corpus lists questions
        // only after these three mutations. All other fields remain recorded.
        if command == "confirm" {
            question["confirmedAt"] = Value::Null;
            question["confirmedBy"] = Value::Null;
        } else {
            for field in ["answeredAt", "answeredBy", "answeredByPrincipal", "answer"] {
                question[field] = Value::Null;
            }
        }
        let expected = body(fixture);
        let cloud = Cloud::new(vec![
            (200, json!({"questions":[question]})),
            (200, expected.clone()),
        ]);
        let home = Home::new(&cloud.endpoint);
        let mut args = vec![
            command,
            "--mission",
            "tx-ask",
            request["questionId"].as_str().unwrap(),
        ];
        args.extend(argument);
        let result = home.run(&args, false);
        assert_eq!(result.0, 0, "{}", result.2);
        assert_eq!(serde_json::from_str::<Value>(&result.1).unwrap(), expected);
        cloud.assert_owner(&[
            ("GET", "/v1/missions/tx-ask/work/questions", Value::Null),
            (
                "POST",
                recorded["request"]["path"].as_str().unwrap(),
                request.clone(),
            ),
        ]);
    }
}

#[test]
fn owner_refusals_retain_cloud_reason_and_recovery_without_retry_or_credential_leaks() {
    let cloud = Cloud::new(vec![(
        404,
        json!({
            "error":"NOT_FOUND", "message":"no work item in this mission",
            "recovery":"check the selected mission", "retryable":false,
            "details":{"refusal":"unknown_work_item", "ids":["task-other"], "token":TOKEN},
            "echo":TOKEN
        }),
    )]);
    let home = Home::new(&cloud.endpoint);
    let result = home.run(
        &["move", "--mission", "selected", "next", "task-other"],
        false,
    );
    assert_ne!(result.0, 0);
    for text in [
        "404",
        "NOT_FOUND",
        "unknown_work_item",
        "check the selected mission",
    ] {
        assert!(result.2.contains(text), "missing {text}: {}", result.2);
    }
    cloud.assert_owner(&[(
        "POST",
        "/v1/missions/selected/work/owner/move",
        json!({"moves":[{"workItemId":"task-other", "horizon":"next"}]}),
    )]);
}

#[test]
fn mutation_acknowledgements_must_match_the_whole_request() {
    for response in [
        json!({"ok":true, "moved":[]}),
        json!({"ok":true, "moved":[{"id":"wrong-task", "horizon":"next", "detachedFrom":null}]}),
        json!({"ok":false, "moved":[{"id":"task-1", "horizon":"next", "detachedFrom":null}]}),
        json!({"ok":true, "moved":[{"id":"task-1", "horizon":"now", "detachedFrom":null}]}),
    ] {
        let cloud = Cloud::new(vec![(200, response)]);
        let home = Home::new(&cloud.endpoint);
        let result = home.run(&["move", "--mission", "a", "next", "task-1"], false);
        assert_ne!(result.0, 0, "a mismatched acknowledgement is not success");
        assert!(result.2.contains("outcome may be unknown"), "{}", result.2);
    }
    for response in [
        json!({"ok":true,"workItemIds":[]}),
        json!({"ok":true,"workItemIds":[null]}),
        json!({"ok":false,"workItemIds":["created"]}),
    ] {
        let cloud = Cloud::new(vec![(201, response)]);
        let home = Home::new(&cloud.endpoint);
        let result = home.run(&["file", "--mission", "a", "brief"], false);
        assert_ne!(result.0, 0);
        assert!(result.2.contains("outcome may be unknown"), "{}", result.2);
    }
}

#[test]
fn identifiers_that_the_backend_would_trim_are_rejected_before_network_io() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    for args in [
        vec!["move", "--mission", "a", "next", " task-1"],
        vec!["file", "--mission", "a", "--parent", "task-1 ", "brief"],
        vec!["answer", "--mission", "a", " q-1", "yes"],
        vec![
            "questions",
            "--mission",
            "a",
            "--work-item",
            "task-1\u{feff}",
        ],
    ] {
        let result = home.run(&args, false);
        assert_ne!(result.0, 0);
        assert!(result.2.contains("identifier"), "{}", result.2);
    }
    cloud.assert_owner(&[]);
}

#[test]
fn enrollment_rejects_agents_overlaps_reserved_ids_and_unfinished_project_operations() {
    let cloud = Cloud::new(vec![]);
    let home = Home::new(&cloud.endpoint);
    let root = home.0.join("project");
    assert_ne!(
        home.run(
            &["project", "enroll", "local-project", root.to_str().unwrap()],
            true
        )
        .0,
        0
    );
    assert!(!home.0.join(".agent-broker/projects.json").exists());
    assert_ne!(
        home.run(
            &["project", "enroll", "self", root.to_str().unwrap()],
            false
        )
        .0,
        0
    );
    assert_eq!(
        home.run(
            &["project", "enroll", "local-project", root.to_str().unwrap()],
            false
        )
        .0,
        0
    );
    let before = fs::read(home.0.join(".agent-broker/projects.json")).unwrap();
    fs::create_dir(root.join("child")).unwrap();
    for path in [&home.0, &root.join("child"), &home.0.join(".config")] {
        assert_ne!(
            home.run(
                &["project", "enroll", "other", path.to_str().unwrap()],
                false
            )
            .0,
            0
        );
    }
    for args in [
        vec!["project", "pause", "local-project"],
        vec!["project", "unpause", "local-project"],
        vec!["project", "role", "apply", "local-project"],
    ] {
        let r = home.run(&args, false);
        assert_ne!(r.0, 0);
        assert!(r.2.contains("unavailable"), "{}", r.2);
    }
    assert_eq!(
        before,
        fs::read(home.0.join(".agent-broker/projects.json")).unwrap()
    );
    assert!(!root.join("ALL-TESTS-PAUSED.md").exists());
    cloud.assert_owner(&[]);
}
