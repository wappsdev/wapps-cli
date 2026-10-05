//! Lifecycle tests use isolated homes, real Unix sockets and owned child handles only.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = broker_oracle::hermetic::temp_root(&format!(
            "daemon-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("project")).unwrap();
        fs::create_dir_all(root.join(".agent-broker")).unwrap();
        fs::create_dir_all(root.join(".config/wapps-broker")).unwrap();
        fs::write(
            root.join(".agent-broker/projects.json"),
            json!({"version":1,"projects":{"local":{"root":root.join("project")}}}).to_string(),
        )
        .unwrap();
        fs::write(
            root.join(".config/wapps-broker/client.yaml"),
            "clientId: fixture\nendpoint: http://127.0.0.1:1\n",
        )
        .unwrap();
        let secret = root.join(".config/wapps-broker/agents.secret");
        fs::write(&secret, "fixture-secret").unwrap();
        fs::set_permissions(secret, fs::Permissions::from_mode(0o600)).unwrap();
        Self(root)
    }
    fn command(&self, verb: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wapps"));
        cmd.args(["broker", verb])
            .env_clear()
            .env("HOME", &self.0)
            .current_dir(self.0.join("project"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }
    fn socket(&self) -> PathBuf {
        self.0.join(".agent-broker/daemon/broker.sock")
    }
    fn control(&self, kind: &str) -> Option<Value> {
        let mut stream = UnixStream::connect(self.socket()).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        writeln!(stream, "{}", json!({"kind":kind})).ok()?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).ok()?;
        serde_json::from_str(&line).ok()
    }
    fn ready(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(v) = self.control("status") {
                return v;
            }
            assert!(Instant::now() < deadline, "daemon must become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn stopped(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.socket().exists() {
            assert!(Instant::now() < deadline, "daemon must remove its socket");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        self.control("stop");
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.socket().exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "owned child must exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn daemon_command_owns_private_socket_and_stops_without_pid_signals() {
    let home = Home::new();
    let mut daemon = Process(home.command("daemon").spawn().unwrap());
    let status = home.ready();
    assert_eq!(status["pid"], daemon.0.id());
    assert_eq!(
        fs::metadata(home.socket()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(home.socket().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(home
        .command("daemon")
        .arg("--stop")
        .status()
        .unwrap()
        .success());
    assert!(daemon.wait().success());
    home.stopped();
}

#[test]
fn two_concurrent_starts_have_one_owner_and_loser_cannot_unlink_socket() {
    let home = Home::new();
    let mut a = Process(home.command("daemon").spawn().unwrap());
    let mut b = Process(home.command("daemon").spawn().unwrap());
    let pid = home.ready()["pid"].as_u64().unwrap();
    let (winner, loser) = if pid == a.0.id() as u64 {
        (&mut a, &mut b)
    } else {
        (&mut b, &mut a)
    };
    assert_eq!(pid, winner.0.id() as u64);
    assert!(!loser.wait().success());
    assert_eq!(home.control("status").unwrap()["pid"], pid);
    home.control("stop").unwrap();
    assert!(winner.wait().success());
}

#[test]
fn dead_owner_and_partial_record_recover_without_trusting_record_pid() {
    let home = Home::new();
    let mut first = Process(home.command("daemon").spawn().unwrap());
    home.ready();
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    // A truncated record may contain the test runner's PID. It is never a liveness authority.
    fs::write(
        home.socket().with_file_name("owner.json"),
        format!("{{\"pid\":{}", std::process::id()),
    )
    .unwrap();
    let mut next = Process(home.command("daemon").spawn().unwrap());
    assert_eq!(home.ready()["pid"], next.0.id());
    home.control("stop").unwrap();
    assert!(next.wait().success());
}

#[test]
fn failed_bind_releases_claim_and_never_removes_a_regular_file() {
    let home = Home::new();
    let dir = home.socket().parent().unwrap().to_owned();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.socket(), "not a socket").unwrap();
    let mut failed = Process(home.command("daemon").spawn().unwrap());
    assert!(!failed.wait().success());
    assert_eq!(fs::read_to_string(home.socket()).unwrap(), "not a socket");
    fs::remove_file(home.socket()).unwrap();
    let mut next = Process(home.command("daemon").spawn().unwrap());
    home.ready();
    home.control("stop").unwrap();
    assert!(next.wait().success());
}

#[test]
fn stdio_spawns_detached_daemon_and_reconnects_to_same_owner() {
    let home = Home::new();
    let ping = |home: &Home| {
        let mut cmd = home.command("serve");
        let mut child = Process(
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        writeln!(
            child.0.stdin.take().unwrap(),
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"})
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["result"],
            json!({})
        );
        assert!(child.wait().success());
    };
    ping(&home);
    let pid = home.ready()["pid"].clone();
    let daemon_pid = rustix::process::Pid::from_raw(pid.as_u64().unwrap() as i32).unwrap();
    assert_eq!(
        rustix::process::getsid(Some(daemon_pid)).unwrap(),
        daemon_pid
    );
    assert_eq!(
        rustix::process::getpgid(Some(daemon_pid)).unwrap(),
        daemon_pid
    );
    ping(&home);
    assert_eq!(home.ready()["pid"], pid);
    home.control("stop").unwrap();
    home.stopped();
}

#[test]
fn insecure_runtime_directory_and_symlink_lock_are_refused() {
    let home = Home::new();
    let dir = home.socket().parent().unwrap().to_owned();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!Process(home.command("daemon").spawn().unwrap())
        .wait()
        .success());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let target = home.0.join("untouched");
    fs::write(&target, "untouched").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("lock")).unwrap();
    assert!(!Process(home.command("daemon").spawn().unwrap())
        .wait()
        .success());
    assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
}

struct Peer {
    process: Process,
    input: Option<std::process::ChildStdin>,
    output: std::sync::mpsc::Receiver<Value>,
}
impl Peer {
    fn new(home: &Home) -> Self {
        let mut process = Process(
            home.command("serve")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let input = process.0.stdin.take();
        let stdout = process.0.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str(&line) {
                    let _ = tx.send(v);
                }
            }
        });
        let mut peer = Self {
            process,
            input,
            output,
        };
        peer.send(json!({"jsonrpc":"2.0","id":0,"method":"ping"}));
        assert_eq!(peer.receive()["result"], json!({}));
        peer
    }
    fn send(&mut self, value: Value) {
        writeln!(self.input.as_mut().unwrap(), "{value}").unwrap();
    }
    fn receive(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(3))
            .expect("bounded reply")
    }
    fn call(&mut self, id: u64, mission: &str, name: &str, mut args: Value) -> Value {
        args["missionId"] = json!(mission);
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}));
        self.receive()["result"]["structuredContent"].clone()
    }
    fn close(mut self) {
        self.input.take();
        assert!(self.process.wait().success());
    }
}
fn exchange(
    id: Value,
    mission: &str,
    tool: &str,
    args: Value,
    result: Value,
) -> broker_oracle::cloud::Exchange {
    use broker_oracle::cloud::{Envelope, Exchange, Request};
    Exchange {
        id: format!("{id}-{mission}-{tool}"), route: String::new(), principal: None,
        request: Request { method:"POST".into(), path:format!("/v1/missions/{mission}/mcp"), body:Some(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}}).to_string()) },
        status:200, envelope:Envelope { content_type:"application/json".into(), retry_after:None },
        body:json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":result.to_string()}],"structuredContent":result}}).to_string(),
    }
}
#[test]
fn multiple_clients_and_missions_release_only_a_gone_owner_before_claim() {
    use broker_oracle::cloud::FakeCloud;
    let authority = json!({"capability":"lease-a","fencingToken":1});
    let cloud = FakeCloud::start(
        vec![
            exchange(
                json!(1),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"claude"}),
                json!({"authority":authority}),
            ),
            exchange(
                json!(2),
                "beta",
                "orchestrator_claim",
                json!({"provider":"codex"}),
                json!({"authority":{"capability":"lease-b","fencingToken":2}}),
            ),
            exchange(
                json!(3),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"codex"}),
                json!({"standby":true}),
            ),
            exchange(
                json!(0),
                "alpha",
                "orchestrator_release",
                authority.clone(),
                json!({"released":true}),
            ),
            exchange(
                json!(4),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"codex"}),
                json!({"authority":{"capability":"lease-c","fencingToken":3}}),
            ),
            exchange(
                json!(5),
                "alpha",
                "orchestrator_release",
                json!({"capability":"lease-c","fencingToken":3}),
                json!({"released":true}),
            ),
            exchange(
                json!(6),
                "beta",
                "orchestrator_release",
                json!({"capability":"lease-b","fencingToken":2}),
                json!({"released":true}),
            ),
        ],
        Some("fixture-secret".into()),
    )
    .unwrap();
    let home = Home::new();
    fs::write(
        home.0.join(".config/wapps-broker/client.yaml"),
        format!("clientId: fixture\nendpoint: {}\n", cloud.url()),
    )
    .unwrap();
    let mut first = Peer::new(&home);
    let mut second = Peer::new(&home);
    assert_eq!(
        first.call(
            1,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"claude"})
        )["authority"],
        authority
    );
    assert_eq!(
        second.call(2, "beta", "orchestrator_claim", json!({"provider":"codex"}))["authority"]
            ["fencingToken"],
        2
    );
    assert_eq!(
        second.call(
            3,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"codex"})
        )["standby"],
        true
    );
    first.close();
    assert_eq!(
        second.call(
            4,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"codex"})
        )["authority"]["fencingToken"],
        3
    );
    assert_eq!(
        second.call(
            5,
            "alpha",
            "orchestrator_release",
            json!({"capability":"lease-c","fencingToken":3})
        )["released"],
        true
    );
    assert_eq!(
        second.call(
            6,
            "beta",
            "orchestrator_release",
            json!({"capability":"lease-b","fencingToken":2})
        )["released"],
        true
    );
    second.close();
    assert!(cloud.unanswered().is_empty(), "{:?}", cloud.unanswered());
    assert_eq!(cloud.requests().len(), 7);
    assert!(cloud
        .requests()
        .iter()
        .all(|r| r.access && !r.leaked && r.answered.is_some()));
}

#[test]
fn partial_startup_with_locked_empty_record_is_not_stolen() {
    let home = Home::new();
    let dir = home.socket().parent().unwrap().to_owned();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = fs::File::create(dir.join("lock")).unwrap();
    fs::set_permissions(dir.join("lock"), fs::Permissions::from_mode(0o600)).unwrap();
    lock.lock().unwrap();
    fs::write(dir.join("owner.json"), "").unwrap();
    let mut contender = Process(home.command("daemon").spawn().unwrap());
    assert!(!contender.wait().success());
    assert_eq!(fs::read_to_string(dir.join("owner.json")).unwrap(), "");
    drop(lock);
    let mut recovery = Process(home.command("daemon").spawn().unwrap());
    home.ready();
    home.control("stop").unwrap();
    assert!(recovery.wait().success());
}

#[test]
fn graceful_stop_closes_connected_clients_and_reconnect_spawns_fresh_daemon() {
    let home = Home::new();
    let mut first = Peer::new(&home);
    let mut second = Peer::new(&home);
    let old = home.ready()["pid"].clone();
    home.control("stop").unwrap();
    // The peers still hold stdin open: shutdown is driven by the socket, not host EOF.
    assert!(first.process.wait().success());
    assert!(second.process.wait().success());
    home.stopped();
    let next = Peer::new(&home);
    assert_ne!(home.ready()["pid"], old);
    next.close();
}

#[test]
fn bad_handshake_does_not_take_down_other_clients() {
    let home = Home::new();
    let mut good = Peer::new(&home);
    let mut bad = UnixStream::connect(home.socket()).unwrap();
    bad.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    writeln!(
        bad,
        "{}",
        json!({"kind":"hello","version":1,"session":"0".repeat(64),"credential":"wrong"})
    )
    .unwrap();
    let mut line = String::new();
    assert_eq!(BufReader::new(bad).read_line(&mut line).unwrap(), 0);
    good.send(json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
    assert_eq!(good.receive()["result"], json!({}));
    good.close();
}

#[test]
fn changing_credential_does_not_silently_reuse_the_daemons_old_credential() {
    let home = Home::new();
    let peer = Peer::new(&home);
    fs::write(
        home.0.join(".config/wapps-broker/agents.secret"),
        "new-fixture-secret",
    )
    .unwrap();
    let mut stale = Process(home.command("serve").spawn().unwrap());
    assert!(!stale.wait().success());
    peer.close();
}

#[test]
fn termination_signal_drains_clients_and_cleans_ownership() {
    let home = Home::new();
    let mut daemon = Process(home.command("daemon").spawn().unwrap());
    home.ready();
    let mut peer = Peer::new(&home);
    // Only the child we just spawned, never a PID read from disk.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(daemon.0.id() as i32).unwrap(),
        rustix::process::Signal::Term,
    )
    .unwrap();
    assert!(
        daemon.wait().success(),
        "SIGTERM must use the graceful path"
    );
    assert!(peer.process.wait().success());
    home.stopped();
}

#[test]
fn stale_gone_owner_capability_does_not_block_a_fresh_cloud_claim() {
    use broker_oracle::cloud::FakeCloud;
    for refusal in [
        "no_live_lease",
        "lease_expired",
        "stale_fencing_token",
        "invalid_lease_capability",
    ] {
        let authority = json!({"capability":"old-capability","fencingToken":1});
        let mut release = exchange(
            json!(0),
            "alpha",
            "orchestrator_release",
            authority.clone(),
            json!({"error":"FORBIDDEN","details":{"refusal":refusal}}),
        );
        let mut body: Value = serde_json::from_str(&release.body).unwrap();
        body["result"]["isError"] = json!(true);
        release.body = body.to_string();
        let cloud = FakeCloud::start(
            vec![
                exchange(
                    json!(1),
                    "alpha",
                    "orchestrator_claim",
                    json!({"provider":"claude"}),
                    json!({"authority":authority}),
                ),
                release,
                exchange(
                    json!(2),
                    "alpha",
                    "orchestrator_claim",
                    json!({"provider":"codex"}),
                    json!({"authority":{"capability":"fresh-capability","fencingToken":2}}),
                ),
            ],
            Some("fixture-secret".into()),
        )
        .unwrap();
        let home = Home::new();
        fs::write(
            home.0.join(".config/wapps-broker/client.yaml"),
            format!("clientId: fixture\nendpoint: {}\n", cloud.url()),
        )
        .unwrap();
        let mut owner = Peer::new(&home);
        assert_eq!(
            owner.call(
                1,
                "alpha",
                "orchestrator_claim",
                json!({"provider":"claude"})
            )["authority"],
            authority
        );
        owner.close();
        let mut next = Peer::new(&home);
        assert_eq!(
            next.call(
                2,
                "alpha",
                "orchestrator_claim",
                json!({"provider":"codex"})
            )["authority"]["fencingToken"],
            2,
            "{refusal}"
        );
        next.close();
        assert!(cloud.unanswered().is_empty());
        assert_eq!(cloud.requests().len(), 3);
    }
}

#[test]
fn killed_stdio_owner_is_forgotten_without_killing_shared_daemon() {
    use broker_oracle::cloud::FakeCloud;
    let authority = json!({"capability":"abandoned","fencingToken":1});
    let cloud = FakeCloud::start(
        vec![
            exchange(
                json!(1),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"claude"}),
                json!({"authority":authority}),
            ),
            exchange(
                json!(0),
                "alpha",
                "orchestrator_release",
                authority.clone(),
                json!({"released":true}),
            ),
            exchange(
                json!(2),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"codex"}),
                json!({"authority":{"capability":"next","fencingToken":2}}),
            ),
        ],
        Some("fixture-secret".into()),
    )
    .unwrap();
    let home = Home::new();
    fs::write(
        home.0.join(".config/wapps-broker/client.yaml"),
        format!("clientId: fixture\nendpoint: {}\n", cloud.url()),
    )
    .unwrap();
    let mut owner = Peer::new(&home);
    assert_eq!(
        owner.call(
            1,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"claude"})
        )["authority"],
        authority
    );
    let pid = home.ready()["pid"].clone();
    owner.process.0.kill().unwrap();
    owner.process.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while home.control("status").unwrap()["connections"] != 0 {
        assert!(
            Instant::now() < deadline,
            "disconnected session must be removed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let mut next = Peer::new(&home);
    assert_eq!(home.ready()["pid"], pid);
    assert_eq!(
        next.call(
            2,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"codex"})
        )["authority"]["fencingToken"],
        2
    );
    next.close();
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 3);
}

#[test]
fn simultaneous_stdio_starters_converge_on_one_detached_owner() {
    let home = Home::new();
    let (mut first, mut second) = thread::scope(|scope| {
        let a = scope.spawn(|| Peer::new(&home));
        let b = scope.spawn(|| Peer::new(&home));
        (a.join().unwrap(), b.join().unwrap())
    });
    let status = home.ready();
    assert_eq!(status["connections"], 2);
    for peer in [&mut first, &mut second] {
        peer.send(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
        assert_eq!(peer.receive()["result"], json!({}));
    }
    first.close();
    second.close();
    assert_eq!(home.ready()["pid"], status["pid"]);
}

#[test]
fn graceful_shutdown_cancels_a_long_poll_without_waiting_for_its_deadline() {
    use broker_oracle::cloud::FakeCloud;
    let cloud = FakeCloud::start(
        vec![exchange(
            json!(1),
            "alpha",
            "agent_await",
            json!({"sinceDigest":"same"}),
            json!({"changed":false,"digest":"same"}),
        )],
        Some("fixture-secret".into()),
    )
    .unwrap();
    let home = Home::new();
    fs::write(
        home.0.join(".config/wapps-broker/client.yaml"),
        format!("clientId: fixture\nendpoint: {}\n", cloud.url()),
    )
    .unwrap();
    let mut peer = Peer::new(&home);
    peer.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"agent_await","arguments":{"missionId":"alpha","sinceDigest":"same","waitMs":55000}}}));
    let deadline = Instant::now() + Duration::from_secs(2);
    while cloud.requests().is_empty() {
        assert!(Instant::now() < deadline, "poll starts");
        thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    home.control("stop").unwrap();
    assert_eq!(
        peer.receive()["result"]["structuredContent"]["error"],
        "CANCELLED"
    );
    assert!(peer.process.wait().success());
    home.stopped();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 1);
}

#[test]
fn automatic_release_uses_no_string_id_that_could_match_the_runtime_credential() {
    use broker_oracle::cloud::FakeCloud;
    let authority = json!({"capability":"lease-a","fencingToken":1});
    let cloud = FakeCloud::start(
        vec![
            exchange(
                json!(1),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"claude"}),
                json!({"authority":authority}),
            ),
            exchange(
                json!(0),
                "alpha",
                "orchestrator_release",
                authority.clone(),
                json!({"released":true}),
            ),
            exchange(
                json!(2),
                "alpha",
                "orchestrator_claim",
                json!({"provider":"codex"}),
                json!({"standby":true}),
            ),
        ],
        Some("daemon-release".into()),
    )
    .unwrap();
    let home = Home::new();
    fs::write(
        home.0.join(".config/wapps-broker/client.yaml"),
        format!("clientId: fixture\nendpoint: {}\n", cloud.url()),
    )
    .unwrap();
    fs::write(
        home.0.join(".config/wapps-broker/agents.secret"),
        "daemon-release",
    )
    .unwrap();
    let mut owner = Peer::new(&home);
    assert_eq!(
        owner.call(
            1,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"claude"})
        )["authority"],
        authority
    );
    owner.close();
    let mut next = Peer::new(&home);
    assert_eq!(
        next.call(
            2,
            "alpha",
            "orchestrator_claim",
            json!({"provider":"codex"})
        )["standby"],
        true
    );
    next.close();
    assert!(cloud.unanswered().is_empty());
    assert_eq!(cloud.requests().len(), 3);
    assert!(cloud.requests().iter().all(|r| !r.leaked));
}
