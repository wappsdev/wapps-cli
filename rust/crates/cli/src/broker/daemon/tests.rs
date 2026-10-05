use super::*;
use std::{fs, path::PathBuf, sync::atomic::AtomicUsize};

struct Daemon {
    home: PathBuf,
    socket: PathBuf,
    worker: Option<JoinHandle<Result<(), String>>>,
    credential: String,
}
impl Daemon {
    fn new(idle: Duration) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let home = broker_oracle::hermetic::temp_root(&format!(
            "idle-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let paths = Paths::at(&home).unwrap();
        let socket = paths.socket.clone();
        let config = Arc::new(Config {
            endpoint: "http://127.0.0.1:1".parse().unwrap(),
            client_id: "fixture".into(),
            secret: "fixture-secret".into(),
            addresses: vec!["127.0.0.1:1".parse().unwrap()],
        });
        let credential = fingerprint(&config);
        let worker = thread::spawn(move || run_at(paths, config, idle));
        let daemon = Self {
            home,
            socket,
            worker: Some(worker),
            credential,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !daemon.socket.exists() {
            assert!(Instant::now() < deadline, "daemon binds");
            thread::sleep(Duration::from_millis(5));
        }
        daemon
    }
    fn hello(&self, session: &str) -> BufReader<UnixStream> {
        let mut socket = UnixStream::connect(&self.socket).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        send(
            &mut socket,
            json!({"kind":"hello","version":1,"session":session,"credential":self.credential}),
        )
        .unwrap();
        let mut reader = BufReader::new(socket);
        assert_eq!(frame(&mut reader, 4096).unwrap()["kind"], "ready");
        reader
    }
    fn exits_within(&self, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        loop {
            if self.worker.as_ref().unwrap().is_finished() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(mut stream) = UnixStream::connect(&self.socket) {
            let _ = send(&mut stream, json!({"kind":"stop"}));
        }
        if let Some(worker) = self.worker.take() {
            assert!(worker.join().unwrap().is_ok());
        }
        assert!(!self.socket.exists());
        assert!(!self.socket.with_file_name("owner.json").exists());
        assert!(
            self.socket.with_file_name("lock").is_file(),
            "permanent kernel lock inode remains"
        );
        fs::remove_dir_all(&self.home).unwrap();
    }
}
#[test]
fn idle_daemon_exits_and_removes_only_ephemeral_ownership_files() {
    let daemon = Daemon::new(Duration::from_millis(100));
    assert!(daemon.exits_within(Duration::from_secs(1)));
}
#[test]
fn live_client_prevents_idle_exit_and_disconnect_starts_a_fresh_idle_period() {
    let daemon = Daemon::new(Duration::from_millis(100));
    let client = daemon.hello(&"a".repeat(64));
    assert!(!daemon.exits_within(Duration::from_millis(250)));
    drop(client);
    assert!(!daemon.exits_within(Duration::from_millis(40)));
    assert!(daemon.exits_within(Duration::from_secs(1)));
}
#[test]
fn client_that_never_completes_hello_is_evicted_then_idle_exits() {
    let daemon = Daemon::new(Duration::from_millis(100));
    let _client = UnixStream::connect(&daemon.socket).unwrap();
    assert!(daemon.exits_within(Duration::from_secs(4)));
}
#[test]
fn authenticated_socket_reconnect_supports_more_than_one_connection_per_session() {
    let daemon = Daemon::new(Duration::from_millis(100));
    let first = daemon.hello(&"b".repeat(64));
    let mut second = daemon.hello(&"b".repeat(64));
    drop(first);
    assert!(!daemon.exits_within(Duration::from_millis(250)));
    send(
        second.get_mut(),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .unwrap();
    assert_eq!(frame(&mut second, 4096).unwrap()["result"], json!({}));
    drop(second);
    assert!(daemon.exits_within(Duration::from_secs(1)));
}

#[test]
fn trickled_hello_cannot_extend_the_handshake_deadline() {
    let daemon = Daemon::new(Duration::from_millis(100));
    let mut client = UnixStream::connect(&daemon.socket).unwrap();
    let sender = thread::spawn(move || {
        for _ in 0..8 {
            if client.write_all(b" ").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(400));
        }
    });
    let exited = daemon.exits_within(Duration::from_millis(2700));
    sender.join().unwrap();
    assert!(
        exited,
        "hello has a total deadline, not an inactivity timeout"
    );
}
