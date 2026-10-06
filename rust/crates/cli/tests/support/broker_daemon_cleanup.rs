//! Test fixtures own a foreground daemon so teardown can stop and reap it.
use rustix::process::{kill_process, Pid, Signal};
use serde_json::Value;
use std::{
    cell::RefCell,
    fs::{self, Metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(10);
// Existing SIGTERM handling drains for at most 12 seconds; allow accept overhead.
const EXIT: Duration = Duration::from_secs(15);

#[derive(Default)]
pub struct DaemonCleanup(RefCell<Option<OwnedDaemon>>);
struct OwnedDaemon {
    child: Child,
    identity: Option<(Metadata, Metadata)>,
}

impl DaemonCleanup {
    pub fn start(&self, home: &Path) -> Result<(), String> {
        let mut owned = self.0.borrow_mut();
        if owned.is_some() {
            return Ok(());
        }
        private(home, false)?;
        let runtime = home.join(".agent-broker/daemon");
        if runtime.exists() {
            return Err("fixture must not reuse a daemon runtime".into());
        }
        let child = Command::new(env!("CARGO_BIN_EXE_wapps"))
            .args(["broker", "daemon"])
            .env_clear()
            .env("HOME", home)
            .current_dir(home.join("project"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot start fixture daemon")?;
        // Install ownership before logging or readiness can fail or unwind.
        *owned = Some(OwnedDaemon {
            child,
            identity: None,
        });
        let daemon = owned.as_mut().unwrap();
        let _ = writeln!(
            std::io::stderr(),
            "owned fixture started home={} pid={}",
            home.display(),
            daemon.child.id()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if daemon
                .child
                .try_wait()
                .map_err(|_| "cannot inspect fixture child")?
                .is_some()
            {
                return Err("fixture daemon exited before readiness".into());
            }
            if let Ok(identity) = identity(home) {
                // Readiness is diagnostic, never a signalling authority. Signal
                // handlers are installed before the daemon publishes either file.
                // No socket connect is needed (including to a saturated backlog).
                let fd = rustix::fs::open(
                    runtime.join("owner.json"),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| "cannot open fixture daemon record")?;
                let file = fs::File::from(fd);
                if !same(
                    &file
                        .metadata()
                        .map_err(|_| "cannot inspect opened record")?,
                    &identity.1,
                ) {
                    return Err("fixture daemon record changed during readiness".into());
                }
                let record: Value = serde_json::from_reader(file.take(4096))
                    .map_err(|_| "invalid fixture daemon record")?;
                if record["pid"] != daemon.child.id() {
                    return Err("fixture daemon record belongs to a different child".into());
                }
                daemon.identity = Some(identity);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("fixture daemon readiness timed out".into());
            }
            thread::sleep(POLL);
        }
    }

    pub fn remove_home(&mut self, home: &Path) {
        let result = self.finish(home).and_then(|()| {
            fs::remove_dir_all(home).map_err(|_| "cannot remove fixture home".to_owned())
        });
        if let Err(error) = result {
            // Never double-panic and hide the assertion/runner failure being unwound.
            // Retain private state for diagnosis when teardown could not be proven.
            if thread::panicking() {
                let _ = writeln!(
                    std::io::stderr(),
                    "fixture cleanup failed at {}: {error}",
                    home.display()
                );
            } else {
                panic!("fixture cleanup failed at {}: {error}", home.display());
            }
        }
    }

    fn finish(&mut self, home: &Path) -> Result<(), String> {
        self.finish_after_check(home, || Ok(()))
    }

    // The test hook replaces a pathname at the exact former control boundary.
    fn finish_after_check(
        &mut self,
        home: &Path,
        after_check: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let Some(mut daemon) = self.0.get_mut().take() else {
            if home.join(".agent-broker/daemon").exists() {
                return Err("refusing to remove an unowned daemon runtime".into());
            }
            return Ok(());
        };
        let result = (|| {
            if daemon
                .child
                .try_wait()
                .map_err(|_| "cannot inspect fixture child")?
                .is_some()
            {
                return Err("fixture daemon exited before teardown".into());
            }
            let (socket, record) = identity(home)?;
            let (expected_socket, expected_record) = daemon
                .identity
                .as_ref()
                .ok_or("fixture daemon was not ready")?;
            if !same(&socket, expected_socket) || !same(&record, expected_record) {
                return Err("fixture daemon ownership resources changed".into());
            }
            after_check()?;
            // Authority is this exact foreground Child, not a pathname or disk
            // PID. No other thread reaps it; even if it exits here, its unreaped
            // zombie reserves the PID until our next try_wait. Never connect to
            // a possibly replaced endpoint to send stop (or first send status).
            kill_process(Pid::from_child(&daemon.child), Signal::Term)
                .map_err(|_| "cannot signal owned fixture child")?;
            let status = wait(&mut daemon.child, EXIT)?;
            if !status.success() {
                return Err("fixture daemon did not exit successfully".into());
            }
            for name in ["broker.sock", "owner.json"] {
                match fs::symlink_metadata(home.join(".agent-broker/daemon").join(name)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err("fixture daemon left ownership resources after exit".into())
                    }
                    Err(_) => return Err("cannot inspect fixture resources after exit".into()),
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            // Only our unreaped Child handle is eligible, never a PID from disk.
            // try_wait reaps an exited child, so never kill after it returns Some.
            let recovery = (|| {
                if daemon
                    .child
                    .try_wait()
                    .map_err(|_| "cannot inspect owned fixture child during recovery")?
                    .is_none()
                {
                    daemon
                        .child
                        .kill()
                        .map_err(|_| "cannot terminate owned fixture child")?;
                    wait(&mut daemon.child, Duration::from_secs(3))?;
                }
                Ok::<(), String>(())
            })();
            return Err(match recovery {
                Ok(()) => error,
                Err(recovery) => format!("{error}; owned-child recovery failed: {recovery}"),
            });
        }
        Ok(())
    }
}

fn wait(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| "cannot reap fixture child")? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("fixture child exit timed out".into());
        }
        thread::sleep(POLL);
    }
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn private(path: &Path, socket: bool) -> Result<Metadata, String> {
    use std::os::unix::fs::FileTypeExt;
    let meta = fs::symlink_metadata(path).map_err(|_| "cannot inspect fixture ownership")?;
    let mode = if socket { 0o600 } else { 0o700 };
    if meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != mode
        || if socket {
            !meta.file_type().is_socket()
        } else {
            !meta.is_dir()
        }
    {
        return Err("fixture runtime must be owned, private and nonsymlink".into());
    }
    Ok(meta)
}
fn identity(home: &Path) -> Result<(Metadata, Metadata), String> {
    private(home, false)?;
    private(&home.join(".agent-broker/daemon"), false)?;
    let socket = private(&home.join(".agent-broker/daemon/broker.sock"), true)?;
    let record = fs::symlink_metadata(home.join(".agent-broker/daemon/owner.json"))
        .map_err(|_| "cannot inspect fixture daemon record")?;
    if !record.is_file()
        || record.uid() != rustix::process::geteuid().as_raw()
        || record.mode() & 0o777 != 0o600
        || record.nlink() != 1
    {
        return Err("fixture daemon record must be owned and private".into());
    }
    Ok((socket, record))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    const CONTROL: Duration = Duration::from_secs(2);

    fn home() -> crate::Home {
        let home = crate::Home::new("http://127.0.0.1:9");
        // Owner-command homes are deliberately unenrolled by default. Prepare
        // only these fresh cleanup-test homes for a foreground daemon.
        fs::create_dir_all(home.0.join(".agent-broker")).unwrap();
        fs::write(
            home.0.join(".agent-broker/projects.json"),
            serde_json::json!({"version":1,"projects":{"local-project":{"root":home.0.join("project")}}})
                .to_string(),
        )
        .unwrap();
        fs::set_permissions(
            home.0.join(".config/wapps-broker/agents.secret"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        home
    }

    #[test]
    fn stopped_owned_child_has_bounded_termination_and_reap() {
        let mut home = home();
        home.1.start(&home.0).unwrap();
        let pid = {
            let mut owned = home.1 .0.borrow_mut();
            let child = &mut owned.as_mut().unwrap().child;
            assert!(child.try_wait().unwrap().is_none());
            let pid = child.id();
            // Only the unreaped foreground child from this fresh HOME is stopped.
            kill_process(Pid::from_child(child), Signal::Stop).unwrap();
            pid
        };
        let started = Instant::now();
        let outcome = home.1.finish(&home.0);
        let elapsed = started.elapsed();
        eprintln!(
            "stopped root={} pid={pid} elapsed={elapsed:?} outcome={outcome:?}",
            home.0.display()
        );
        assert_eq!(outcome.unwrap_err(), "fixture child exit timed out");
        assert!(elapsed >= Duration::from_secs(15));
        assert!(elapsed < Duration::from_millis(18250));
        // SAFETY: observation only, of the child started/stopped by this test.
        assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) }, -1);
        assert!(home.0.join(".agent-broker/daemon/owner.json").exists());
        assert!(home.0.join(".agent-broker/daemon/broker.sock").exists());
        fs::remove_dir_all(home.0.join(".agent-broker/daemon")).unwrap();
        let root = home.0.clone();
        drop(home);
        assert!(!root.exists());
    }

    #[test]
    fn changed_socket_before_teardown_is_not_contacted() {
        let mut home = home();
        home.1.start(&home.0).unwrap();
        let pid = home.1 .0.borrow().as_ref().unwrap().child.id();
        let socket = home.0.join(".agent-broker/daemon/broker.sock");
        fs::rename(&socket, socket.with_extension("original")).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let started = Instant::now();
        let outcome = home.1.finish(&home.0);
        eprintln!(
            "changed-socket root={} pid={pid} elapsed={:?} outcome={outcome:?}",
            home.0.display(),
            started.elapsed()
        );
        assert!(outcome.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        // SAFETY: observation only, of the child just started by this fixture.
        assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) }, -1);
        assert!(home.0.exists() && socket.exists());
        fs::remove_dir_all(home.0.join(".agent-broker/daemon")).unwrap();
        let root = home.0.clone();
        drop(home);
        assert!(!root.exists());
    }

    #[test]
    fn readiness_error_is_preserved_and_diagnostic_home_is_retained() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let home = home();
        let root = home.0.clone();
        fs::remove_file(root.join(".config/wapps-broker/agents.secret")).unwrap();
        let mut pid = None;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let home = home;
            let error = home.1.start(&home.0).unwrap_err();
            pid = Some(home.1 .0.borrow().as_ref().unwrap().child.id());
            std::panic::panic_any(error);
        }));
        let error = *outcome.unwrap_err().downcast::<String>().unwrap();
        assert_eq!(error, "fixture daemon exited before readiness");
        let pid = pid.unwrap();
        eprintln!(
            "readiness-error root={} pid={pid} error={error}",
            root.display()
        );
        // SAFETY: observation only, of the child started by this fresh HOME.
        assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) }, -1);
        assert!(root.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_at_shutdown_boundary_receives_no_connection() {
        let mut home = home();
        home.1.start(&home.0).unwrap();
        let pid = home.1 .0.borrow().as_ref().unwrap().child.id();
        let socket = home.0.join(".agent-broker/daemon/broker.sock");
        let retained = socket.with_extension("original");
        // An inert peer, not another daemon, replaces this run's endpoint only
        // after teardown has accepted the original inode/record identities.
        let mut replacement = None;
        let started = Instant::now();
        let outcome = home.1.finish_after_check(&home.0, || {
            fs::rename(&socket, &retained).map_err(|e| e.to_string())?;
            let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            replacement = Some(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_read_timeout(Some(CONTROL)).unwrap();
                            let mut reader = std::io::BufReader::new(&mut stream);
                            let mut frame = String::new();
                            use std::io::BufRead;
                            let _ = reader.read_line(&mut frame);
                            // Refuse promptly so the defective helper still
                            // recovers/reaps its exact owned child on RED.
                            let _ = writeln!(stream, "{{\"kind\":\"inert\"}}");
                            return Some(frame);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => panic!("cannot inspect replacement listener: {e}"),
                    }
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(POLL);
                }
            }));
            Ok(())
        });
        let elapsed = started.elapsed();
        let received = replacement.unwrap().join().unwrap();
        eprintln!(
            "replacement root={} pid={pid} elapsed={elapsed:?} outcome={outcome:?} received={received:?}",
            home.0.display()
        );
        assert!(
            received.is_none(),
            "replacement endpoint received {received:?}"
        );
        assert!(
            outcome.is_err(),
            "changed resources must retain diagnostics"
        );
        assert!(elapsed < Duration::from_secs(18));
        // SAFETY: observation only, of the child just started by this fixture.
        assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) }, -1);
        assert!(home.0.exists() && retained.exists() && socket.exists());
        // The assertions above prove retention and reaping before this test
        // removes its own injected runtime; Home then removes the remaining HOME.
        fs::remove_dir_all(home.0.join(".agent-broker/daemon")).unwrap();
        let root = home.0.clone();
        drop(home);
        assert!(!root.exists());
    }
}
