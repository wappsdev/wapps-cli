//! Test fixtures own a foreground daemon so teardown can stop and reap it.
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    fs::{self, Metadata},
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(10);
const CONTROL: Duration = Duration::from_secs(2);
// Production drain is bounded at 12 seconds; allow its control/accept overhead.
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
        // Install ownership before any readiness operation that could fail.
        *owned = Some(OwnedDaemon {
            child,
            identity: None,
        });
        let daemon = owned.as_mut().unwrap();
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
                if control(home, "status")?["pid"] != daemon.child.id() {
                    return Err("fixture socket belongs to a different child".into());
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
                eprintln!("fixture cleanup failed at {}: {error}", home.display());
            } else {
                panic!("fixture cleanup failed at {}: {error}", home.display());
            }
        }
    }

    fn finish(&mut self, home: &Path) -> Result<(), String> {
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
                return Err("fixture daemon ownership changed; refusing socket control".into());
            }
            if control(home, "stop")?["kind"] != "stopping" {
                return Err("fixture daemon refused stop".into());
            }
            let status = wait(&mut daemon.child, EXIT)?;
            if !status.success() {
                return Err("fixture daemon did not exit successfully".into());
            }
            for name in ["broker.sock", "owner.json"] {
                if home.join(".agent-broker/daemon").join(name).exists() {
                    return Err("fixture daemon left ownership resources after exit".into());
                }
            }
            Ok(())
        })();
        if result.is_err() {
            // Only our unreaped Child handle is eligible, never a PID from disk.
            // try_wait reaps an exited child, so never kill after it returns Some.
            match daemon.child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    daemon
                        .child
                        .kill()
                        .map_err(|_| "cannot terminate owned fixture child")?;
                    wait(&mut daemon.child, Duration::from_secs(3))?;
                }
                Err(_) => return Err("cannot inspect owned fixture child during recovery".into()),
            }
        }
        result
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
fn control(home: &Path, kind: &str) -> Result<Value, String> {
    let mut stream = UnixStream::connect(home.join(".agent-broker/daemon/broker.sock"))
        .map_err(|_| "cannot connect to fixture daemon")?;
    stream
        .set_write_timeout(Some(CONTROL))
        .map_err(|_| "cannot bound fixture control write")?;
    writeln!(stream, "{}", json!({"kind":kind})).map_err(|_| "cannot write fixture control")?;
    let deadline = Instant::now() + CONTROL;
    let mut reply = Vec::new();
    while reply.len() < 4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("fixture control reply timed out".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "cannot bound fixture control read")?;
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_| "cannot read fixture control")?;
        if byte[0] == b'\n' {
            return serde_json::from_slice(&reply)
                .map_err(|_| "invalid fixture control JSON".into());
        }
        reply.push(byte[0]);
    }
    Err("invalid fixture control frame".into())
}
