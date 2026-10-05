//! The stdio process owns a connection, never the daemon's lifetime.
use super::{fingerprint, frame, send, Config, Paths, HANDSHAKE};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use std::{
    io::{BufReader, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn serve() -> Result<(), String> {
    // Keep 13.1's enrollment and file-only credential validation at each entry.
    // The daemon also loads it itself; a changed credential fails the handshake
    // rather than silently using a prior client's config or mission.
    let config = Config::load()?;
    let paths = Paths::load()?;
    let mut socket = ensure(&paths)?;
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "cannot create daemon session")?;
    let session: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    socket
        .set_read_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound daemon handshake")?;
    socket
        .set_write_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound daemon writes")?;
    send(
        &mut socket,
        json!({"kind":"hello","version":1,"session":session,"credential":fingerprint(&config)}),
    )?;
    let mut input = BufReader::new(
        socket
            .try_clone()
            .map_err(|_| "cannot clone daemon connection")?,
    );
    if frame(&mut input, 4096)? != json!({"kind":"ready","version":1}) {
        return Err(
            "daemon handshake refused; restart the daemon after a credential change".into(),
        );
    }
    socket
        .set_read_timeout(None)
        .map_err(|_| "cannot clear daemon handshake deadline")?;
    // Read stdin off the main thread: a dead daemon must terminate this client
    // even if the MCP host is keeping stdin open and waiting for a reply.
    thread::spawn(move || {
        let result = std::io::copy(&mut std::io::stdin().lock(), &mut socket);
        let _ = socket.shutdown(if result.is_ok() {
            Shutdown::Write
        } else {
            Shutdown::Both
        });
    });
    let mut stdout = std::io::stdout().lock();
    loop {
        let value = frame(&mut input, 16 * 1024 * 1024).map_err(|_| "broker daemon disconnected; outcome may be unknown; reconnect without replaying mutations")?;
        if value["kind"] == "end" {
            return if value["ok"] == true {
                Ok(())
            } else {
                Err("broker daemon ended this MCP session".into())
            };
        }
        writeln!(stdout, "{value}")
            .and_then(|()| stdout.flush())
            .map_err(|_| "cannot write MCP stdout")?;
    }
}
fn connect(paths: &Paths) -> Result<UnixStream, String> {
    paths.check_socket()?;
    UnixStream::connect(&paths.socket).map_err(|_| "cannot connect to broker daemon".into())
}
fn ensure(paths: &Paths) -> Result<UnixStream, String> {
    if let Ok(stream) = connect(paths) {
        return Ok(stream);
    }
    let exe = std::env::current_exe().map_err(|_| "cannot locate wapps executable")?;
    // Absolute executable, no shell, no inherited stdin/stdout/credentials, and
    // setsid in the child. A racing starter loses the kernel claim harmlessly.
    let mut child = Command::new(exe)
        .args(["broker", "daemon", "--detached"])
        .env_clear()
        .env("HOME", std::env::var_os("HOME").ok_or("HOME is required")?)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "cannot spawn broker daemon")?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(stream) = connect(paths) {
            // Reap our own child if this stdio process outlives it. The process
            // exiting before this thread does is fine: the daemon is detached.
            thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(stream);
        }
        if Instant::now() >= deadline {
            // Only the Child handle we created is eligible for termination.
            let _ = child.kill();
            let _ = child.wait();
            return Err("broker daemon did not become ready within 15 seconds".into());
        }
        // A contender may have exited because another starter won. Keep waiting
        // for that winner's socket, including its partial startup window.
        let _ = child.try_wait();
        thread::sleep(Duration::from_millis(20));
    }
}
