//! Local lifecycle only. Workers are deliberately unavailable until slice 13.3.
mod client;
mod ownership;
mod sessions;
mod signals;
use super::config::Config;
pub use client::serve;
use ownership::{Claim, Paths};
use serde_json::{json, Value};
pub(in crate::broker) use sessions::Session;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const IDLE: Duration = Duration::from_secs(600);
const HANDSHAKE: Duration = Duration::from_secs(2);
const MAX_CLIENTS: usize = 64;

pub fn run(detached: bool) -> Result<(), String> {
    if detached {
        rustix::process::setsid().map_err(|_| "cannot detach broker daemon")?;
    }
    let _signals = signals::Signals::install()?;
    let paths = Paths::load()?;
    let config = Arc::new(Config::load()?);
    run_at(paths, config, IDLE)
}

struct Connection {
    socket: UnixStream,
    worker: JoinHandle<()>,
}
fn run_at(paths: Paths, config: Arc<Config>, idle: Duration) -> Result<(), String> {
    let mut claim = Claim::acquire(&paths)?;
    let listener = UnixListener::bind(&paths.socket).map_err(|_| "cannot bind daemon socket")?;
    claim.bound()?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "cannot poll daemon listener")?;
    let stop = Arc::new(AtomicBool::new(false));
    let sessions = Arc::new(sessions::Sessions::default());
    let mut connections: Vec<Connection> = Vec::new();
    let mut empty_since = Instant::now();
    let mut outcome = Ok(());
    while !stop.load(Ordering::Relaxed) && !signals::stopping() {
        let was_busy = !connections.is_empty();
        let mut index = 0;
        while index < connections.len() {
            if connections[index].worker.is_finished() {
                let _ = connections.swap_remove(index).worker.join();
            } else {
                index += 1;
            }
        }
        if was_busy && connections.is_empty() {
            empty_since = Instant::now();
        }
        if connections.is_empty() && empty_since.elapsed() >= idle {
            break;
        }
        match listener.accept() {
            Ok((socket, _)) => {
                if connections.len() >= MAX_CLIENTS {
                    continue;
                }
                let Ok(control) = socket.try_clone() else {
                    continue;
                };
                let config = Arc::clone(&config);
                let sessions = Arc::clone(&sessions);
                let stop = Arc::clone(&stop);
                let worker = thread::spawn(move || {
                    // All failure paths close the accepted stream. No credential or
                    // untrusted frame contents are written to logs.
                    let _ = connection(socket, config, sessions, stop);
                });
                connections.push(Connection {
                    socket: control,
                    worker,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                outcome = Err("daemon accept failed".into());
                break;
            }
        }
    }
    // Stop admitting clients first. Wake every read, cancel in-flight polls and
    // join their bounded HTTP exchanges before dropping the exclusive claim.
    drop(listener);
    for conn in &connections {
        let _ = conn.socket.shutdown(Shutdown::Read);
    }
    for conn in connections {
        let _ = conn.worker.join();
    }
    outcome
}
fn frame(input: &mut impl BufRead, max: u64) -> Result<Value, String> {
    let mut line = Vec::new();
    let count = input
        .take(max + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| "cannot read daemon frame")?;
    if count == 0 || count as u64 > max || line.last() != Some(&b'\n') {
        return Err("invalid daemon frame".into());
    }
    serde_json::from_slice(&line).map_err(|_| "invalid daemon JSON".into())
}
fn hello_frame(input: &mut BufReader<UnixStream>) -> Result<Value, String> {
    let deadline = Instant::now() + HANDSHAKE;
    let mut line = Vec::new();
    // A read timeout alone resets whenever a peer supplies another byte. Bound
    // the whole (small) hello, including peers that trickle data indefinitely.
    while line.len() < 4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("daemon handshake timed out".into());
        }
        input
            .get_ref()
            .set_read_timeout(Some(remaining))
            .map_err(|_| "cannot bound handshake")?;
        let mut byte = [0];
        input
            .read_exact(&mut byte)
            .map_err(|_| "cannot read daemon hello")?;
        if byte[0] == b'\n' {
            return serde_json::from_slice(&line).map_err(|_| "invalid daemon hello".into());
        }
        line.push(byte[0]);
    }
    Err("daemon hello exceeds 4096 bytes".into())
}
fn send(stream: &mut impl Write, value: Value) -> Result<(), String> {
    writeln!(stream, "{value}")
        .and_then(|()| stream.flush())
        .map_err(|_| "cannot write daemon frame".into())
}
fn fingerprint(config: &Config) -> String {
    let bytes = serde_json::to_vec(&json!([
        config.endpoint.as_str(),
        config.client_id,
        config.secret
    ]))
    .expect("credential tuple");
    ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn connection(
    mut socket: UnixStream,
    config: Arc<Config>,
    sessions: Arc<sessions::Sessions>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    // BSD accepts inherit the listener's nonblocking flag; Linux accepts do not.
    socket
        .set_nonblocking(false)
        .map_err(|_| "cannot configure accepted socket")?;
    socket
        .set_read_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound handshake")?;
    socket
        .set_write_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound writes")?;
    let mut input = BufReader::new(
        socket
            .try_clone()
            .map_err(|_| "cannot clone daemon socket")?,
    );
    let hello = hello_frame(&mut input)?;
    match hello["kind"].as_str() {
        Some("status") => {
            return send(
                &mut socket,
                json!({"kind":"status","pid":std::process::id(),"connections":sessions.connections()}),
            )
        }
        Some("stop") => {
            stop.store(true, Ordering::Relaxed);
            return send(&mut socket, json!({"kind":"stopping"}));
        }
        Some("hello") if hello["version"] == 1 && hello["credential"] == fingerprint(&config) => {}
        _ => return Err("daemon handshake refused".into()),
    }
    let id = hello["session"]
        .as_str()
        .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("invalid daemon session")?;
    let session = Arc::new(sessions.connect(id.to_owned()));
    socket
        .set_read_timeout(None)
        .map_err(|_| "cannot clear handshake deadline")?;
    send(&mut socket, json!({"kind":"ready","version":1}))?;
    let output: super::Output = Arc::new(Mutex::new(socket));
    let outcome = super::serve_connection(&config, &mut input, &output, session);
    // This private trailer is consumed by the stdio client, never sent as MCP.
    // It distinguishes clean stdin EOF from a daemon disappearing mid-call.
    send(
        &mut *output.lock().map_err(|_| "daemon output lock failed")?,
        json!({"kind":"end","ok":outcome.is_ok()}),
    )?;
    outcome
}
pub fn stop() -> Result<(), String> {
    let paths = Paths::load()?;
    paths.check_socket()?;
    let mut stream = UnixStream::connect(&paths.socket).map_err(|_| "cannot connect to daemon")?;
    stream
        .set_read_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound daemon stop")?;
    stream
        .set_write_timeout(Some(HANDSHAKE))
        .map_err(|_| "cannot bound daemon stop")?;
    send(&mut stream, json!({"kind":"stop"}))?;
    if frame(&mut BufReader::new(stream), 4096)?["kind"] != "stopping" {
        return Err("daemon stop refused".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
