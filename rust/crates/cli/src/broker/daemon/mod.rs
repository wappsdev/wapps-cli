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
    io::{BufRead, BufReader, Read},
    net::Shutdown,
    os::fd::AsRawFd,
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
const WRITE_FRAME: Duration = Duration::from_secs(2);
// One bounded cloud exchange (10 s) plus one complete output frame (2 s).
const DRAIN: Duration = Duration::from_secs(12);
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
                    // One bounded control-only handshake on the accept thread.
                    // The owned 0700 directory/0600 socket still authenticate the
                    // local UID; overflow never admits another MCP session or
                    // creates another worker. Slow hellos retain the total bound.
                    let _ = connection(
                        socket,
                        Arc::clone(&config),
                        Arc::clone(&sessions),
                        Arc::clone(&stop),
                        false,
                    );
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
                    let _ = connection(socket, config, sessions, stop, true);
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
    // Stop admitting first and wake reads so sessions cancel outstanding polls.
    // Never let slow output or queued workers turn graceful drain into an
    // unbounded join. An interrupted response means unknown outcome, not success.
    drop(listener);
    drain(connections);
    outcome
}
fn drain(mut connections: Vec<Connection>) {
    let deadline = Instant::now() + DRAIN;
    for conn in &connections {
        let _ = conn.socket.shutdown(Shutdown::Read);
    }
    while !connections.is_empty() {
        let mut index = 0;
        while index < connections.len() {
            if connections[index].worker.is_finished() {
                let _ = connections.swap_remove(index).worker.join();
            } else {
                index += 1;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            for conn in &connections {
                let _ = conn.socket.shutdown(Shutdown::Write);
                let _ = conn.socket.shutdown(Shutdown::Read);
            }
            // Do not join unfinished handles. Returning from the daemon command
            // exits the process, including any remaining bounded HTTP workers.
            break;
        }
        if !connections.is_empty() {
            thread::sleep(Duration::from_millis(10).min(remaining));
        }
    }
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
// O_NONBLOCK is shared by cloned descriptors. Keep input blocking at the
// protocol boundary with poll, while every kernel send itself stays nonblocking.
struct SocketInput {
    socket: UnixStream,
    deadline: Option<Instant>,
}
impl Read for SocketInput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.socket.read(buffer) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_socket(&self.socket, libc::POLLIN, self.deadline)?;
                }
                result => return result,
            }
        }
    }
}
fn wait_socket(
    socket: &UnixStream,
    events: libc::c_short,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    loop {
        let timeout = if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            remaining.as_millis().max(1).min(i32::MAX as u128) as i32
        } else {
            -1
        };
        let mut fd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: poll receives one initialized pollfd for this live socket.
        let ready = unsafe { libc::poll(&mut fd, 1, timeout) };
        if ready > 0 {
            return Ok(());
        }
        if ready == 0 {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
fn hello_frame(input: &mut BufReader<SocketInput>) -> Result<Value, String> {
    let deadline = Instant::now() + HANDSHAKE;
    let mut line = Vec::new();
    // A read timeout alone resets whenever a peer supplies another byte. Bound
    // the whole (small) hello, including peers that trickle data indefinitely.
    while line.len() < 4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("daemon handshake timed out".into());
        }
        input.get_mut().deadline = Some(deadline);
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
pub(in crate::broker) fn send(stream: &mut UnixStream, value: Value) -> Result<(), String> {
    let deadline = Instant::now() + WRITE_FRAME;
    let mut bytes = serde_json::to_vec(&value).map_err(|_| "cannot encode daemon frame")?;
    bytes.push(b'\n');
    let result = (|| {
        let mut remaining_bytes = bytes.as_slice();
        while !remaining_bytes.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("daemon frame write timed out");
            }
            // SO_SNDTIMEO and MSG_DONTWAIT alone did not bound a progressing
            // Darwin Unix-socket send. Accepted sockets also carry O_NONBLOCK;
            // SocketInput uses poll to preserve blocking protocol reads.
            // SAFETY: stream owns a live socket FD and the slice remains readable
            // for its exact length throughout send. No pointer is retained.
            let sent = unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    remaining_bytes.as_ptr().cast(),
                    remaining_bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent > 0 {
                remaining_bytes = &remaining_bytes[sent as usize..];
                continue;
            }
            if sent == 0 {
                return Err("cannot write daemon frame");
            }
            match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {}
                _ => return Err("cannot write daemon frame"),
            }
            wait_socket(stream, libc::POLLOUT, Some(deadline))
                .map_err(|_| "daemon frame write timed out")?;
        }
        Ok(())
    })();
    if result.is_err() {
        // No later reply or end trailer may follow a partial JSON frame. Closing
        // both halves also wakes the input loop and cancels its outstanding calls.
        let _ = stream.shutdown(Shutdown::Write);
        let _ = stream.shutdown(Shutdown::Read);
    }
    result.map_err(str::to_owned)
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
    admit_mcp: bool,
) -> Result<(), String> {
    // BSD accepts inherit nonblocking; Linux accepts do not. Set it explicitly
    // for writes on both. SocketInput supplies deadline-aware blocking reads.
    socket
        .set_nonblocking(true)
        .map_err(|_| "cannot configure accepted socket")?;
    let mut input = BufReader::new(SocketInput {
        socket: socket
            .try_clone()
            .map_err(|_| "cannot clone daemon socket")?,
        deadline: None,
    });
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
    if !admit_mcp {
        return Err("daemon client capacity reached".into());
    }
    let id = hello["session"]
        .as_str()
        .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("invalid daemon session")?;
    let session = Arc::new(sessions.connect(id.to_owned()));
    input.get_mut().deadline = None;
    send(&mut socket, json!({"kind":"ready","version":1}))?;
    let output: super::Output = Arc::new(Mutex::new(super::OutputWriter::new(socket)));
    let outcome = super::serve_connection(&config, &mut input, &output, session);
    // This private trailer is consumed by the stdio client, never sent as MCP.
    // It distinguishes clean stdin EOF from a daemon disappearing mid-call.
    output
        .lock()
        .map_err(|_| "daemon output lock failed")?
        .send(json!({"kind":"end","ok":outcome.is_ok()}))?;
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
