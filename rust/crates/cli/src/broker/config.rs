//! Machine enrollment and an in-memory, file-only Access credential.
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::{SocketAddr, ToSocketAddrs},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    projects: BTreeMap<String, Project>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    root: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Client {
    client_id: String,
    #[serde(default = "endpoint")]
    endpoint: String,
}
fn endpoint() -> String {
    "https://broker.meapps.dev".into()
}

// No Debug, environment export, command invocation, or diagnostic containing values.
pub(super) struct Config {
    pub endpoint: url::Url,
    pub client_id: String,
    pub secret: String,
    pub addresses: Vec<SocketAddr>,
}
impl Config {
    pub fn load() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or("HOME is required")?;
        let home = Path::new(&home);
        let state = home.join(".agent-broker");
        let config = home.join(".config/wapps-broker");
        let cwd = std::env::current_dir()
            .and_then(fs::canonicalize)
            .map_err(|_| "cannot resolve cwd")?;
        let enrolled: Enrollment = serde_json::from_slice(
            &fs::read(state.join("projects.json")).map_err(|_| "cannot read enrollment")?,
        )
        .map_err(|_| "invalid enrollment")?;
        if enrolled.version != 1 {
            return Err("invalid enrollment version".into());
        }
        let state = fs::canonicalize(&state).map_err(|_| "cannot resolve enrollment home")?;
        let config = fs::canonicalize(&config).map_err(|_| "cannot resolve broker config home")?;
        let mut roots: Vec<PathBuf> = Vec::new();
        for (id, project) in enrolled.projects {
            if id == "self"
                || id.len() > 64
                || !id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err("invalid enrollment project id".into());
            }
            let root =
                fs::canonicalize(state.join(project.root)).map_err(|_| "invalid enrolled root")?;
            if !root.is_dir()
                || overlaps(&root, &state)
                || overlaps(&root, &config)
                || roots.iter().any(|other| overlaps(&root, other))
            {
                return Err("enrolled roots overlap or are not directories".into());
            }
            roots.push(root);
        }
        if !roots.iter().any(|root| cwd.starts_with(root)) {
            return Err("cwd is not enrolled".into());
        }
        let client_path = config.join("client.yaml");
        let real_client =
            fs::canonicalize(&client_path).map_err(|_| "cannot read client metadata")?;
        if roots.iter().any(|root| real_client.starts_with(root)) {
            return Err("client metadata is inside an enrolled root".into());
        }
        let client: Client = serde_yaml_ng::from_slice(
            &fs::read(client_path).map_err(|_| "cannot read client metadata")?,
        )
        .map_err(|_| "invalid client metadata")?;
        if !header_value(&client.client_id) {
            return Err("invalid client id".into());
        }
        let endpoint = url::Url::parse(&client.endpoint).map_err(|_| "invalid broker endpoint")?;
        let loopback = matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"));
        if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err("broker endpoint must be an HTTPS origin (HTTP only on loopback)".into());
        }
        let secret_path = config.join("agents.secret");
        let fd = rustix::fs::open(
            &secret_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "cannot open agents.secret")?;
        let file = fs::File::from(fd);
        let meta = file
            .metadata()
            .map_err(|_| "cannot inspect agents.secret")?;
        if !meta.is_file()
            || meta.mode() & 0o7777 != 0o600
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.nlink() != 1
        {
            return Err("agents.secret must be an owned, unlinked-to, regular 0600 file".into());
        }
        let mut secret = String::new();
        file.take(4097)
            .read_to_string(&mut secret)
            .map_err(|_| "cannot read agents.secret")?;
        if secret.len() > 4096 {
            return Err("agents.secret exceeds 4096 bytes".into());
        }
        let secret = secret.trim_end_matches(['\r', '\n']).to_owned();
        if !header_value(&secret) {
            return Err("invalid agents.secret".into());
        }
        // ureq 2's request deadline does not bound libc DNS. Resolve once at
        // startup, before serving calls, and keep these addresses for this
        // bridge's lifetime. TLS still authenticates the configured hostname.
        let host = endpoint
            .host_str()
            .expect("validated host")
            .trim_matches(['[', ']'])
            .to_owned();
        let port = endpoint.port_or_known_default().expect("HTTP origin");
        let addresses = resolve_with(
            move || {
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(Iterator::collect)
            },
            Duration::from_secs(10),
        )?;
        Ok(Self {
            endpoint,
            client_id: client.client_id,
            secret,
            addresses,
        })
    }
}
fn resolve_with(
    resolve: impl FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, String> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(resolve());
    });
    let addresses = receiver
        .recv_timeout(timeout)
        .map_err(|_| "broker DNS timed out")?
        .map_err(|_| "cannot resolve broker endpoint")?;
    if addresses.is_empty() {
        return Err("broker endpoint has no addresses".into());
    }
    Ok(addresses)
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn header_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| (33..=126).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

    // A hung test fails; this is not an assertion about scheduler latency.
    const WATCHDOG: Duration = Duration::from_secs(5);

    struct StalledResolver {
        release: Sender<()>,
        completed: Receiver<()>,
    }
    impl Drop for StalledResolver {
        fn drop(&mut self) {
            // Release the resolver even during assertion unwinding.
            let _ = self.release.send(());
            let completed = self.completed.recv_timeout(WATCHDOG);
            if !std::thread::panicking() {
                completed.expect("stalled resolver did not complete after release");
            }
        }
    }

    #[test]
    fn stalled_dns_is_bounded_before_any_mcp_call() {
        std::thread::scope(|scope| {
            let (release, wait_for_release) = mpsc::channel();
            let (started, wait_for_start) = mpsc::channel();
            let (completed, wait_for_completion) = mpsc::channel();
            let (returned, wait_for_return) = mpsc::channel();
            let stalled = StalledResolver {
                release,
                completed: wait_for_completion,
            };
            // The scoped caller is joined even if a test assertion panics.
            let caller = scope.spawn(move || {
                let result = resolve_with(
                    move || {
                        let _ = started.send(());
                        let _ = wait_for_release.recv();
                        let _ = completed.send(());
                        Ok(vec![SocketAddr::from(([127, 0, 0, 1], 443))])
                    },
                    Duration::from_millis(20),
                );
                let _ = returned.send(result);
            });
            wait_for_start
                .recv_timeout(WATCHDOG)
                .expect("resolver did not start");
            let result = wait_for_return
                .recv_timeout(WATCHDOG)
                .expect("DNS timeout waited for the stalled resolver");
            assert_eq!(result, Err("broker DNS timed out".into()));
            // The timeout must return before the resolver is allowed to finish.
            assert_eq!(stalled.completed.try_recv(), Err(TryRecvError::Empty));
            drop(stalled);
            caller.join().expect("DNS caller panicked");
        });
    }

    #[test]
    fn successful_dns_preserves_resolved_addresses() {
        let addresses = vec![
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([127, 0, 0, 2], 443)),
        ];
        let expected = addresses.clone();
        assert_eq!(resolve_with(move || Ok(addresses), WATCHDOG), Ok(expected));
    }

    #[test]
    fn failed_dns_reports_resolution_error() {
        assert_eq!(
            resolve_with(
                || Err(std::io::Error::other("synthetic resolver failure")),
                WATCHDOG,
            ),
            Err("cannot resolve broker endpoint".into()),
        );
    }

    #[test]
    fn empty_dns_rejects_missing_addresses() {
        assert_eq!(
            resolve_with(|| Ok(Vec::new()), WATCHDOG),
            Err("broker endpoint has no addresses".into()),
        );
    }
}
