//! Local enrollment is only the version-1 root registry consumed by 13.1.
//! It does not create a mission, install a harness, or invent a spawn-spec format.
use clap::{Arg, ArgMatches, Command};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

pub(super) fn command() -> Command {
    Command::new("project")
        .about("Owner project management; enrollment does not install harnesses")
        .subcommand(
            Command::new("enroll")
                .about("Enroll a canonical local root in the version-1 registry only")
                .arg(Arg::new("id"))
                .arg(Arg::new("root")),
        )
        .subcommand(
            Command::new("pause")
                .about("Unavailable until the execution pause contract lands")
                .arg(Arg::new("id")),
        )
        .subcommand(
            Command::new("unpause")
                .about("Unavailable until the execution pause contract lands")
                .arg(Arg::new("id")),
        )
        .subcommand(
            Command::new("role")
                .about("Project role management")
                .subcommand(
                    Command::new("apply")
                        .about("Unavailable until the local role spawn-spec contract lands")
                        .arg(Arg::new("id")),
                ),
        )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    projects: BTreeMap<String, Project>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    root: PathBuf,
}
struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub(super) fn run(args: &ArgMatches) -> Result<(), String> {
    let Some((name, args)) = args.subcommand() else {
        return Err("project command is required".into());
    };
    if name != "enroll" {
        return Err("action unavailable: pause/unpause require slice 13.3 execution enforcement; role apply requires its local spawn-spec contract (cloud role tools alone are insufficient); nothing changed".into());
    }
    let id = super::required(args, "id")?;
    if !valid_id(id) {
        return Err("invalid project id (self is reserved)".into());
    }
    let root = fs::canonicalize(super::required(args, "root")?)
        .map_err(|_| "cannot resolve project root")?;
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or("HOME is required")?;
    let home = fs::canonicalize(home).map_err(|_| "cannot resolve home")?;
    let state = home.join(".agent-broker");
    let config = home.join(".config/wapps-broker");
    let config = if config.exists() {
        fs::canonicalize(&config).map_err(|_| "cannot resolve broker config")?
    } else {
        config
    };
    // Reject before even creating the state directory. Never follow a state
    // symlink into a project or another enrollment, including a dangling link.
    match fs::symlink_metadata(&state) {
        Ok(meta) if !meta.is_dir() => return Err("enrollment home must be a real directory".into()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err("cannot inspect enrollment home".into())
        }
        _ => {}
    }
    check_root(&root, &state, &config)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|_| "cannot create enrollment home")?;
    let lock_path = state.join("projects.lock");
    let _file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|_| "enrollment is locked; inspect projects.lock before retrying")?;
    let _lock = Lock(lock_path);
    let path = state.join("projects.json");
    if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
        return Err("enrollment must be a regular file, not a symlink".into());
    }
    let mut registry = match fs::read(&path) {
        Ok(raw) => serde_json::from_slice::<Registry>(&raw).map_err(|_| "invalid enrollment")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Registry {
            version: 1,
            projects: BTreeMap::new(),
        },
        Err(_) => return Err("cannot read enrollment".into()),
    };
    if registry.version != 1 {
        return Err("invalid enrollment version".into());
    }
    let mut roots: Vec<PathBuf> = vec![];
    let mut already = false;
    for (key, project) in &registry.projects {
        if !valid_id(key) {
            return Err("invalid existing project id".into());
        }
        let existing = fs::canonicalize(state.join(&project.root))
            .map_err(|_| "cannot resolve existing enrolled root")?;
        check_root(&existing, &state, &config)?;
        if roots.iter().any(|other| overlaps(&existing, other)) {
            return Err("existing enrolled roots overlap".into());
        }
        if key == id {
            if existing != root {
                return Err("project id is already enrolled to another root".into());
            }
            already = true;
        } else if overlaps(&existing, &root) {
            return Err("enrolled roots must not overlap".into());
        }
        roots.push(existing);
    }
    if !already {
        registry.projects.insert(id.into(), Project { root });
        let bytes = serde_json::to_vec_pretty(&registry).map_err(|_| "cannot encode enrollment")?;
        crate::atomicfile::write(&path, &bytes, 0o600).map_err(|_| "cannot write enrollment")?;
    }
    println!("Local root enrolled. No mission, role, harness, or pause state was changed; installation is a separate slice.");
    Ok(())
}
fn valid_id(id: &str) -> bool {
    id != "self"
        && id.len() <= 64
        && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn check_root(root: &Path, state: &Path, config: &Path) -> Result<(), String> {
    if !root.is_dir() || overlaps(root, state) || overlaps(root, config) {
        Err("project root is not a directory or overlaps broker state/config".into())
    } else {
        Ok(())
    }
}
