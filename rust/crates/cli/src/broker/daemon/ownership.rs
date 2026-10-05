//! A permanent kernel lock serializes O_EXCL claims and stale-path recovery.
//! Records are diagnostic only: no PID from disk is ever probed or signalled.
use rustix::fs::{Mode, OFlags};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Paths {
    pub directory: PathBuf,
    pub socket: PathBuf,
}
impl Paths {
    pub fn load() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .filter(|s| !s.is_empty())
            .ok_or("HOME is required")?;
        Self::at(Path::new(&home))
    }
    pub fn at(home: &Path) -> Result<Self, String> {
        let state = home.join(".agent-broker");
        directory(&state, false)?;
        let directory_path = state.join("daemon");
        directory(&directory_path, true)?;
        Ok(Self {
            socket: directory_path.join("broker.sock"),
            directory: directory_path,
        })
    }
    pub fn check_socket(&self) -> Result<(), String> {
        let meta = fs::symlink_metadata(&self.socket).map_err(|_| "daemon socket is absent")?;
        if !meta.file_type().is_socket() || !owned(&meta) || meta.mode() & 0o777 != 0o600 {
            return Err("daemon socket must be owned and private".into());
        }
        Ok(())
    }
}
fn owned(meta: &Metadata) -> bool {
    meta.uid() == rustix::process::geteuid().as_raw()
}
fn directory(path: &Path, private: bool) -> Result<(), String> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("cannot create broker runtime directory".into()),
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "cannot inspect broker runtime directory")?;
    if !meta.is_dir()
        || !owned(&meta)
        || meta.mode() & 0o022 != 0
        || (private && meta.mode() & 0o777 != 0o700)
    {
        return Err("broker runtime directory must be owned, nonsymlink and private".into());
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<File, String> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "cannot open daemon lock")?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| "cannot inspect daemon lock")?;
    if !meta.is_file() || !owned(&meta) || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err("daemon lock must be an owned regular 0600 file".into());
    }
    Ok(file)
}

pub(super) struct Claim {
    // Never unlink this file: waiters must always lock the same inode.
    _lock: File,
    record: PathBuf,
    record_meta: Metadata,
    socket: PathBuf,
    socket_meta: Option<Metadata>,
}
impl Claim {
    pub fn acquire(paths: &Paths) -> Result<Self, String> {
        let lock = private_file(&paths.directory.join("lock"))?;
        lock.try_lock()
            .map_err(|_| "a broker daemon already owns this runtime")?;
        let record = paths.directory.join("owner.json");
        // Only a kernel-lock holder may recover even a completely empty O_EXCL record.
        match fs::symlink_metadata(&record) {
            Ok(meta) if meta.is_file() && owned(&meta) && meta.nlink() == 1 => {
                fs::remove_file(&record).map_err(|_| "cannot recover daemon record")?;
            }
            Ok(_) => return Err("unsafe daemon record".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("cannot inspect daemon record".into()),
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&record)
            .map_err(|_| "cannot claim daemon record")?;
        let record_meta = file
            .metadata()
            .map_err(|_| "cannot inspect daemon record")?;
        let claim = Self {
            _lock: lock,
            record,
            record_meta,
            socket: paths.socket.clone(),
            socket_meta: None,
        };
        serde_json::to_writer(&file, &serde_json::json!({"pid":std::process::id()}))
            .map_err(|_| "cannot write daemon record")?;
        match fs::symlink_metadata(&paths.socket) {
            Ok(meta) if meta.file_type().is_socket() && owned(&meta) => {
                fs::remove_file(&paths.socket).map_err(|_| "cannot recover stale socket")?;
            }
            Ok(_) => return Err("refusing to remove a non-socket daemon path".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("cannot inspect daemon socket".into()),
        }
        Ok(claim)
    }
    pub fn bound(&mut self) -> Result<(), String> {
        self.socket_meta =
            Some(fs::symlink_metadata(&self.socket).map_err(|_| "cannot inspect bound socket")?);
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot secure daemon socket".into())
    }
}
fn remove_same(path: &Path, expected: &Metadata) {
    if fs::symlink_metadata(path)
        .is_ok_and(|m| m.dev() == expected.dev() && m.ino() == expected.ino())
    {
        let _ = fs::remove_file(path);
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(meta) = &self.socket_meta {
            remove_same(&self.socket, meta);
        }
        remove_same(&self.record, &self.record_meta);
    }
}
