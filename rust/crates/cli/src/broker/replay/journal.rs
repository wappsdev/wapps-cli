//! Private durable journal, format wapps-broker-replay-journal-v1 (contract
//! section 6).
//!
//! The directory is reached through no-follow directory descriptors and must be
//! UID-owned with no group/other bits. A persistent `<name>.lock` inode holds an
//! exclusive nonblocking flock for the whole run. Every publication writes an
//! exclusive sibling temp file and syncs it; the first is linked without
//! overwriting any name, later ones rename only after the current bytes still
//! equal the bytes this writer last published; then the directory is synced.
//! Leftovers of a crash are retained, never swept or repaired. The checksum
//! detects corruption, not origin, consent or a coherent same-UID rollback.
use super::canonical::{encode, sha256_hex};
use super::plan::Kind;
use super::StopCode;
use ring::rand::{SecureRandom, SystemRandom};
use rustix::{
    fs::{
        fchmod, flock, fstat, fsync, linkat, openat, renameat, statat, unlinkat, AtFlags, FileType,
        FlockOperation, Mode, OFlags, CWD,
    },
    io::Errno,
    process::getuid,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};

pub(super) const FORMAT: &str = "wapps-broker-replay-journal-v1";

// Fields are declared in sorted key order: the file is canonical bytes.

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalDoc {
    pub(super) destination_bindings: Vec<DestinationBinding>,
    pub(super) entries: Vec<Entry>,
    pub(super) format: String,
    pub(super) manifest_sha256: String,
    pub(super) principal: String,
}

/// The destination receipt-history identity observed before the first send.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DestinationBinding {
    pub(super) history: String,
    pub(super) target_mission_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) destination_ids: Vec<String>,
    pub(super) kind: Kind,
    pub(super) operation_key: String,
    pub(super) project: String,
    /// Exact authority-free request bytes; absent until resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request_sha256: Option<String>,
    pub(super) snapshot_sha256: String,
    pub(super) source_ids: Vec<String>,
    pub(super) source_mission_id: String,
    pub(super) state: State,
    pub(super) target_mission_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Pending,
    InFlight,
    Acknowledged,
    Unresolved,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<J> {
    journal: J,
    sha256: String,
}

pub(super) struct Journal {
    dir: OwnedFd,
    _lock: OwnedFd,
    name: String,
    previous: Option<Vec<u8>>,
}

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn unsafe_path(_: Errno) -> StopCode {
    StopCode::JournalUnsafe
}

fn durability<E>(_: E) -> StopCode {
    StopCode::Durability
}

fn private(fd: &OwnedFd, directory: bool) -> Result<(), StopCode> {
    let stat = fstat(fd).map_err(unsafe_path)?;
    let expected = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let private = FileType::from_raw_mode(stat.st_mode as _) == expected
        && stat.st_uid == getuid().as_raw()
        && !Mode::from_raw_mode(stat.st_mode as _).intersects(Mode::RWXG | Mode::RWXO)
        && (directory || stat.st_nlink == 1);
    private.then_some(()).ok_or(StopCode::JournalUnsafe)
}

fn parse(bytes: &[u8]) -> Result<JournalDoc, StopCode> {
    let envelope: Envelope<JournalDoc> =
        serde_json::from_slice(bytes).map_err(|_| StopCode::JournalCorrupt)?;
    let mut canonical = encode(&envelope);
    canonical.push(b'\n');
    if canonical != bytes || envelope.sha256 != sha256_hex(&encode(&envelope.journal)) {
        return Err(StopCode::JournalCorrupt);
    }
    Ok(envelope.journal)
}

impl Journal {
    /// Start: lock a journal name that must not exist yet.
    pub(super) fn create(path: &Path) -> Result<Journal, StopCode> {
        let journal = Journal::lock(path)?;
        match statat(
            &journal.dir,
            journal.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Err(StopCode::JournalExists),
            Err(Errno::NOENT) => Ok(journal),
            Err(_) => Err(StopCode::JournalUnsafe),
        }
    }

    /// Resume: lock and read an existing journal; never creates or repairs one.
    pub(super) fn open(path: &Path) -> Result<(Journal, JournalDoc), StopCode> {
        let mut journal = Journal::lock(path)?;
        let bytes = journal.read()?;
        let doc = parse(&bytes)?;
        journal.previous = Some(bytes);
        Ok((journal, doc))
    }

    fn lock(path: &Path) -> Result<Journal, StopCode> {
        let name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) if path.is_absolute() && !name.starts_with('.') => name.to_owned(),
            _ => return Err(StopCode::JournalUnsafe),
        };
        let parent = path.parent().ok_or(StopCode::JournalUnsafe)?;
        let mut dir = openat(CWD, "/", DIRECTORY, Mode::empty()).map_err(unsafe_path)?;
        for component in parent.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(part) => {
                    dir = openat(&dir, part, DIRECTORY, Mode::empty()).map_err(unsafe_path)?;
                }
                _ => return Err(StopCode::JournalUnsafe),
            }
        }
        private(&dir, true)?;
        let lock_name = format!("{name}.lock");
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let created = openat(
            &dir,
            lock_name.as_str(),
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        );
        let lock = match created {
            Err(Errno::EXIST) => openat(&dir, lock_name.as_str(), flags, Mode::empty()),
            other => other,
        }
        .map_err(unsafe_path)?;
        private(&lock, false)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|e| match e {
            Errno::WOULDBLOCK => StopCode::JournalLocked,
            _ => StopCode::JournalUnsafe,
        })?;
        Ok(Journal {
            dir,
            _lock: lock,
            name,
            previous: None,
        })
    }

    fn read(&self) -> Result<Vec<u8>, StopCode> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd =
            openat(&self.dir, self.name.as_str(), flags, Mode::empty()).map_err(unsafe_path)?;
        private(&fd, false)?;
        let mut bytes = Vec::new();
        File::from(fd)
            .read_to_end(&mut bytes)
            .map_err(|_| StopCode::JournalUnsafe)?;
        Ok(bytes)
    }

    /// Durably publishes `doc`; on `Err` nothing may be sent on its strength.
    pub(super) fn save(&mut self, doc: &JournalDoc) -> Result<(), StopCode> {
        let mut bytes = encode(&Envelope {
            journal: doc,
            sha256: sha256_hex(&encode(doc)),
        });
        bytes.push(b'\n');
        private(&self.dir, true)?;
        let mut random = [0u8; 8];
        SystemRandom::new().fill(&mut random).map_err(durability)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temp = format!(".{}.{suffix}.tmp", self.name);
        let published = self.publish(&temp, &bytes);
        // Only this writer's own temp name; other leftovers are never touched.
        let _ = unlinkat(&self.dir, temp.as_str(), AtFlags::empty());
        published?;
        self.previous = Some(bytes);
        Ok(())
    }

    fn publish(&self, temp: &str, bytes: &[u8]) -> Result<(), StopCode> {
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW;
        let fd = openat(
            &self.dir,
            temp,
            flags | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(durability)?;
        fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(durability)?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(durability)?;
        fsync(&file).map_err(durability)?;
        let name = self.name.as_str();
        match &self.previous {
            None => {
                linkat(&self.dir, temp, &self.dir, name, AtFlags::empty()).map_err(
                    |e| match e {
                        Errno::EXIST => StopCode::JournalExists,
                        _ => StopCode::Durability,
                    },
                )?;
                unlinkat(&self.dir, temp, AtFlags::empty()).map_err(durability)?;
            }
            Some(previous) => {
                if &self.read()? != previous {
                    return Err(StopCode::JournalChanged);
                }
                renameat(&self.dir, temp, &self.dir, name).map_err(durability)?;
            }
        }
        fsync(&self.dir).map_err(durability)
    }
}
