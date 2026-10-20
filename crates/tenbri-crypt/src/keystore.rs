//! The local data key store: one owner-only file per subject and key epoch, beside the stream's
//! signing keys and never under the stream; erasure overwrites and deletes them.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenbri_core::encoding::{format_ts, hex, unhex};
use tenbri_core::{Action, Entry, Kind, Principal};
use tenbri_keys::KeyStore;
use tenbri_store::{Put, Store};
use zeroize::{Zeroize, Zeroizing};

use crate::{DataKey, NONCE_LEN, address, blob_path, digest, digest_key, open, seal};

/// Why a body or digest could not be read or written.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The store holds no key for this subject (`None`: the tenant): erased, or never held here.
    NoKey(Option<String>),
    /// None of the subject's keys opens the blob at this address: the key that sealed it was
    /// erased (and a new one made since), or this is another stream's key store.
    WrongKey(Option<String>, String),
    /// The entry names a blob the stream does not hold.
    MissingBlob(String),
    /// The blob's bytes do not hash to the address that names them.
    Tampered(String),
}

fn who(subject: &Option<String>) -> String {
    match subject {
        Some(s) => format!("subject {s:?}"),
        None => "the tenant".into(),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NoKey(s) => write!(f, "no data key for {}: erased, or never held here", who(s)),
            Error::WrongKey(s, a) => write!(
                f,
                "no data key of {} opens {a}: the key that sealed it was erased, or this is another stream's key store",
                who(s)
            ),
            Error::MissingBlob(a) => write!(f, "the stream holds no blob {a}"),
            Error::Tampered(a) => write!(f, "the blob stored for {a} does not hash to it"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// One key epoch as stored: `<name>.<epoch>.json`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    stream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    epoch: u32,
    created: String,
    key: String,
}

/// A key epoch, without its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Epoch {
    pub epoch: u32,
    pub created: String,
}

/// The keys held for one subject (`None`: the tenant).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Held {
    pub subject: Option<String>,
    pub epochs: Vec<Epoch>,
}

/// The data keys of one stream: `<signing keys dir>/data/`, owner-only. A subject's data key seals
/// its bodies and, through HKDF, keys its input digests; entries without a subject use the
/// tenant's. Rotation adds a key epoch: new data uses it, old epochs keep opening old data until
/// erased.
///
/// ponytail: reads the key files on every call; cache them when a writer seals thousands of
/// bodies a second.
#[derive(Clone, Debug)]
pub struct DataKeys {
    dir: PathBuf,
    stream: String,
}

impl DataKeys {
    /// Opens (creating it, owner-only) the data key store beside `keys`, which [`KeyStore::open`]
    /// already keeps apart from the stream. Refuses a directory open to group or others.
    pub fn open(keys: &KeyStore) -> io::Result<DataKeys> {
        let dir = keys.dir().join("data");
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&dir)?;
        owner_only(&dir, true)?;
        Ok(DataKeys {
            dir,
            stream: keys.stream().to_owned(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every epoch of `subject`, oldest first, with its key.
    fn epochs(&self, subject: Option<&str>) -> Result<Vec<(Epoch, Zeroizing<DataKey>)>, Error> {
        let prefix = format!("{}.", name(subject));
        let mut out = vec![];
        for e in fs::read_dir(&self.dir)? {
            let e = e?;
            let file = e.file_name();
            let Some(f) = file.to_str() else { continue };
            if !(f.starts_with(&prefix) && f.ends_with(".json")) {
                continue;
            }
            let (s, epoch, key) = self.read(&e.path())?;
            if s.as_deref() != subject {
                return Err(corrupt(&e.path(), "holds another subject's key"));
            }
            out.push((epoch, key));
        }
        out.sort_by_key(|(e, _)| e.epoch);
        Ok(out)
    }

    fn read(&self, path: &Path) -> Result<(Option<String>, Epoch, Zeroizing<DataKey>), Error> {
        owner_only(path, false)?;
        let mut s: Stored = serde_json::from_slice(&Zeroizing::new(fs::read(path)?))
            .map_err(|e| corrupt(path, &e.to_string()))?;
        let key = unhex::<32>(&s.key).map(Zeroizing::new);
        s.key.zeroize();
        let key = key.ok_or_else(|| corrupt(path, "the key is not 64 hex digits"))?;
        if s.stream != self.stream {
            return Err(corrupt(path, "belongs to another stream"));
        }
        let epoch = Epoch {
            epoch: s.epoch,
            created: s.created,
        };
        Ok((s.subject, epoch, key))
    }

    /// Writes epoch `epoch` of `subject` with a new random key; `false` if it already exists.
    fn create(&self, subject: Option<&str>, epoch: u32) -> Result<bool, Error> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|e| io::Error::other(e.to_string()))?;
        let mut stored = Stored {
            stream: self.stream.clone(),
            subject: subject.map(str::to_owned),
            epoch,
            created: format_ts(now_ms()),
            key: hex(key.as_ref()),
        };
        let json = Zeroizing::new(serde_json::to_vec_pretty(&stored).map_err(io::Error::other)?);
        stored.key.zeroize();
        // A synced temporary file linked to its name, which fails if the name exists: a crash
        // never leaves a partial key file in the way.
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).map_err(|e| io::Error::other(e.to_string()))?;
        let tmp = self.dir.join(format!(".tmp-{}", hex(&rand)));
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        let written = f.write_all(&json).and_then(|_| f.sync_all());
        drop(f);
        let linked = written.and_then(|_| {
            fs::hard_link(
                &tmp,
                self.dir.join(format!("{}.{epoch}.json", name(subject))),
            )
        });
        fs::remove_file(&tmp)?;
        match linked {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            r => r?,
        }
        sync_dir(&self.dir)?;
        Ok(true)
    }

    /// The newest key of `subject`, made (epoch 1) if it has none.
    fn current(&self, subject: Option<&str>) -> Result<Zeroizing<DataKey>, Error> {
        check_subject(subject)?;
        loop {
            if let Some((_, k)) = self.epochs(subject)?.pop() {
                return Ok(k);
            }
            // Another writer may create it first; then read theirs.
            self.create(subject, 1)?;
        }
    }

    /// The digest of an input's `content` for an entry about `subject`, under its newest key.
    pub fn digest(&self, subject: Option<&str>, content: &[u8]) -> Result<String, Error> {
        let key = self.current(subject)?;
        Ok(digest(&key, content))
    }

    /// Whether `digest` is the digest of `content` under any of `subject`'s key epochs.
    pub fn confirm(&self, subject: Option<&str>, content: &[u8], d: &str) -> Result<bool, Error> {
        let epochs = self.epochs(subject)?;
        if epochs.is_empty() {
            return Err(Error::NoKey(subject.map(str::to_owned)));
        }
        Ok(epochs.iter().any(|(_, k)| digest(k, content) == d))
    }

    /// Seals `body` under `subject`'s newest key, stores it in `store` and returns its address,
    /// for the entry's `body`.
    pub async fn seal_body<S: Store>(
        &self,
        store: &S,
        subject: Option<&str>,
        body: &[u8],
    ) -> Result<String, Error> {
        let key = self.current(subject)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
        let blob = seal(&key, &self.stream, &nonce, body);
        let addr = address(&blob);
        let path = blob_path(&addr).expect("an address made by address()");
        if store.put_if_absent(&path, &blob).await? == Put::Exists {
            // Content-addressed: whatever is there must be these bytes.
            let there = store.get(&path).await?;
            if there.is_none_or(|o| o.bytes != blob) {
                return Err(Error::Tampered(addr));
            }
        }
        Ok(addr)
    }

    /// The plaintext body of `entry`, if it has one: its blob read from `store`, checked against
    /// its address, and opened with a key of the entry's subject.
    pub async fn open_body<S: Store>(
        &self,
        store: &S,
        entry: &Entry,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let Some(addr) = &entry.body else {
            return Ok(None);
        };
        let path = blob_path(addr).ok_or_else(|| Error::Tampered(addr.clone()))?;
        let blob = store
            .get(&path)
            .await?
            .ok_or_else(|| Error::MissingBlob(addr.clone()))?
            .bytes;
        if address(&blob) != *addr {
            return Err(Error::Tampered(addr.clone()));
        }
        let subject = entry.subject.as_deref();
        let epochs = self.epochs(subject)?;
        if epochs.is_empty() {
            return Err(Error::NoKey(subject.map(str::to_owned)));
        }
        epochs
            .iter()
            .find_map(|(_, k)| open(k, &entry.stream, &blob))
            .map(Some)
            .ok_or_else(|| Error::WrongKey(subject.map(str::to_owned), addr.clone()))
    }

    /// Starts a new key epoch for `subject` and returns its number; new bodies and digests use it.
    pub fn rotate(&self, subject: Option<&str>) -> Result<u32, Error> {
        check_subject(subject)?;
        loop {
            let next = self.epochs(subject)?.last().map_or(1, |(e, _)| e.epoch + 1);
            if self.create(subject, next)? {
                return Ok(next);
            }
        }
    }

    /// Erases every key epoch of `subject`: each file is overwritten with zeros, synced and
    /// deleted. Returns how many there were. On copy-on-write disks, with snapshots or backups,
    /// old copies may survive the overwrite (spec/privacy.md, section 5).
    pub fn erase(&self, subject: Option<&str>) -> Result<usize, Error> {
        check_subject(subject)?;
        let prefix = format!("{}.", name(subject));
        let mut n = 0;
        for e in fs::read_dir(&self.dir)? {
            let e = e?;
            let file = e.file_name();
            if !file
                .to_str()
                .is_some_and(|f| f.starts_with(&prefix) && f.ends_with(".json"))
            {
                continue;
            }
            let path = e.path();
            let len = fs::symlink_metadata(&path)?.len();
            let mut f = fs::OpenOptions::new().write(true).open(&path)?;
            f.write_all(&vec![0u8; len as usize])?;
            f.sync_all()?;
            drop(f);
            fs::remove_file(&path)?;
            n += 1;
        }
        sync_dir(&self.dir)?;
        Ok(n)
    }

    /// Every subject (and the tenant) with keys here, and their epochs.
    pub fn list(&self) -> Result<Vec<Held>, Error> {
        let mut out: Vec<Held> = vec![];
        for e in fs::read_dir(&self.dir)? {
            let path = e?.path();
            if path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let (subject, epoch, _) = self.read(&path)?;
            match out.iter_mut().find(|h| h.subject == subject) {
                Some(h) => h.epochs.push(epoch),
                None => out.push(Held {
                    subject,
                    epochs: vec![epoch],
                }),
            }
        }
        for h in &mut out {
            h.epochs.sort_by_key(|e| e.epoch);
        }
        out.sort_by(|a, b| a.subject.cmp(&b.subject));
        Ok(out)
    }

    /// `subject`'s keys as JSON, for a backup kept apart from the log: `{stream, subject, epochs:
    /// [{epoch, created, key}]}`. With `digest_only`, each epoch's digest key instead of its data
    /// key: enough for an auditor to confirm the subject's input digests, never to open a body.
    pub fn export(
        &self,
        subject: Option<&str>,
        digest_only: bool,
    ) -> Result<Zeroizing<String>, Error> {
        let epochs = self.epochs(subject)?;
        if epochs.is_empty() {
            return Err(Error::NoKey(subject.map(str::to_owned)));
        }
        let field = if digest_only { "digest_key" } else { "key" };
        let list: Vec<serde_json::Value> = epochs
            .iter()
            .map(|(e, k)| {
                let k = if digest_only {
                    digest_key(k)
                } else {
                    k.clone()
                };
                serde_json::json!({"epoch": e.epoch, "created": e.created, field: hex(k.as_ref())})
            })
            .collect();
        let json = serde_json::json!({"stream": self.stream, "subject": subject, "epochs": list});
        Ok(Zeroizing::new(
            serde_json::to_string_pretty(&json).map_err(io::Error::other)?,
        ))
    }
}

/// The draft of the note recording an erasure: `subject` set to the handle (absent for the
/// tenant), `action` `{type: "tenbri.erase", target: reason}`, `principal` who asked for it.
pub fn erasure_note(subject: Option<&str>, reason: &str, by: Option<Principal>) -> Entry {
    note(subject, "tenbri.erase", reason.to_owned(), by)
}

/// The draft of the note recording a new key epoch: `action` `{type: "tenbri.key_epoch", target:
/// "epoch:<n>"}`.
pub fn epoch_note(subject: Option<&str>, epoch: u32, by: Option<Principal>) -> Entry {
    note(subject, "tenbri.key_epoch", format!("epoch:{epoch}"), by)
}

fn note(subject: Option<&str>, kind: &str, target: String, by: Option<Principal>) -> Entry {
    Entry {
        subject: subject.map(str::to_owned),
        principal: by,
        action: Some(Action {
            r#type: kind.into(),
            target: Some(target),
        }),
        ..Entry::new(Kind::Note)
    }
}

/// The file name stem of a subject's keys: `tenant`, or `s-` and the hex SHA-256 of the handle,
/// so any handle makes a safe file name.
fn name(subject: Option<&str>) -> String {
    match subject {
        None => "tenant".into(),
        Some(s) => format!("s-{}", hex(&Sha256::digest(s.as_bytes()))),
    }
}

fn check_subject(subject: Option<&str>) -> io::Result<()> {
    if subject == Some("") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a subject handle is never empty",
        ));
    }
    Ok(())
}

fn corrupt(path: &Path, why: &str) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {why}", path.display()),
    ))
}

/// Refuses a symlink, and on Unix anything open to group or others: data keys are owner-only.
fn owner_only(path: &Path, dir: bool) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if (dir && !m.is_dir()) || (!dir && !m.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not a plain {}",
                path.display(),
                if dir { "directory" } else { "file" }
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is open to group or others (mode {mode:03o}); data keys must be owner-only: chmod {} it",
                    path.display(),
                    if dir { "700" } else { "600" }
                ),
            ));
        }
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}
