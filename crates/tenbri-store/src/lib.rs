//! Tenbri store trait (get, put-if-absent, compare-and-swap) for local disk and object stores.
//!
//! A [`Store`] holds one stream's objects by key (`HEAD`, `batches/000000000001.jsonl`). The
//! writer fences itself with [`Store::put_if_absent`] and advances HEAD with
//! [`Store::compare_and_swap`]; nothing else needs to be atomic. [`LocalStore`] keeps a stream in
//! a directory; with the `s3` feature, [`Bucket`] keeps it under a prefix of an S3, R2 or MinIO
//! bucket with conditional writes, and [`open`] picks one from a location string.

#[cfg(feature = "s3")]
mod bucket;
#[cfg(feature = "s3")]
pub use bucket::Bucket;
#[cfg(feature = "s3")]
pub use object_store;

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs, process};

use sha2::{Digest, Sha256};

/// An object's bytes and its version: an opaque token for [`Store::compare_and_swap`] (an ETag on
/// object stores, a content hash on local disk).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub bytes: Vec<u8>,
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version(pub String);

/// What [`Store::put_if_absent`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    Created,
    /// Something is already stored under that key; nothing was written.
    Exists,
}

/// What [`Store::compare_and_swap`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Swap {
    Swapped(Version),
    /// The object was not at the expected version; nothing was written.
    Mismatch,
}

/// A listed object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub key: String,
    pub modified: SystemTime,
}

/// One stream's objects. Every write is durable when its future resolves.
pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> impl Future<Output = io::Result<Option<Object>>> + Send;
    /// Writes `bytes` under `key` only if nothing is there; atomic, never a partial object.
    fn put_if_absent(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> impl Future<Output = io::Result<Put>> + Send;
    /// Replaces `key` only if it is at `expected` (`None`: only if absent).
    fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> impl Future<Output = io::Result<Swap>> + Send;
    /// Objects whose key starts with `prefix` (a directory such as `batches/`).
    fn list(&self, prefix: &str) -> impl Future<Output = io::Result<Vec<Listed>>> + Send;
    fn delete(&self, key: &str) -> impl Future<Output = io::Result<()>> + Send;
}

/// A stream in a directory on a local disk (APFS, ext4, XFS, NTFS; not NFS or SMB).
///
/// - put-if-absent: a temporary file in the same directory, synced, then hard-linked to its name,
///   which fails if the name exists, then a sync of the directory. A crash leaves at most a
///   temporary file (`.tmp-…`), never a partial object.
/// - compare-and-swap: under an exclusive lock on `.lock` (`flock`, `LockFileEx`), released by
///   the OS if the process dies; a temporary file, synced, renamed over the old one, directory
///   synced.
/// - Files are synced with `fsync` (`F_FULLFSYNC` on macOS, which Rust's `sync_all` uses).
///
/// ponytail: the I/O is blocking inside `async fn`s; fine for a local disk and a CLI, move it to
/// `spawn_blocking` when one runtime serves many lanes.
#[derive(Clone, Debug)]
pub struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    /// A store over the directory `root`, which must exist.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<LocalStore> {
        let root = root.into();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is not a directory", root.display()),
            ));
        }
        Ok(LocalStore { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> io::Result<PathBuf> {
        check_key(key)?;
        Ok(self.root.join(key))
    }

    fn get_sync(&self, key: &str) -> io::Result<Option<Object>> {
        match fs::read(self.path(key)?) {
            Ok(bytes) => Ok(Some(Object {
                version: version(&bytes),
                bytes,
            })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put_sync(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        let path = self.path(key)?;
        let dir = path.parent().expect("a key has a parent").to_owned();
        fs::create_dir_all(&dir)?;
        let tmp = write_tmp(&dir, bytes)?;
        let linked = fs::hard_link(&tmp, &path);
        fs::remove_file(&tmp)?;
        match linked {
            Ok(()) => {
                sync_dir(&dir)?;
                Ok(Put::Created)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Put::Exists),
            Err(e) => Err(e),
        }
    }

    fn cas_sync(&self, key: &str, expected: Option<&Version>, bytes: &[u8]) -> io::Result<Swap> {
        let path = self.path(key)?;
        let dir = path.parent().expect("a key has a parent").to_owned();
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join(".lock"))?;
        // Fully qualified: newer Rust has an inherent File::lock with the same meaning.
        fs4::FileExt::lock(&lock)?;
        let current = self.get_sync(key)?.map(|o| o.version);
        if current.as_ref() != expected {
            return Ok(Swap::Mismatch);
        }
        let tmp = write_tmp(&dir, bytes)?;
        fs::rename(&tmp, &path)?;
        sync_dir(&dir)?;
        Ok(Swap::Swapped(version(bytes)))
        // The lock is released when `lock` is dropped (closed).
    }

    fn list_sync(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        let prefix = prefix.trim_end_matches('/');
        let dir = self.path(prefix)?;
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut out = vec![];
        for e in entries {
            let e = e?;
            if e.file_type()?.is_file() {
                out.push(Listed {
                    key: format!("{prefix}/{}", e.file_name().to_string_lossy()),
                    modified: e.metadata()?.modified()?,
                });
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    fn delete_sync(&self, key: &str) -> io::Result<()> {
        let path = self.path(key)?;
        match fs::remove_file(&path) {
            Ok(()) => sync_dir(path.parent().expect("a key has a parent")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Store for LocalStore {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        self.get_sync(key)
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        self.put_sync(key, bytes)
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        self.cas_sync(key, expected, bytes)
    }
    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        self.list_sync(prefix)
    }
    async fn delete(&self, key: &str) -> io::Result<()> {
        self.delete_sync(key)
    }
}

/// A key is `/`-separated names, none empty, `.`, `..` or holding a backslash.
fn check_key(key: &str) -> io::Result<()> {
    let ok = !key.is_empty()
        && key
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && !p.contains('\\'));
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad key {key:?}"),
        ));
    }
    Ok(())
}

/// A stream's store, chosen at run time: a local directory or, with the `s3` feature, a bucket.
#[derive(Clone, Debug)]
pub enum AnyStore {
    Local(LocalStore),
    #[cfg(feature = "s3")]
    Bucket(Bucket),
}

/// Opens the store at `location`: `s3://bucket/prefix`, `r2://bucket/prefix` (and, with the
/// `experimental` feature, `gs://` and `az://`) as a [`Bucket`], running its canary; anything
/// else as a local directory, which must exist.
pub async fn open(location: &str) -> io::Result<AnyStore> {
    if is_url(location) {
        #[cfg(feature = "s3")]
        return Ok(AnyStore::Bucket(Bucket::open(location).await?));
        #[cfg(not(feature = "s3"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{location}: object stores need tenbri-store's `s3` feature"),
        ));
    }
    LocalStore::open(location).map(AnyStore::Local)
}

/// Is `location` an object-store URL rather than a local path?
pub fn is_url(location: &str) -> bool {
    location.contains("://")
}

macro_rules! each {
    ($s:expr, $x:ident => $e:expr) => {
        match $s {
            AnyStore::Local($x) => $e,
            #[cfg(feature = "s3")]
            AnyStore::Bucket($x) => $e,
        }
    };
}

impl Store for AnyStore {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        each!(self, s => s.get(key).await)
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        each!(self, s => s.put_if_absent(key, bytes).await)
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        each!(self, s => s.compare_and_swap(key, expected, bytes).await)
    }
    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        each!(self, s => s.list(prefix).await)
    }
    async fn delete(&self, key: &str) -> io::Result<()> {
        each!(self, s => s.delete(key).await)
    }
}

/// A local version: the SHA-256 of the content.
fn version(bytes: &[u8]) -> Version {
    let h = Sha256::digest(bytes);
    Version(h.iter().map(|b| format!("{b:02x}")).collect())
}

/// Is `name` a temporary file of an interrupted write?
pub fn is_temporary(key: &str) -> bool {
    key.rsplit('/')
        .next()
        .is_some_and(|n| n.starts_with(".tmp-"))
}

fn write_tmp(dir: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!(
        ".tmp-{}-{nanos}-{}",
        process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(tmp)
}

/// Makes a directory's entries durable. Windows has no directory handle to sync; NTFS journals
/// its metadata.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: Future>(f: F) -> F::Output {
        // The local store never awaits anything, so one poll finishes it.
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => unreachable!(),
        }
    }

    #[test]
    fn put_if_absent_and_compare_and_swap() {
        let dir = std::env::temp_dir().join(format!("tenbri-store-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let s = LocalStore::open(&dir).unwrap();
        assert_eq!(
            block_on(s.put_if_absent("batches/1.jsonl", b"a")).unwrap(),
            Put::Created
        );
        assert_eq!(
            block_on(s.put_if_absent("batches/1.jsonl", b"b")).unwrap(),
            Put::Exists
        );
        assert_eq!(
            block_on(s.get("batches/1.jsonl")).unwrap().unwrap().bytes,
            b"a"
        );
        assert!(block_on(s.get("../x")).is_err());

        let Swap::Swapped(v1) = block_on(s.compare_and_swap("HEAD", None, b"1")).unwrap() else {
            panic!()
        };
        assert_eq!(
            block_on(s.compare_and_swap("HEAD", None, b"x")).unwrap(),
            Swap::Mismatch
        );
        assert!(matches!(
            block_on(s.compare_and_swap("HEAD", Some(&v1), b"2")).unwrap(),
            Swap::Swapped(_)
        ));
        assert_eq!(
            block_on(s.compare_and_swap("HEAD", Some(&v1), b"3")).unwrap(),
            Swap::Mismatch
        );
        assert_eq!(block_on(s.get("HEAD")).unwrap().unwrap().bytes, b"2");

        let listed = block_on(s.list("batches/")).unwrap();
        assert_eq!(
            listed.iter().map(|l| l.key.as_str()).collect::<Vec<_>>(),
            ["batches/1.jsonl"]
        );
        block_on(s.delete("batches/1.jsonl")).unwrap();
        assert!(block_on(s.get("batches/1.jsonl")).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
