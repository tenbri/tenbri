//! The checkpoints a writer makes (spec/checkpoints.md), and the floor it will not open below.

use std::io;
use std::path::PathBuf;
use std::time::Instant;

use tenbri_core::sign::SigningKey;
use tenbri_core::{Broken, Chain, Code, Error};
use tenbri_keys::Key;
use tenbri_merkle::{Checkpoint, Hash, Note, checkpoint};
use tenbri_store::Store;

use crate::{Commit, Hook, WriteError, Writer, signer};

/// The file name `tenbri` and tenbrid keep the latest checkpoint under, in the stream's key
/// directory.
pub const CHECKPOINT_FILE: &str = "checkpoint.note";

/// A [`Hook`] that writes a signed checkpoint, `checkpoints/<size>.note`, every
/// [`checkpoint::EVERY_ENTRIES`] entries or [`checkpoint::EVERY_MS`], whichever comes first, and
/// keeps a copy of the latest one outside the store: the floor the next writer checks HEAD
/// against. Made by [`Writer::with_checkpoints`].
#[derive(Debug)]
pub struct Checkpoints {
    /// The size of the last checkpoint written or found.
    size: u64,
    since: Instant,
    local: Option<PathBuf>,
    /// The stream's checkpoint key, which signs every checkpoint after the session key.
    key: Option<SigningKey>,
}

impl Checkpoints {
    /// The size of the last checkpoint written or found, 0 if none.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Checkpoints {
    /// Signs and stores the checkpoint of the whole stream, and keeps it at `local`.
    async fn write<S: Store>(&mut self, store: &S, c: &Commit<'_>, key: &Key) -> io::Result<()> {
        let size = c.hashes.len() as u64;
        let cp = Checkpoint::new(&c.head.stream, c.hashes);
        let note = match &self.key {
            Some(k) => cp.sign_with(&[&key.signing, k]),
            None => cp.sign(&key.signing),
        };
        // Exists: another writer checkpointed the same entries.
        store.put_if_absent(&checkpoint::key(size), &note).await?;
        if let Some(p) = &self.local {
            keep(p, &note)?;
        }
        (self.size, self.since) = (size, Instant::now());
        Ok(())
    }
}

impl<S: Store> Hook<S> for Checkpoints {
    async fn committed(&mut self, store: &S, c: Commit<'_>) {
        let Some(key) = c.signer else { return };
        let size = c.hashes.len() as u64;
        let ms = self.since.elapsed().as_millis() as u64;
        if checkpoint::due(size.saturating_sub(self.size), ms) {
            // On an error the next commit tries again; the entries are durable whatever happens.
            let _ = self.write(store, &c, key).await;
        }
    }

    async fn seal(&mut self, store: &S, c: Commit<'_>) {
        if let Some(key) = c.signer.filter(|_| c.hashes.len() as u64 > self.size) {
            let _ = self.write(store, &c, key).await;
        }
    }
}

impl<S: Store> Writer<S, Checkpoints> {
    /// Signs and stores a checkpoint of the whole stream now, unless the latest one already
    /// covers it (`tenbri checkpoint`). Returns its size.
    pub async fn checkpoint(&mut self) -> Result<u64, WriteError> {
        let size = self.hashes.len() as u64;
        if self.hook.size == size {
            return Ok(size);
        }
        let key = signer(&self.chain, self.session.as_ref(), self.clock.now_ms())
            .ok_or_else(|| WriteError::NoSession("no session key may sign a checkpoint".into()))?;
        let c = Commit {
            head: &self.head,
            first: self.head.seq + 1,
            hashes: &self.hashes,
            signer: Some(key),
        };
        self.hook.write(&self.store, &c, key).await?;
        Ok(size)
    }
}

#[cfg(feature = "witness")]
impl<S: Store> Writer<S, Checkpoints> {
    /// Signs every checkpoint with `key`, the stream's checkpoint key, too: the one key witnesses
    /// verify checkpoints with (spec/checkpoints.md, section 6). If the stream's checkpoint key
    /// is another one, or none, first certifies `key` in the `ext` of a new session key's
    /// certificate, signed by the stream key from the key store [`Writer::use_keys`] set.
    pub async fn use_checkpoint_key(&mut self, key: SigningKey) -> Result<(), WriteError> {
        use tenbri_merkle::witness;
        let mut r = crate::Reader::new(&self.store, self.pin.as_deref());
        let entries = r.poll().await?;
        if witness::checkpoint_key(&entries, u64::MAX) != Some(key.verifying_key()) {
            let keys = self.keys.clone().ok_or_else(|| {
                WriteError::NoSession("no key store to certify the checkpoint key from".into())
            })?;
            let stream_key = self.load_stream_key(&keys)?;
            let session = tenbri_keys::Key::new_session(
                self.clock.now_ms(),
                tenbri_keys::SESSION_LIFETIME_MS,
            )?;
            let backend = keys
                .list()?
                .into_iter()
                .find(|m| m.id == stream_key.id)
                .map_or(tenbri_keys::Backend::File, |m| m.backend);
            keys.save(&session, backend)?;
            let mut e = tenbri_keys::certify(&session);
            e.ext = Some(witness::ext(&key.verifying_key()));
            self.write(e, &stream_key, &session).await?;
            self.session = Some(session);
        }
        self.hook.key = Some(key);
        Ok(())
    }
}

impl<S: Store, H> Writer<S, H> {
    /// The same writer, writing checkpoints from now on (see [`Checkpoints`]), keeping the latest
    /// at `local`, a file outside the store (the stream's key directory, say).
    ///
    /// The HEAD floor: refuses a stream that no longer holds its latest checkpoint in the store,
    /// or the one at `local` (behind it, or rewritten): an older HEAD put back by someone with
    /// access to the store fails with [`WriteError::Broken`] (`truncated` or `fork`).
    pub async fn with_checkpoints(
        self,
        local: Option<PathBuf>,
    ) -> Result<Writer<S, Checkpoints>, WriteError> {
        let mut size = 0;
        if let Some((at, bytes)) = latest_checkpoint(&self.store).await? {
            size =
                check(&bytes, Some(at), &self.chain, &self.hashes).map_err(WriteError::Broken)?;
        }
        let kept = match local.as_ref().map(std::fs::read) {
            Some(Err(e)) if e.kind() == io::ErrorKind::NotFound => None,
            r => r.transpose()?,
        };
        if let Some(bytes) = kept {
            let at = check(&bytes, None, &self.chain, &self.hashes).map_err(WriteError::Broken)?;
            size = size.max(at);
        }
        Ok(self.with_hook(Checkpoints {
            size,
            since: Instant::now(),
            local,
            key: None,
        }))
    }
}

/// Writes `note` to `path` whole: a temporary file renamed over it.
fn keep(path: &std::path::Path, note: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("note.tmp");
    std::fs::write(&tmp, note)?;
    std::fs::rename(&tmp, path)
}

/// The size in a checkpoint key, if it is one.
pub(crate) fn size_of(key: &str) -> Option<u64> {
    let n: u64 = key
        .strip_prefix("checkpoints/")?
        .strip_suffix(".note")?
        .parse()
        .ok()?;
    (checkpoint::key(n) == key).then_some(n)
}

/// The size in an anchor key, if it is one.
pub(crate) fn anchored_size(key: &str) -> Option<u64> {
    let n: u64 = key
        .strip_prefix("anchors/")?
        .strip_suffix(".tsr")?
        .parse()
        .ok()?;
    (checkpoint::anchor_key(n) == key).then_some(n)
}

/// The stream's latest checkpoint in `store`: its size and bytes.
pub async fn latest_checkpoint<S: Store>(store: &S) -> io::Result<Option<(u64, Vec<u8>)>> {
    let Some(size) = store
        .list("checkpoints/")
        .await?
        .iter()
        .filter_map(|l| size_of(&l.key))
        .max()
    else {
        return Ok(None);
    };
    Ok(store
        .get(&checkpoint::key(size))
        .await?
        .map(|o| (size, o.bytes)))
}

/// Checks a checkpoint note against a stream read to its end (`chain`, entry hashes `hashes`);
/// `at` is the size its key names, if it was found in the store. Returns its size.
pub(crate) fn check(
    bytes: &[u8],
    at: Option<u64>,
    chain: &Chain,
    hashes: &[Hash],
) -> Result<u64, Broken> {
    let broken = |seq: u64, error| Broken {
        seq: seq.max(1),
        error,
    };
    let note = Note::parse(bytes).map_err(|e| broken(at.unwrap_or(chain.seq() + 1), e))?;
    let size = note.checkpoint.size;
    if let Some(at) = at.filter(|&at| at != size) {
        return Err(broken(
            at,
            Error::new(
                Code::BadCheckpoint,
                format!("{} holds size {size}", checkpoint::key(at)),
            ),
        ));
    }
    note.check(chain, hashes)?;
    Ok(size)
}
