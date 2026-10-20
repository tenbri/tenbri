//! The checkpoints a writer makes (spec/checkpoints.md), and the floor it will not open below.

use std::io;
use std::path::PathBuf;
use std::time::Instant;

use tenbri_core::{Broken, Chain, Code, Error};
use tenbri_merkle::{Hash, Note, checkpoint};
use tenbri_store::{Put, Store};

use crate::{Commit, Hook, WriteError, Writer};

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
}

impl Checkpoints {
    /// The size of the last checkpoint written or found, 0 if none.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<S: Store> Hook<S> for Checkpoints {
    async fn committed(&mut self, store: &S, c: Commit<'_>) {
        let Some(key) = c.signer else { return };
        let size = c.hashes.len() as u64;
        let ms = self.since.elapsed().as_millis() as u64;
        if !checkpoint::due(size.saturating_sub(self.size), ms) {
            return;
        }
        let note = checkpoint::sign(&c.head.stream, c.hashes, &key.signing);
        // Exists: another writer checkpointed the same entries. On an error the next commit tries
        // again; the entries are durable whatever happens here.
        let stored = matches!(
            store.put_if_absent(&checkpoint::key(size), &note).await,
            Ok(Put::Created | Put::Exists)
        );
        if stored && self.local.as_ref().is_none_or(|p| keep(p, &note).is_ok()) {
            (self.size, self.since) = (size, Instant::now());
        }
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
        if let Some((at, bytes)) = latest(&self.store).await? {
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
fn size_of(key: &str) -> Option<u64> {
    let n: u64 = key
        .strip_prefix("checkpoints/")?
        .strip_suffix(".note")?
        .parse()
        .ok()?;
    (checkpoint::key(n) == key).then_some(n)
}

/// The stream's latest checkpoint in `store`: its size and bytes.
pub(crate) async fn latest<S: Store>(store: &S) -> io::Result<Option<(u64, Vec<u8>)>> {
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
