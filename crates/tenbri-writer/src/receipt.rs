//! Receipts from a stored stream (spec/receipts.md, section 4).

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;

use tenbri_core::{Broken, Kind};
use tenbri_merkle::{checkpoint, receipt};
use tenbri_store::Store;

use crate::checkpoints::{anchored_size, check, size_of};
use crate::read::{ReadError, Reader, batch_key, split_batch};

/// Why [`receipt`] made none.
#[derive(Debug)]
pub enum ReceiptError {
    Read(ReadError),
    /// No entry matched.
    NotFound,
    /// No checkpoint covers the entry at this seq yet: the writer makes one within 60 seconds.
    NotCheckpointed(u64),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::Read(e) => write!(f, "{e}"),
            ReceiptError::NotFound => f.write_str("no such entry"),
            ReceiptError::NotCheckpointed(seq) => write!(
                f,
                "no checkpoint covers seq {seq} yet; the writer makes one within 60 seconds of a write"
            ),
        }
    }
}

impl std::error::Error for ReceiptError {}

impl From<ReadError> for ReceiptError {
    fn from(e: ReadError) -> Self {
        ReceiptError::Read(e)
    }
}

impl From<io::Error> for ReceiptError {
    fn from(e: io::Error) -> Self {
        ReceiptError::Read(ReadError::Io(e))
    }
}

impl From<Broken> for ReceiptError {
    fn from(b: Broken) -> Self {
        ReceiptError::Read(ReadError::Broken(b))
    }
}

/// A receipt for the entries `select` picks, read from `store` and checked against `pin` on the
/// way. The checkpoint is the earliest one covering them that has an RFC 3161 timestamp, whose
/// response goes in too; without one, the latest checkpoint. The key history is every key entry
/// up to the checkpoint.
///
/// ponytail: reads the whole stream per receipt; tenbri-index's entry lookup when that is slow.
pub async fn receipt<S: Store>(
    store: &S,
    pin: Option<&str>,
    select: impl Fn(&tenbri_core::Entry) -> bool,
) -> Result<Vec<u8>, ReceiptError> {
    let mut r = Reader::new(store, pin);
    let all = r.poll().await?;
    if let Some(b) = r.chain().invalidated() {
        return Err(b.clone().into());
    }
    let targets: Vec<u64> = all.iter().filter(|e| select(e)).map(|e| e.seq).collect();
    let need = *targets.iter().max().ok_or(ReceiptError::NotFound)?;
    let len = r.hashes.len() as u64;
    let covering: BTreeSet<u64> = store
        .list("checkpoints/")
        .await?
        .iter()
        .filter_map(|l| size_of(&l.key))
        .filter(|s| (need..=len).contains(s))
        .collect();
    let anchored: BTreeSet<u64> = store
        .list("anchors/")
        .await?
        .iter()
        .filter_map(|l| anchored_size(&l.key))
        .collect();
    let size = covering
        .iter()
        .find(|s| anchored.contains(s))
        .or(covering.last())
        .copied()
        .ok_or(ReceiptError::NotCheckpointed(need))?;
    let note = store
        .get(&checkpoint::key(size))
        .await?
        .ok_or(ReceiptError::NotCheckpointed(need))?
        .bytes;
    check(&note, Some(size), &r.chain, &r.hashes)?;
    let tokens: Vec<_> = store
        .get(&checkpoint::anchor_key(size))
        .await?
        .map(|o| o.bytes)
        .into_iter()
        .collect();

    let mut seqs: BTreeSet<u64> = all
        .iter()
        .filter(|e| e.kind == Kind::Key && e.seq <= size)
        .map(|e| e.seq)
        .collect();
    seqs.extend(targets);
    let mut batches: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut lines = vec![];
    for seq in seqs {
        let first = r.batches[r.batches.partition_point(|b| *b <= seq) - 1];
        if let Entry::Vacant(v) = batches.entry(first) {
            let o = store.get(&batch_key(first)).await?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} is gone", batch_key(first)),
                )
            })?;
            v.insert(o.bytes);
        }
        lines.push((seq, first));
    }
    let mut entries = vec![];
    for (seq, first) in &lines {
        let batch = split_batch(&batches[first]).expect("read before");
        entries.push((*seq, batch[(seq - first) as usize]));
    }
    Ok(receipt::build(&note, &r.hashes, &entries, &tokens).expect("checked above"))
}
