//! Reading a stream the way the spec says: follow HEAD, batch by batch, checking everything.

use std::fmt;
use std::io;

use tenbri_core::{Broken, Chain, Code, Entry, Error, Head};
use tenbri_store::{Store, Version};

/// The key of the batch whose first entry is `seq`.
pub fn batch_key(seq: u64) -> String {
    format!("batches/{seq:012}.jsonl")
}

/// The first sequence number in a batch key, if it is one.
pub fn batch_seq(key: &str) -> Option<u64> {
    let name = key.strip_prefix("batches/")?.strip_suffix(".jsonl")?;
    (name.len() >= 12 && name.bytes().all(|c| c.is_ascii_digit()))
        .then(|| name.parse().ok())
        .flatten()
        .filter(|s| batch_key(*s) == key)
}

/// The lines of a batch file: each ends with a line feed, none is empty or holds a carriage return.
pub fn split_batch(bytes: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let bad = |d: &str| Error::new(Code::BadBatch, d.to_owned());
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| bad("a batch ends with a line feed"))?;
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    if lines.iter().any(|l| l.is_empty() || l.contains(&b'\r')) {
        return Err(bad("a batch has an empty line or a carriage return"));
    }
    Ok(lines)
}

/// Why a stream could not be read to its HEAD.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    /// There is no HEAD: nothing was ever written here.
    NoStream,
    /// The stream breaks at this sequence number.
    Broken(Broken),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::NoStream => f.write_str("no stream here (no HEAD)"),
            ReadError::Broken(b) => write!(f, "{b}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// Follows a stream's HEAD and checks every entry on the way. Call [`Reader::poll`] again to get
/// what was written since.
pub struct Reader<'a, S> {
    store: &'a S,
    pub(crate) chain: Chain,
    pub(crate) batches: Vec<u64>,
    pub(crate) head: Option<(Head, Version)>,
}

impl<'a, S: Store> Reader<'a, S> {
    /// A reader that trusts the genesis key with fingerprint `pin`, or only the stream itself.
    pub fn new(store: &'a S, pin: Option<&str>) -> Self {
        Reader {
            store,
            chain: Chain::new(pin),
            batches: vec![],
            head: None,
        }
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn head(&self) -> Option<&Head> {
        self.head.as_ref().map(|(h, _)| h)
    }

    /// Reads up to the current HEAD; returns the entries that are new since the last poll.
    pub async fn poll(&mut self) -> Result<Vec<Entry>, ReadError> {
        let Some(obj) = self.store.get("HEAD").await? else {
            return Err(ReadError::NoStream);
        };
        let at = |seq: u64, error: Error| ReadError::Broken(Broken { seq, error });
        let (head, _) = Head::parse(&obj.bytes).map_err(|e| at(self.chain.seq().max(1), e))?;
        if let Some((prev, _)) = &self.head {
            if head.counter < prev.counter || head.seq < prev.seq {
                return Err(at(head.seq, Error::new(Code::BadHead, "HEAD went back")));
            }
        }
        let mut out = vec![];
        while self.chain.seq() < head.seq {
            let first = self.chain.seq() + 1;
            let Some(batch) = self.store.get(&batch_key(first)).await? else {
                return Err(at(
                    first,
                    Error::new(
                        Code::MissingBatch,
                        format!("{} is missing", batch_key(first)),
                    ),
                ));
            };
            for line in split_batch(&batch.bytes).map_err(|e| at(first, e))? {
                out.push(self.chain.push(line).map_err(ReadError::Broken)?);
            }
            self.batches.push(first);
        }
        if self.chain.seq() > head.seq {
            return Err(at(
                head.seq,
                Error::new(Code::BadHead, "HEAD names an entry inside a batch"),
            ));
        }
        let batch = self.batches.last().copied().unwrap_or(0);
        let head = self
            .chain
            .check_head(&obj.bytes, batch)
            .map_err(|e| at(head.seq, e))?;
        self.head = Some((head, obj.version));
        Ok(out)
    }
}

/// The result of [`verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub stream: Option<String>,
    /// Entries checked before the first break, or all of them.
    pub entries: u64,
    /// Whether the genesis key was checked against a pinned fingerprint.
    pub pinned: bool,
    pub broken: Option<Broken>,
}

/// Checks a whole stream: canonical bytes, chain, signatures, keys, intents, HEAD.
pub async fn verify<S: Store>(store: &S, pin: Option<&str>) -> io::Result<Report> {
    let mut r = Reader::new(store, pin);
    let broken = match r.poll().await {
        Ok(_) => r.chain.invalidated().cloned(),
        Err(ReadError::Broken(b)) => Some(b),
        Err(ReadError::NoStream) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no stream here (no HEAD)",
            ));
        }
        Err(ReadError::Io(e)) => return Err(e),
    };
    let entries = match &broken {
        Some(b) => b.seq - 1,
        None => r.chain.seq(),
    };
    Ok(Report {
        stream: r.chain.stream().map(str::to_owned),
        entries,
        pinned: pin.is_some(),
        broken,
    })
}
