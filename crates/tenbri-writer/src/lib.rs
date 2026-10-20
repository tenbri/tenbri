//! Tenbri batching, write protocol, HEAD, checkpoints and reconciliation.
//!
//! [`Writer`] appends to one stream with the write protocol of spec/format-v1.md, section 8, on
//! any [`Store`] (a local directory, an S3, R2 or MinIO bucket): create-exclusive batches, a
//! signed HEAD advanced by compare-and-swap, roll-forward of a batch a crashed writer left behind,
//! and a conflict, never an overwrite, when another writer got there first. [`Lane`] shares one
//! writer between many tasks with group commit and backpressure. A [`Hook`] runs after every HEAD
//! the writer moves; [`Checkpoints`] is the one that writes signed checkpoints, and
//! [`Writer::with_checkpoints`] refuses a HEAD older than the latest one. [`verify`] and
//! [`Reader`] read a stream back; [`gc`] removes what crashed writers left.

mod checkpoints;
mod lane;
mod read;

use std::fmt;
use std::future::Future;
use std::io;
use std::time::{Duration, SystemTime};

use tenbri_core::{
    Broken, Chain, Code, Entry, Error, Head, Kind, Phase, Role, Source, Status, canon, encoding,
    sign,
};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::Hash;
use tenbri_store::{Object, Put, Store, Swap, Version, is_temporary};

pub use checkpoints::{CHECKPOINT_FILE, Checkpoints};
pub use lane::{Lane, LaneConfig};
pub use read::{ReadError, Reader, Report, batch_key, batch_seq, split_batch, verify};

/// How long an intent may stay open before the next writer session reconciles it: 1 hour.
pub const RECONCILE_AFTER_MS: i64 = 3_600_000;

/// How old an orphaned batch or temporary file must be before [`gc`] removes it: 1 hour.
pub const GC_MIN_AGE: Duration = Duration::from_secs(3600);

/// A writer with a key store ([`Writer::use_keys`]) replaces its session key when it has less
/// than this left: 1 minute.
pub const SESSION_MARGIN_MS: i64 = 60_000;

#[derive(Debug)]
pub enum WriteError {
    Io(io::Error),
    /// There is no stream here.
    NoStream,
    /// [`Writer::create`] found a stream already there.
    Exists,
    /// The stream does not verify; nothing was written.
    Broken(Broken),
    /// The entry breaks a rule of the format; nothing was written.
    Rejected(Error),
    /// A batch that does not chain from HEAD holds the next sequence number; nothing was written.
    Conflict {
        seq: u64,
    },
    /// No usable session key (none set, expired or revoked).
    NoSession(String),
    /// The lane's queue stayed full past the deadline; nothing was written (fail closed).
    Backpressure,
    /// The lane's writer stopped; whether the entry was written is unknown.
    Closed,
}

impl WriteError {
    /// The same error again, for every entry of a batch that failed as a whole.
    fn again(&self) -> WriteError {
        match self {
            WriteError::Io(e) => WriteError::Io(io::Error::new(e.kind(), e.to_string())),
            WriteError::NoStream => WriteError::NoStream,
            WriteError::Exists => WriteError::Exists,
            WriteError::Broken(b) => WriteError::Broken(b.clone()),
            WriteError::Rejected(e) => WriteError::Rejected(e.clone()),
            WriteError::Conflict { seq } => WriteError::Conflict { seq: *seq },
            WriteError::NoSession(s) => WriteError::NoSession(s.clone()),
            WriteError::Backpressure => WriteError::Backpressure,
            WriteError::Closed => WriteError::Closed,
        }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::Io(e) => write!(f, "{e}"),
            WriteError::NoStream => f.write_str("no stream here (no HEAD)"),
            WriteError::Exists => f.write_str("a stream already exists here"),
            WriteError::Broken(b) => write!(f, "the stream does not verify: {b}"),
            WriteError::Rejected(e) => write!(f, "entry rejected: {e}"),
            WriteError::Conflict { seq } => {
                write!(
                    f,
                    "conflict: {} exists and does not chain from HEAD",
                    batch_key(*seq)
                )
            }
            WriteError::NoSession(why) => write!(f, "no session key: {why}"),
            WriteError::Backpressure => {
                f.write_str("the lane's queue is full and stayed full past the deadline")
            }
            WriteError::Closed => f.write_str("the lane's writer stopped"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<io::Error> for WriteError {
    fn from(e: io::Error) -> Self {
        WriteError::Io(e)
    }
}

impl From<ReadError> for WriteError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::Io(e) => WriteError::Io(e),
            ReadError::NoStream => WriteError::NoStream,
            ReadError::Broken(b) => WriteError::Broken(b),
        }
    }
}

/// Milliseconds since the Unix epoch, now.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// A new ULID for `ms`.
pub fn new_id(ms: i64) -> io::Result<String> {
    let mut r = [0u8; 16];
    getrandom::fill(&mut r[6..]).map_err(|e| io::Error::other(e.to_string()))?;
    r[..6].copy_from_slice(&(ms as u64).to_be_bytes()[2..]);
    Ok(encoding::ulid(u128::from_be_bytes(r)))
}

/// An entry draft from JSON (`tenbri append`): canonicalised, duplicate keys and non-integers
/// rejected, and none of the members the writer fills (`v`, `stream`, `seq`, `prev`, `signer`,
/// `sig`). `id` and `ts` may be given, for idempotent retries and attestations.
pub fn draft_from_json(bytes: &[u8]) -> Result<Entry, Error> {
    let v = canon::parse(bytes)?;
    let canon::Value::Obj(mut members) = v else {
        return Err(Error::new(Code::InvalidField, "an entry is a JSON object"));
    };
    if let Some(k) = members
        .iter()
        .map(|(k, _)| k.as_str())
        .find(|k| !tenbri_core::FIELDS.contains(k))
    {
        return Err(Error::new(Code::UnknownField, format!("`{k}`")));
    }
    if let Some(k) = members
        .iter()
        .map(|(k, _)| k.as_str())
        .find(|k| ["v", "stream", "seq", "prev", "signer", "sig"].contains(k))
    {
        return Err(Error::new(
            Code::InvalidField,
            format!("`{k}` is filled in by the writer"),
        ));
    }
    for (k, v) in [("v", canon::Value::Int(1)), ("seq", canon::Value::Int(0))]
        .into_iter()
        .chain(
            ["id", "stream", "ts", "signer", "sig"].map(|k| (k, canon::Value::Str(String::new()))),
        )
    {
        if !members.iter().any(|(m, _)| m == k) {
            members.push((k.into(), v));
        }
    }
    serde_json::from_slice(&canon::to_vec(&canon::Value::Obj(members)))
        .map_err(|e| Error::new(Code::InvalidField, e.to_string()))
}

/// What a writer just made durable: HEAD, whose last batch starts at `first`, and the entry hashes
/// (RFC 6962 leaf hashes) of the whole stream, from seq 1 to `head.seq`, the entries other writers
/// put under HEAD included. From [`Writer::tick`], nothing new: `first` is `head.seq + 1`.
#[derive(Clone, Copy)]
pub struct Commit<'a> {
    pub head: &'a Head,
    pub first: u64,
    pub hashes: &'a [Hash],
    /// The writer's session key, if it may sign a checkpoint now: certified by the stream, not
    /// revoked, not expired.
    pub signer: Option<&'a Key>,
}

/// Runs after every HEAD compare-and-swap this writer wins (its own batches and the ones it rolls
/// forward), before the appends it covers return, and on [`Writer::tick`]. [`Checkpoints`] plugs
/// in here. The batch is durable whatever the hook does.
pub trait Hook<S: Store>: Send {
    fn committed(&mut self, store: &S, commit: Commit<'_>) -> impl Future<Output = ()> + Send;
}

/// No hook.
impl<S: Store> Hook<S> for () {
    async fn committed(&mut self, _: &S, _: Commit<'_>) {}
}

/// Appends to one stream. Holds the stream's state, checked from genesis when opened.
pub struct Writer<S: Store, H = ()> {
    store: S,
    pin: Option<String>,
    chain: Chain,
    batches: Vec<u64>,
    head: Head,
    version: Version,
    session: Option<Key>,
    /// Where session keys are renewed from, if set.
    keys: Option<KeyStore>,
    /// The entry hashes of `chain`, from seq 1.
    ///
    /// ponytail: 32 bytes per entry in memory, as `chain` keeps every id; a compact range
    /// (O(log n)) once checkpoint roots need only that.
    hashes: Vec<Hash>,
    /// `chain` may hold entries HEAD does not (a write was interrupted): read the stream again
    /// before the next write.
    stale: bool,
    hook: H,
}

impl<S: Store> Writer<S> {
    /// Creates a stream: the genesis entry certifying `stream_key` (signed by it), then `session`
    /// certified by it. Fails with [`WriteError::Exists`] if the store already holds a stream.
    pub async fn create(store: S, stream_key: &Key, session: Key) -> Result<Writer<S>, WriteError> {
        if store.get("HEAD").await?.is_some() {
            return Err(WriteError::Exists);
        }
        let mut e = tenbri_keys::certify(stream_key);
        e.stream = sign::stream_id(&stream_key.signing.verifying_key());
        e.seq = 1;
        stamp(&mut e)?;
        let mut w = Writer {
            pin: Some(stream_key.fingerprint()),
            chain: Chain::new(Some(&stream_key.fingerprint())),
            batches: vec![],
            head: Head {
                v: 1,
                stream: e.stream.clone(),
                seq: 0,
                hash: String::new(),
                counter: 0,
                batch: 0,
                signer: String::new(),
                sig: String::new(),
            },
            version: Version(String::new()),
            session: None,
            keys: None,
            hashes: vec![],
            stale: false,
            hook: (),
            store,
        };
        let mut e = fill(e, &w.chain, &stream_key.id);
        let line = sign::sign_entry(&mut e, &stream_key.signing).map_err(WriteError::Rejected)?;
        let checked = w.chain.check(&line).map_err(WriteError::Rejected)?;
        if w.store
            .put_if_absent(&batch_key(1), &with_lf(&line))
            .await?
            == Put::Exists
        {
            return Err(WriteError::Exists);
        }
        let head = signed_head(&w.head, 1, &checked.hash, 1, stream_key);
        match w.store.compare_and_swap("HEAD", None, &head.1).await? {
            Swap::Swapped(v) => (w.head, w.version) = (head.0, v),
            Swap::Mismatch => return Err(WriteError::Exists),
        }
        w.chain.apply(checked);
        w.hashes.push(read::last_hash(&w.chain));
        w.batches.push(1);
        w.certify_session(stream_key, session).await?;
        Ok(w)
    }

    /// Opens the stream in `store`, checking it from genesis against `pin` (a fingerprint), if
    /// given. A stream a revocation reaches back into still opens: the writer continues it.
    pub async fn open(store: S, pin: Option<&str>) -> Result<Writer<S>, WriteError> {
        let (chain, batches, hashes, head) = {
            let mut r = Reader::new(&store, pin);
            r.poll().await?;
            (r.chain, r.batches, r.hashes, r.head)
        };
        let (head, version) = head.expect("a polled reader has a HEAD");
        Ok(Writer {
            store,
            pin: pin.map(str::to_owned),
            chain,
            batches,
            head,
            version,
            session: None,
            keys: None,
            hashes,
            stale: false,
            hook: (),
        })
    }
}

impl<S: Store, H> Writer<S, H> {
    /// The same writer, calling `hook` after every HEAD it moves from now on, instead of its hook.
    pub fn with_hook<H2: Hook<S>>(self, hook: H2) -> Writer<S, H2> {
        Writer {
            store: self.store,
            pin: self.pin,
            chain: self.chain,
            batches: self.batches,
            head: self.head,
            version: self.version,
            session: self.session,
            keys: self.keys,
            hashes: self.hashes,
            stale: self.stale,
            hook,
        }
    }
}

impl<S: Store, H: Hook<S>> Writer<S, H> {
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn session(&self) -> Option<&Key> {
        self.session.as_ref()
    }
    pub fn hook(&mut self) -> &mut H {
        &mut self.hook
    }
    /// The entry hashes (RFC 6962 leaf hashes) of the stream, from seq 1.
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// Lets the hook act on time alone, when nothing is being written (a checkpoint due after
    /// 60 seconds): [`Lane`] calls it when idle.
    pub async fn tick(&mut self) {
        if self.stale {
            return;
        }
        let commit = Commit {
            head: &self.head,
            first: self.head.seq + 1,
            hashes: &self.hashes,
            signer: signer(&self.chain, self.session.as_ref()),
        };
        self.hook.committed(&self.store, commit).await;
    }

    /// Signs with session keys from `keys` from now on, renewing the session key before it
    /// expires: the stored one the stream certified that is valid longest, else a new one,
    /// certified with the stream key if `keys` holds it, and saved there.
    pub async fn use_keys(&mut self, keys: KeyStore) -> Result<(), WriteError> {
        self.keys = Some(keys);
        self.renew_session().await
    }

    /// With a key store, makes sure the session key is valid for at least [`SESSION_MARGIN_MS`].
    async fn renew_session(&mut self) -> Result<(), WriteError> {
        let now = now_ms();
        let Some(keys) = self.keys.clone() else {
            return Ok(());
        };
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.valid_at(now + SESSION_MARGIN_MS))
        {
            return Ok(());
        }
        let metas = keys.list()?;
        let mut sessions: Vec<_> = metas.iter().filter(|m| m.role == Role::Session).collect();
        sessions.sort_by(|a, b| b.not_after.cmp(&a.not_after));
        for m in sessions {
            if let Ok(k) = keys.load(&m.id) {
                if k.valid_at(now + SESSION_MARGIN_MS) && self.use_session(k).is_ok() {
                    return Ok(());
                }
            }
        }
        let current = self
            .chain
            .stream_key()
            .ok_or_else(|| WriteError::NoSession("the stream has no stream key".into()))?
            .to_owned();
        let stream_key = keys.load(&current).map_err(|e| {
            WriteError::NoSession(format!(
                "no usable session key, and the stream key {current} is not in {}: {e}",
                keys.dir().display()
            ))
        })?;
        let session = Key::new_session(now, SESSION_LIFETIME_MS)?;
        let backend = metas
            .iter()
            .find(|m| m.id == current)
            .map_or(Backend::File, |m| m.backend);
        keys.save(&session, backend)?;
        self.certify_session(&stream_key, session).await?;
        Ok(())
    }

    /// Signs with `key` from now on: a session key this stream certified, not revoked, valid now.
    pub fn use_session(&mut self, key: Key) -> Result<(), WriteError> {
        let info = self.chain.key(&key.id).ok_or_else(|| {
            WriteError::NoSession(format!("{} is not certified in this stream", key.id))
        })?;
        if info.role != tenbri_core::Role::Session || info.public != key.signing.verifying_key() {
            return Err(WriteError::NoSession(format!(
                "{} is not this stream's session key",
                key.id
            )));
        }
        if info.revoked_from.is_some() {
            return Err(WriteError::NoSession(format!("{} is revoked", key.id)));
        }
        if !key.valid_at(now_ms()) {
            return Err(WriteError::NoSession(format!("{} expired", key.id)));
        }
        self.session = Some(key);
        Ok(())
    }

    /// Certifies `session` with the current stream key and signs with it from now on.
    pub async fn certify_session(
        &mut self,
        stream_key: &Key,
        session: Key,
    ) -> Result<Entry, WriteError> {
        let e = self
            .write(tenbri_keys::certify(&session), stream_key, &session)
            .await?;
        self.session = Some(session);
        Ok(e)
    }

    /// Makes `new` the stream key; `old`, the current one, signs the hand-over.
    pub async fn rotate(&mut self, old: &Key, new: &Key) -> Result<Entry, WriteError> {
        let head_key = self.session.clone().unwrap_or_else(|| new.clone());
        self.write(tenbri_keys::rotate(new), old, &head_key).await
    }

    /// Revokes key `id` from sequence number `from`; entries it signed there or later stop
    /// verifying, including ones already written (see [`Chain::invalidated`]).
    pub async fn revoke(
        &mut self,
        stream_key: &Key,
        id: &str,
        from: u64,
    ) -> Result<Entry, WriteError> {
        let head_key = match &self.session {
            Some(s) if s.id != id => s.clone(),
            _ => stream_key.clone(),
        };
        let e = self
            .write(tenbri_keys::revoke(id, from), stream_key, &head_key)
            .await?;
        if self.session.as_ref().is_some_and(|s| s.id == id) {
            self.session = None;
        }
        Ok(e)
    }

    /// Appends `e`, signed by the session key; returns it as stored, once durable.
    pub async fn append(&mut self, e: Entry) -> Result<Entry, WriteError> {
        self.append_batch(vec![e])
            .await
            .pop()
            .expect("one result per entry")
    }

    /// Appends `entries` as one batch, in order, signed by the session key: one put and one HEAD
    /// swap for all of them. Returns each entry as stored, or why it was not: an entry that breaks
    /// a rule is refused alone, a failed write fails all of them.
    pub async fn append_batch(&mut self, entries: Vec<Entry>) -> Vec<Result<Entry, WriteError>> {
        if let Err(e) = self.renew_session().await {
            return entries.iter().map(|_| Err(e.again())).collect();
        }
        let session = match &self.session {
            None => Err(WriteError::NoSession("none set".into())),
            Some(s) if !s.valid_at(now_ms()) => {
                Err(WriteError::NoSession(format!("{} expired", s.id)))
            }
            Some(s) => Ok(s.clone()),
        };
        match session {
            Ok(s) => self.write_batch(entries, &s, &s).await,
            Err(e) => entries.iter().map(|_| Err(e.again())).collect(),
        }
    }

    /// Records an intent: durable before the action runs.
    pub async fn intent(&mut self, e: Entry) -> Result<Entry, WriteError> {
        self.append(as_intent(e)).await
    }

    /// Records the outcome of `intent`, with its principal, action, source and subject.
    pub async fn outcome(&mut self, intent: &Entry, status: Status) -> Result<Entry, WriteError> {
        self.append(outcome_of(intent, status)).await
    }

    /// Writes a `reconcile` entry with `status: unknown` for every intent open longer than
    /// `timeout_ms` at `now`, except `keep` (the intent the caller is about to close).
    pub async fn reconcile_stale(
        &mut self,
        now: i64,
        timeout_ms: i64,
        keep: Option<&str>,
    ) -> Result<Vec<Entry>, WriteError> {
        let entries = self.stale_intents(now, timeout_ms, |id| Some(id) == keep);
        self.append_batch(entries).await.into_iter().collect()
    }

    /// `reconcile` drafts for the intents open longer than `timeout_ms` at `now`, but `keep`.
    fn stale_intents(&self, now: i64, timeout_ms: i64, keep: impl Fn(&str) -> bool) -> Vec<Entry> {
        let mut stale: Vec<String> = self
            .chain
            .open_intents()
            .iter()
            .filter(|(id, o)| {
                !o.reconciled
                    && !keep(id)
                    && encoding::parse_ts(&o.ts).is_some_and(|t| t + timeout_ms < now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        stale.sort();
        stale
            .into_iter()
            .map(|id| Entry {
                intent: Some(id),
                status: Some(Status::Unknown),
                ..Entry::new(Kind::Reconcile)
            })
            .collect()
    }

    /// Reads the stream again from genesis, refusing a HEAD older than the one it had.
    ///
    /// ponytail: replays every batch; after an interrupted write only. Incremental from the last
    /// checkpoint once checkpoints exist.
    async fn reload(&mut self) -> Result<(), WriteError> {
        let mut r = Reader::new(&self.store, self.pin.as_deref());
        r.poll().await?;
        let (head, version) = r.head.expect("a polled reader has a HEAD");
        if head.counter < self.head.counter {
            return Err(WriteError::Broken(Broken {
                seq: head.seq,
                error: Error::new(
                    Code::BadHead,
                    format!(
                        "HEAD went back: counter {} after {}",
                        head.counter, self.head.counter
                    ),
                ),
            }));
        }
        (self.chain, self.batches, self.hashes) = (r.chain, r.batches, r.hashes);
        (self.head, self.version) = (head, version);
        self.stale = false;
        Ok(())
    }

    /// One entry signed by `key`, HEAD signed by `head_key`.
    async fn write(&mut self, e: Entry, key: &Key, head_key: &Key) -> Result<Entry, WriteError> {
        self.write_batch(vec![e], key, head_key)
            .await
            .pop()
            .expect("one result per entry")
    }

    /// The write protocol for one batch of entries signed by `key`, HEAD signed by `head_key`.
    async fn write_batch(
        &mut self,
        entries: Vec<Entry>,
        key: &Key,
        head_key: &Key,
    ) -> Vec<Result<Entry, WriteError>> {
        let mut results: Vec<Option<Result<Entry, WriteError>>> =
            entries.iter().map(|_| None).collect();
        let mut pending = vec![];
        for (i, mut e) in entries.into_iter().enumerate() {
            match stamp(&mut e) {
                Ok(()) => pending.push((i, e)),
                Err(err) => results[i] = Some(Err(err.into())),
            }
        }
        if let Err(err) = self
            .write_pending(&mut pending, &mut results, key, head_key)
            .await
        {
            for (i, _) in pending {
                results[i] = Some(Err(err.again()));
            }
        }
        results
            .into_iter()
            .map(|r| r.expect("every entry has a result"))
            .collect()
    }

    /// Writes `pending` (index, draft) and fills in `results`; on an error, `pending` holds the
    /// entries it is for.
    async fn write_pending(
        &mut self,
        pending: &mut Vec<(usize, Entry)>,
        results: &mut [Option<Result<Entry, WriteError>>],
        key: &Key,
        head_key: &Key,
    ) -> Result<(), WriteError> {
        loop {
            if self.stale {
                self.reload().await?;
            }
            // 1. Sign the batch as the entries after HEAD; an entry that breaks a rule is refused.
            // The chain takes the entries now and is stale until HEAD does too.
            let first = self.chain.seq() + 1;
            self.stale = true;
            let (mut bytes, mut built, mut hashes, mut keep) = (vec![], vec![], vec![], vec![]);
            for (i, draft) in pending.drain(..) {
                let mut e = fill(draft.clone(), &self.chain, &key.id);
                let checked = sign::sign_entry(&mut e, &key.signing)
                    .and_then(|line| Ok((self.chain.check(&line)?, line)));
                match checked {
                    Err(err) => results[i] = Some(Err(WriteError::Rejected(err))),
                    Ok((c, line)) => {
                        hashes.push(c.hash.clone());
                        self.chain.apply(c);
                        self.hashes.push(read::last_hash(&self.chain));
                        bytes.extend_from_slice(&line);
                        bytes.push(b'\n');
                        built.push((i, e));
                        keep.push((i, draft));
                    }
                }
            }
            *pending = keep;
            if built.is_empty() {
                self.stale = false;
                return Ok(());
            }
            let last = self.chain.seq();
            let mut done = |pending: &mut Vec<(usize, Entry)>| {
                pending.clear();
                for (i, e) in built.drain(..) {
                    results[i] = Some(Ok(e));
                }
                Ok(())
            };
            // 2. Put the batch; if the name is taken, 3. roll forward or stop.
            if self.store.put_if_absent(&batch_key(first), &bytes).await? == Put::Exists {
                self.reload().await?;
                let Some(found) = self.store.get(&batch_key(first)).await? else {
                    continue;
                };
                if self.chain.seq() < first {
                    self.roll_forward(first, &found, head_key).await?;
                }
                // Ours from an earlier attempt, and now under HEAD (rolled by us or by someone):
                // written once, done. Otherwise try again after it.
                if found.bytes == bytes && self.chain.seq() >= last {
                    return done(pending);
                }
                continue;
            }
            // 4. Advance HEAD.
            let hash = hashes.last().expect("a batch has entries");
            let (head, head_bytes) = signed_head(&self.head, last, hash, first, head_key);
            match self
                .store
                .compare_and_swap("HEAD", Some(&self.version), &head_bytes)
                .await?
            {
                Swap::Swapped(v) => {
                    self.stale = false;
                    self.batches.push(first);
                    (self.head, self.version) = (head, v);
                    let commit = Commit {
                        head: &self.head,
                        first,
                        hashes: &self.hashes,
                        signer: signer(&self.chain, self.session.as_ref()),
                    };
                    self.hook.committed(&self.store, commit).await;
                    return done(pending);
                }
                Swap::Mismatch => {
                    // Someone moved HEAD; if they rolled our batch forward, it is written.
                    self.reload().await?;
                    if self.chain.seq() >= last {
                        return done(pending);
                    }
                }
            }
        }
    }

    /// Step 3: the batch at `seq`, right after HEAD, belongs to a writer that crashed before
    /// advancing HEAD, if it is valid and chains from HEAD. Advances HEAD to it, or re-reads the
    /// stream if HEAD moved; a batch that does not chain is a conflict.
    async fn roll_forward(
        &mut self,
        seq: u64,
        found: &Object,
        head_key: &Key,
    ) -> Result<(), WriteError> {
        let conflict = || WriteError::Conflict { seq };
        self.stale = true;
        let mut hashes = vec![];
        for line in split_batch(&found.bytes).map_err(|_| conflict())? {
            let c = self.chain.check(line).map_err(|_| conflict())?;
            hashes.push(c.hash.clone());
            self.chain.apply(c);
            self.hashes.push(read::last_hash(&self.chain));
        }
        let last = self.chain.seq();
        let hash = hashes.last().expect("a batch has entries");
        let (head, head_bytes) = signed_head(&self.head, last, hash, seq, head_key);
        match self
            .store
            .compare_and_swap("HEAD", Some(&self.version), &head_bytes)
            .await?
        {
            Swap::Swapped(v) => {
                self.stale = false;
                self.batches.push(seq);
                (self.head, self.version) = (head, v);
                let commit = Commit {
                    head: &self.head,
                    first: seq,
                    hashes: &self.hashes,
                    signer: signer(&self.chain, self.session.as_ref()),
                };
                self.hook.committed(&self.store, commit).await;
                Ok(())
            }
            Swap::Mismatch => self.reload().await,
        }
    }
}

/// `session`, if it may sign a checkpoint of `chain` now: a session key the stream certified, not
/// revoked, not expired.
fn signer<'a>(chain: &Chain, session: Option<&'a Key>) -> Option<&'a Key> {
    session.filter(|k| {
        k.valid_at(now_ms())
            && chain.key(&k.id).is_some_and(|i| {
                i.role == Role::Session
                    && i.revoked_from.is_none()
                    && i.public == k.signing.verifying_key()
            })
    })
}

/// `e` as an intent: a decision, phase `intent`, source `sdk` unless set.
fn as_intent(mut e: Entry) -> Entry {
    e.kind = Kind::Decision;
    e.phase = Some(Phase::Intent);
    e.source.get_or_insert(Source::Sdk);
    e
}

/// The outcome of `intent`, with its principal, action, source and subject.
fn outcome_of(intent: &Entry, status: Status) -> Entry {
    Entry {
        kind: Kind::Decision,
        phase: Some(Phase::Outcome),
        intent: Some(intent.id.clone()),
        status: Some(status),
        source: intent.source,
        principal: intent.principal.clone(),
        action: intent.action.clone(),
        subject: intent.subject.clone(),
        ..Entry::new(Kind::Decision)
    }
}

/// Gives a draft its id and timestamp, unless it has them.
fn stamp(e: &mut Entry) -> io::Result<()> {
    let now = now_ms();
    if e.id.is_empty() {
        e.id = new_id(now)?;
    }
    if e.ts.is_empty() {
        e.ts = encoding::format_ts(now);
    }
    Ok(())
}

/// Completes a draft as the next entry of `chain`.
fn fill(mut e: Entry, chain: &Chain, signer: &str) -> Entry {
    e.v = tenbri_core::FORMAT_VERSION;
    e.seq = chain.seq() + 1;
    if let Some(s) = chain.stream() {
        e.stream = s.to_owned();
    }
    e.prev = chain.last_hash().map(str::to_owned);
    e.signer = signer.to_owned();
    e
}

fn with_lf(line: &[u8]) -> Vec<u8> {
    let mut b = line.to_vec();
    b.push(b'\n');
    b
}

fn signed_head(prev: &Head, seq: u64, hash: &str, batch: u64, key: &Key) -> (Head, Vec<u8>) {
    let mut head = Head {
        v: 1,
        stream: prev.stream.clone(),
        seq,
        hash: hash.to_owned(),
        counter: prev.counter + 1,
        batch,
        signer: key.id.clone(),
        sig: String::new(),
    };
    let bytes = sign::sign_head(&mut head, &key.signing);
    (head, bytes)
}

/// Removes batches that do not chain from HEAD, temporary files and canary objects, if older than
/// `min_age`: what crashed writers and openers leave. A valid batch right after HEAD is kept, for
/// a writer to roll forward. Refuses to run on a stream that does not verify. Returns the removed
/// keys.
pub async fn gc<S: Store>(
    store: &S,
    pin: Option<&str>,
    min_age: Duration,
) -> Result<Vec<String>, WriteError> {
    let mut r = Reader::new(store, pin);
    r.poll().await?;
    let now = SystemTime::now();
    let mut removed = vec![];
    for l in store.list("batches/").await? {
        if now.duration_since(l.modified).unwrap_or_default() < min_age {
            continue;
        }
        let keep = match batch_seq(&l.key) {
            Some(s) if r.batches.contains(&s) => true,
            Some(s) if s == r.chain.seq() + 1 => match store.get(&l.key).await? {
                Some(o) => split_batch(&o.bytes).is_ok_and(|lines| {
                    let mut c = r.chain.clone();
                    lines.iter().all(|line| c.push(line).is_ok())
                }),
                None => true,
            },
            _ => false,
        };
        if !keep
            && (is_temporary(&l.key) || batch_seq(&l.key).is_some() || l.key.ends_with(".jsonl"))
        {
            store.delete(&l.key).await?;
            removed.push(l.key);
        }
    }
    for l in store.list("canary/").await? {
        if now.duration_since(l.modified).unwrap_or_default() >= min_age {
            store.delete(&l.key).await?;
            removed.push(l.key);
        }
    }
    Ok(removed)
}
