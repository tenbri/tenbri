//! tenbrid: the Tenbri REST and gRPC API.
//!
//! One [`Daemon`] holds a writer per configured stream (a lane) and serves the same operations
//! over REST (`/v1`, [`openapi_yaml`]) and gRPC (`tenbri.v1.TenbriService`, [`proto`]): append
//! intents, outcomes, approvals and batches; get, query and tail entries; receipts; verify a
//! stream; list the action schemas; health and readiness.
//!
//! - Every write carries an idempotency key, the entry id: the same key and draft return the
//!   original entry, the same key with another draft is `TENBRI_IDEMPOTENCY_CONFLICT`.
//! - Every append is checked against the format and the action schemas before it is written, and
//!   returns once it is durable. Entries are read back from storage and verified before they are
//!   served.
//! - Each stream is a `tenbri_writer::Lane` on a local directory or an S3, R2 or MinIO bucket:
//!   concurrent appends are group-committed, the writer checkpoints the stream and refuses a HEAD
//!   below the checkpoint it keeps with the keys. Its queue is bounded; an append waits for it up
//!   to the deadline, then fails with `TENBRI_DEADLINE_EXCEEDED` (backpressure).
//! - An intent's durability: `local` on local disk; `replicated` (the default) or `local` on an
//!   object store, where every write is replicated before it returns.
//! - Every request but health checks needs a bearer token, bound to one principal.
//! - With `[anchor]` configured, the latest checkpoint of every stream is timestamped by an RFC 3161
//!   authority every hour (by default), and receipts carry the token.
//! - Shutdown stops accepting requests, ends tails, and waits for the writes in flight.

mod config;
mod error;
mod grpc;
#[rustfmt::skip]
#[allow(clippy::all, missing_docs)]
pub mod proto;
mod rest;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::{Stream, StreamExt, stream};
use tenbri_core::{
    Code, Durability, Entry, Head, Kind, Phase, Principal, Role, Source, Trace, canon, encoding,
    sign,
};
use tenbri_keys::KeyStore;
use tenbri_merkle::checkpoint;
use tenbri_schema::Schemas;
use tenbri_store::{AnyStore, Store};
use tenbri_writer::{CHECKPOINT_FILE, LaneConfig, Reader, WriteError, Writer, draft_from_json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, broadcast, watch};
use tokio_stream::wrappers::BroadcastStream;

pub use config::{AnchorConfig, Config, StreamConfig, TokenConfig};
pub use error::{ApiError, ErrorBody, ErrorCode, Violation};
pub use rest::openapi_yaml;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The most entries one batch may hold.
pub const MAX_BATCH: usize = 1000;

/// How many new entries a tail may fall behind before it is ended with `TENBRI_TAIL_LAGGED`.
const TAIL_BUFFER: usize = 1024;

/// The caller, from its bearer token.
#[derive(Clone, Debug)]
pub struct Token {
    pub principal: Principal,
    /// Stream names it may use; `None`: all.
    pub streams: Option<Vec<String>>,
}

/// An entry as stored, with its canonical JSON and its entry hash.
#[derive(Debug)]
pub struct Stored {
    pub entry: Entry,
    pub line: String,
    /// `sha256:…`, the RFC 6962 leaf hash the chain and checkpoints use.
    pub hash: String,
}

/// Whether an entry checks out against the stream's pinned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    Verified,
    /// At or after the first sequence number that no longer verifies.
    Broken,
}

/// An entry and its verification status.
pub type Found = (Arc<Stored>, Verification);

/// What an append returned.
#[derive(Debug)]
pub struct Appended {
    pub stored: Arc<Stored>,
    /// The idempotency key was seen before; this is the original entry.
    pub replayed: bool,
    pub warnings: Vec<String>,
}

/// Which append operation; it fills the draft's kind and phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Intent,
    Outcome,
    Approval,
    /// Each draft names its own kind.
    Batch,
}

/// Filters for [`Daemon::query`] (the index's filter, a cursor and a page size); empty ones
/// match everything.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Its `after` is the cursor, `after_seq` in the API.
    pub filter: tenbri_index::Filter,
    /// 0 means 100; capped at 1000.
    pub limit: usize,
}

/// A page of [`Daemon::query`]: matching entries in sequence order, the cursor of the next page
/// if more match, and what the stream's index is current to.
pub type Queried = (Vec<Found>, Option<u64>, tenbri_index::State);

/// The result of [`Daemon::verify`].
#[derive(Clone, Debug)]
pub struct Verified {
    pub stream: String,
    pub entries: u64,
    pub pinned_key: String,
    pub broken: Option<tenbri_core::Broken>,
}

/// One stream and its writer: a lane.
struct Lane {
    name: String,
    id: String,
    pin: String,
    store: AnyStore,
    /// The store is an object store: every write is replicated before it returns.
    replicated: bool,
    writer: tenbri_writer::Lane,
    /// Reads back what was written, checking it, to feed the index.
    reader: Mutex<Reader<'static, AnyStore>>,
    index: RwLock<Index>,
    /// The query index (SQLite or Parquet), fed from `index` when a query comes.
    query_index: std::sync::Mutex<Box<dyn tenbri_index::Backend>>,
    tx: broadcast::Sender<Arc<Stored>>,
    writable: AtomicBool,
    /// The stream's key store, beside which its data keys live (spec/privacy.md).
    keys: KeyStore,
}

/// ponytail: every entry in memory, by position (`seq - 1`) and id, verified, for get, tail and
/// idempotent replays; queries go through tenbri-index. Serve those from the store when streams
/// outgrow memory.
#[derive(Default)]
struct Index {
    entries: Vec<Arc<Stored>>,
    ids: HashMap<String, usize>,
    broken_from: Option<u64>,
}

/// tenbrid's state: the lanes, the schemas, the tokens.
pub struct Daemon {
    lanes: BTreeMap<String, Arc<Lane>>,
    /// None without a tenbri.toml: nothing is checked.
    schemas: Option<Arc<Schemas>>,
    tokens: HashMap<String, Token>,
    shutdown: watch::Sender<bool>,
}

impl Daemon {
    /// Opens every configured stream, checks it from genesis against its pin and its latest
    /// checkpoints, and makes sure it has a session key.
    pub async fn open(config: &Config) -> Result<Daemon, String> {
        let mut stores = BTreeMap::new();
        for (name, sc) in &config.streams {
            let store = tenbri_store::open(&sc.path)
                .await
                .map_err(|e| format!("stream {name} ({}): {e}", sc.path))?;
            stores.insert(name.clone(), store);
        }
        Daemon::with_stores(config, stores).await
    }

    /// [`Daemon::open`] with each stream's store already open, by name.
    async fn with_stores(
        config: &Config,
        mut stores: BTreeMap<String, AnyStore>,
    ) -> Result<Daemon, String> {
        let schemas = match &config.schema {
            Some(p) => Some(Arc::new(Schemas::load(p)?)),
            None => None,
        };
        let keys = config
            .keys
            .clone()
            .or_else(tenbri_keys::default_dir)
            .ok_or("no keys directory: set keys or TENBRI_KEYS")?;
        let index_root = config
            .index_dir
            .clone()
            .or_else(tenbri_index::default_root)
            .ok_or("no index directory: set index_dir or TENBRI_INDEX_DIR")?;
        let mut lanes = BTreeMap::new();
        let lane_config = LaneConfig {
            queue: config.queue,
            deadline: Duration::from_millis(config.deadline_ms),
            ..LaneConfig::default()
        };
        for (name, sc) in &config.streams {
            let store = stores.remove(name).ok_or("a stream without a store")?;
            let lane = Lane::open(name, sc, store, &keys, &index_root, lane_config)
                .await
                .map_err(|e| format!("stream {name} ({}): {e}", sc.path))?;
            lanes.insert(name.clone(), Arc::new(lane));
        }
        let tokens = config
            .tokens
            .iter()
            .map(|t| {
                let token = Token {
                    principal: t.principal.clone(),
                    streams: t.streams.clone(),
                };
                (t.sha256.clone(), token)
            })
            .collect();
        Ok(Daemon {
            lanes,
            schemas,
            tokens,
            shutdown: watch::Sender::new(false),
        })
    }

    /// The caller of a request with `Authorization: <header>`.
    pub fn authenticate(&self, header: Option<&str>) -> Result<Token, ApiError> {
        let token = header
            .and_then(|h| h.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unauthenticated,
                    "send Authorization: Bearer <token>",
                )
            })?;
        // Looked up by its hash, so the comparison leaks nothing about the token.
        self.tokens
            .get(&sign::sha256(token.as_bytes()))
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::Unauthenticated, "unknown token"))
    }

    fn lane(&self, token: &Token, stream: &str) -> Result<&Arc<Lane>, ApiError> {
        let lane = self
            .lanes
            .get(stream)
            .or_else(|| self.lanes.values().find(|l| l.id == stream))
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, format!("no stream {stream}")))?;
        match &token.streams {
            Some(names) if !names.contains(&lane.name) => Err(ApiError::new(
                ErrorCode::Forbidden,
                format!("this token may not use stream {stream}"),
            )),
            _ => Ok(lane),
        }
    }

    /// The action schemas as JSON: tenbri.toml's `unknown_actions` and `actions`; without a
    /// tenbri.toml, no actions and nothing checked.
    pub fn schemas_json(&self) -> serde_json::Value {
        match &self.schemas {
            Some(s) => serde_json::to_value(&**s).expect("schemas serialize"),
            None => serde_json::json!({ "actions": {} }),
        }
    }

    /// Ready to take writes: not shutting down, and every stream verifies and has a session key.
    pub fn ready(&self) -> bool {
        !*self.shutdown.borrow()
            && self
                .lanes
                .values()
                .all(|l| l.writable.load(Ordering::Relaxed))
    }

    /// Appends one draft (a JSON object). `key` is the Idempotency-Key, the entry id; `trace`,
    /// from the request's `traceparent`, is the entry's `trace` unless the draft has one.
    pub async fn append(
        &self,
        token: &Token,
        stream: &str,
        op: Op,
        key: Option<&str>,
        draft: &[u8],
        trace: Option<&Trace>,
    ) -> Result<Appended, ApiError> {
        let key = key.ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "an Idempotency-Key is required: the entry id, a ULID",
            )
        })?;
        let value = canon::parse(draft)?;
        let mut out = self
            .commit(token, stream, op, vec![(Some(key), value)], trace)
            .await?;
        Ok(out.remove(0))
    }

    /// Appends drafts in order, each with its own `id`. Every draft is checked before any is
    /// written; a storage failure part-way leaves the earlier ones written, and retrying the
    /// whole batch is safe. `trace` is the `trace` of every draft without one.
    pub async fn append_batch(
        &self,
        token: &Token,
        stream: &str,
        drafts: Vec<canon::Value>,
        trace: Option<&Trace>,
    ) -> Result<Vec<Appended>, ApiError> {
        if drafts.is_empty() || drafts.len() > MAX_BATCH {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                format!("a batch holds 1 to {MAX_BATCH} entries"),
            ));
        }
        let drafts = drafts.into_iter().map(|d| (None, d)).collect();
        self.commit(token, stream, Op::Batch, drafts, trace).await
    }

    async fn commit(
        &self,
        token: &Token,
        stream: &str,
        op: Op,
        drafts: Vec<(Option<&str>, canon::Value)>,
        trace: Option<&Trace>,
    ) -> Result<Vec<Appended>, ApiError> {
        let lane = self.lane(token, stream)?.clone();
        let mut entries: Vec<Entry> = vec![];
        for (key, value) in drafts {
            let e = lane.prepare(token, op, key, value, &entries)?;
            entries.push(e);
        }
        // Spawned, so a client that goes away cannot stop the read-back half-way. The lane's
        // queue gives the backpressure: an append waits for room up to the deadline.
        let schemas = self.schemas.clone();
        let trace = trace.cloned();
        tokio::spawn(async move { lane.write(entries, schemas.as_deref(), trace).await })
            .await
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
    }

    pub fn get(&self, token: &Token, stream: &str, id: &str) -> Result<Found, ApiError> {
        let lane = self.lane(token, stream)?;
        let ix = lane.index.read().expect("index lock");
        let s = ix
            .ids
            .get(id)
            .map(|&i| ix.entries[i].clone())
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, format!("no entry {id}")))?;
        let v = ix.verification(s.entry.seq);
        Ok((s, v))
    }

    /// Matching entries in sequence order, and the `after_seq` of the next page if there is one,
    /// through the stream's index, which first takes what was written since the last query. The
    /// entries returned are the ones this daemon read and verified, not the index's copies.
    pub async fn query(&self, token: &Token, stream: &str, q: &Query) -> Result<Queried, ApiError> {
        let lane = self.lane(token, stream)?;
        let limit = match q.limit {
            0 => 100,
            n => n.min(1000),
        };
        let seq = lane.index.read().expect("index lock").entries.len() as u64;
        let checkpoint = tenbri_index::latest_checkpoint(&lane.store, seq).await?;
        let internal =
            |e: std::io::Error| ApiError::new(ErrorCode::Internal, format!("index: {e}"));
        let (hits, answer) = {
            // ponytail: SQLite and Parquet run on the async worker; spawn_blocking if large pages
            // or Parquet scans hold it too long.
            let mut qx = lane.query_index.lock().expect("query index lock");
            let ix = lane.index.read().expect("index lock");
            let mut answer = None;
            // Once more from scratch if the index disagrees with what was verified (it was
            // changed under us, or by another process).
            for fresh in [false, true] {
                if fresh {
                    qx.clear().map_err(internal)?;
                }
                lane.feed(qx.as_mut(), &ix, checkpoint).map_err(internal)?;
                let page = tenbri_index::search(qx.as_ref(), &q.filter, limit).map_err(internal)?;
                let found: Option<Vec<Found>> = page
                    .hits
                    .iter()
                    .map(|h| {
                        let s = ix.entries.get((h.seq as usize).checked_sub(1)?)?;
                        (s.hash == h.hash).then(|| (s.clone(), ix.verification(h.seq)))
                    })
                    .collect();
                if let (Some(found), Some(state)) = (found, page.state) {
                    answer = Some((page.hits, (found, page.next, state)));
                    break;
                }
            }
            answer.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Internal,
                    "the index disagrees with the stream after a rebuild",
                )
            })?
        };
        // What was verified at startup may have been edited on disk since: check the page's
        // entries against storage before answering with them.
        tenbri_index::confirm(&lane.store, &hits)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::InvalidData => {
                    ApiError::new(ErrorCode::StreamBroken, e.to_string())
                }
                _ => e.into(),
            })?;
        Ok(answer)
    }

    /// Entries after `after_seq`, then new ones as they are written, until shutdown. Ends with an
    /// error if the caller falls more than 1024 entries behind.
    pub fn tail(
        &self,
        token: &Token,
        stream: &str,
        after_seq: u64,
    ) -> Result<impl Stream<Item = Result<Found, ApiError>> + Send + use<>, ApiError> {
        let lane = self.lane(token, stream)?.clone();
        let (backlog, rx) = {
            // Subscribed under the lock that guards the index, so nothing falls in between.
            let ix = lane.index.read().expect("index lock");
            let start = usize::try_from(after_seq)
                .unwrap_or(usize::MAX)
                .min(ix.entries.len());
            (ix.entries[start..].to_vec(), lane.tx.subscribe())
        };
        let last = backlog.last().map_or(after_seq, |s| s.entry.seq);
        let live = BroadcastStream::new(rx).filter_map(move |r| {
            std::future::ready(match r {
                Ok(s) if s.entry.seq <= last => None,
                Ok(s) => Some(Ok(s)),
                Err(_) => Some(Err(ApiError::new(
                    ErrorCode::TailLagged,
                    "the tail fell behind; reconnect with after_seq",
                ))),
            })
        });
        let mut shutdown = self.shutdown.subscribe();
        let stop = async move {
            let _ = shutdown.wait_for(|s| *s).await;
        };
        Ok(stream::iter(backlog.into_iter().map(Ok))
            .chain(live)
            .take_until(stop)
            // Stop after the first error.
            .scan(false, |done, r| {
                let item = (!*done).then_some(r);
                *done = item.as_ref().is_some_and(Result::is_err);
                std::future::ready(item)
            })
            .map(move |r| {
                r.map(|s| {
                    let v = lane
                        .index
                        .read()
                        .expect("index lock")
                        .verification(s.entry.seq);
                    (s, v)
                })
            }))
    }

    /// A receipt for the entry `id` (spec/receipts.md): the file `tenbri receipt verify` checks.
    pub async fn receipt(
        &self,
        token: &Token,
        stream: &str,
        id: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let lane = self.lane(token, stream)?;
        if !lane.index.read().expect("index lock").ids.contains_key(id) {
            return Err(ApiError::new(ErrorCode::NotFound, format!("no entry {id}")));
        }
        let make = || tenbri_writer::receipt(&lane.store, Some(&lane.pin), |e| e.id == id);
        match make().await {
            // No checkpoint covers it yet: seal one now rather than make the caller wait for it.
            Err(tenbri_writer::ReceiptError::NotCheckpointed(_)) => {
                lane.writer.seal().await;
                Ok(make().await?)
            }
            r => Ok(r?),
        }
    }

    /// Timestamps the latest checkpoint of every stream that has none yet with the TSA at `url`;
    /// what [`Daemon::anchor_every`] runs. Returns the store keys of the tokens written.
    pub async fn anchor(&self, url: &str) -> Vec<String> {
        let mut written = vec![];
        for lane in self.lanes.values() {
            match anchor(&lane.store, url).await {
                Ok(Some(k)) => written.push(k),
                Ok(None) => {}
                Err(e) => eprintln!("tenbrid: stream {}: timestamping: {e}", lane.name),
            }
        }
        written
    }

    /// Runs [`Daemon::anchor`] every `every` until shutdown, if `[anchor]` is configured.
    pub async fn anchor_every(&self, config: &Config) {
        let Some(a) = &config.anchor else { return };
        let mut stop = self.shutdown.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(a.every_s));
        loop {
            tokio::select! {
                _ = tick.tick() => { self.anchor(&a.tsa).await; }
                _ = async { stop.wait_for(|s| *s).await.is_ok() } => return,
            }
        }
    }

    /// Reads the stream from storage and checks all of it against its pinned key.
    pub async fn verify(&self, token: &Token, stream: &str) -> Result<Verified, ApiError> {
        let lane = self.lane(token, stream)?;
        let r = tenbri_writer::verify(&lane.store, Some(&lane.pin)).await?;
        Ok(Verified {
            stream: lane.id.clone(),
            entries: r.entries,
            pinned_key: lane.pin.clone(),
            broken: r.broken,
        })
    }

    /// The keyed digest of an input, `hmac-sha256:<hex>`, under the data key of `subject` (the
    /// tenant's without one), made on first use: what an SDK holding the keys computes itself, for
    /// a caller that holds only a token (spec/privacy.md).
    pub async fn digest(
        &self,
        token: &Token,
        stream: &str,
        subject: Option<String>,
        content: Vec<u8>,
    ) -> Result<String, ApiError> {
        let keys = self.lane(token, stream)?.keys.clone();
        tokio::task::spawn_blocking(move || {
            tenbri_crypt::DataKeys::open(&keys)?
                .digest(subject.as_deref(), &content)
                .map_err(|e| match e {
                    tenbri_crypt::Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                        ApiError::new(ErrorCode::InvalidRequest, e.to_string())
                    }
                    e => ApiError::new(ErrorCode::StoreUnavailable, e.to_string()),
                })
        })
        .await
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
    }

    /// Stops readiness and ends every tail.
    pub fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Waits for the writes in flight.
    pub async fn flush(&self) {
        for lane in self.lanes.values() {
            lane.writer.flush().await;
        }
    }
}

impl Lane {
    async fn open(
        name: &str,
        sc: &StreamConfig,
        store: AnyStore,
        keys: &Path,
        index_root: &Path,
        config: LaneConfig,
    ) -> Result<Lane, String> {
        let head = store
            .get("HEAD")
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no stream here (run tenbri init)")?;
        let (head, _) = Head::parse(&head.bytes).map_err(|e| e.to_string())?;
        let ks = if tenbri_store::is_url(&sc.path) {
            KeyStore::open_for_object_store(keys, &head.stream)
        } else {
            KeyStore::open(keys, Path::new(&sc.path), &head.stream)
        }
        .map_err(|e| e.to_string())?;
        let pin = match &sc.key {
            Some(k) => pin(k)?,
            // As `tenbri append` does: the genesis key as this machine holds it.
            None => ks
                .list()
                .map_err(|e| e.to_string())?
                .iter()
                .filter(|m| m.role == Role::Stream)
                .filter_map(|m| sign::decode_key(&m.public).ok())
                .find(|k| sign::stream_id(k) == head.stream)
                .map(|k| sign::fingerprint(&k))
                .ok_or_else(|| {
                    format!(
                        "no `key` configured and no stream key for {} in {}",
                        head.stream,
                        ks.dir().display()
                    )
                })?,
        };
        let mut writer = Writer::open(store.clone(), Some(&pin))
            .await
            .map_err(|e| e.to_string())?
            .with_checkpoints(Some(ks.dir().join(CHECKPOINT_FILE)))
            .await
            .map_err(|e| e.to_string())?;
        let writable = match writer.use_keys(ks.clone()).await {
            Ok(()) => true,
            Err(e) => {
                eprintln!("tenbrid: stream {name}: not writable: {e}");
                false
            }
        };
        // One store per stream for the life of the process; the reader borrows it.
        let leaked: &'static AnyStore = Box::leak(Box::new(store.clone()));
        let query_index =
            tenbri_index::open(sc.index, &tenbri_index::dir_for(index_root, &head.stream))
                .map_err(|e| format!("index: {e}"))?;
        let lane = Lane {
            name: name.to_owned(),
            id: head.stream,
            pin: pin.clone(),
            replicated: matches!(store, AnyStore::Bucket(_)),
            store,
            writer: tenbri_writer::Lane::spawn(writer, config),
            reader: Mutex::new(Reader::new(leaked, Some(&pin))),
            index: RwLock::default(),
            query_index: std::sync::Mutex::new(query_index),
            tx: broadcast::channel(TAIL_BUFFER).0,
            writable: AtomicBool::new(writable),
            keys: ks,
        };
        lane.sync().await.map_err(|e| e.to_string())?;
        // The query index is rebuilt from the stream just read and verified: whatever the file
        // held before (an older run's rows, or rows someone edited) is never trusted.
        let seq = lane.index.read().expect("index lock").entries.len() as u64;
        let checkpoint = tenbri_index::latest_checkpoint(&lane.store, seq)
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut qx = lane.query_index.lock().expect("query index lock");
            let ix = lane.index.read().expect("index lock");
            qx.clear()
                .and_then(|()| lane.feed(qx.as_mut(), &ix, checkpoint))
                .map_err(|e| format!("index: {e}"))?;
        }
        Ok(lane)
    }

    /// Turns a request's draft into the entry to write: kind and phase from the operation, the
    /// id from the idempotency key, the principal bound to the token, defaults filled.
    fn prepare(
        &self,
        token: &Token,
        op: Op,
        key: Option<&str>,
        value: canon::Value,
        earlier: &[Entry],
    ) -> Result<Entry, ApiError> {
        let invalid = |m: String| ApiError::new(ErrorCode::InvalidRequest, m);
        let canon::Value::Obj(mut members) = value else {
            return Err(invalid("a draft is a JSON object".into()));
        };
        let mut set = |k: &str, v: &str| -> Result<(), ApiError> {
            match members.iter().find(|(m, _)| m == k) {
                None => {
                    members.push((k.into(), canon::Value::Str(v.into())));
                    Ok(())
                }
                Some((_, canon::Value::Str(s))) if s == v => Ok(()),
                Some(_) => Err(invalid(format!("`{k}` must be \"{v}\" here, or absent"))),
            }
        };
        match op {
            Op::Intent => (set("kind", "decision")?, set("phase", "intent")?).0,
            Op::Outcome => (set("kind", "decision")?, set("phase", "outcome")?).0,
            Op::Approval => set("kind", "approval")?,
            Op::Batch => {}
        }
        if let Some(key) = key {
            set("id", key).map_err(|_| invalid("`id` differs from the Idempotency-Key".into()))?;
        }
        let mut e = draft_from_json(&canon::to_vec(&canon::Value::Obj(members)))?;
        if encoding::parse_ulid(&e.id).is_none() {
            return Err(invalid(format!(
                "the idempotency key (the entry id) must be a ULID, not \"{}\"",
                e.id
            )));
        }
        if matches!(e.kind, Kind::Key | Kind::Reconcile) {
            return Err(ApiError::new(
                ErrorCode::InvalidEntry,
                "key and reconcile entries are written by tenbri and tenbrid themselves",
            ));
        }
        if e.kind == Kind::Decision {
            e.source.get_or_insert(Source::Sdk);
        }
        if e.phase == Some(Phase::Intent) {
            // On an object store every write is replicated, so `local` is kept too; on local
            // disk nothing is replicated.
            let tier = if self.replicated {
                Durability::Replicated
            } else {
                Durability::Local
            };
            match *e.durability.get_or_insert(tier) {
                Durability::Local => {}
                Durability::Replicated if self.replicated => {}
                d => {
                    let here = if self.replicated {
                        "tenbrid has no postgres tier"
                    } else {
                        "this stream is on local disk"
                    };
                    return Err(ApiError::new(
                        ErrorCode::InvalidEntry,
                        format!("durability {d:?} is not available: {here}"),
                    ));
                }
            }
        }
        if e.phase == Some(Phase::Outcome) {
            // Like Writer::outcome: what the intent said, unless the draft says it.
            let ix = self.index.read().expect("index lock");
            let intent = e.intent.as_deref().and_then(|id| {
                earlier
                    .iter()
                    .find(|x| x.id == id)
                    .or_else(|| ix.ids.get(id).map(|&i| &ix.entries[i].entry))
            });
            if let Some(i) = intent {
                e.principal = e.principal.or_else(|| i.principal.clone());
                e.action = e.action.or_else(|| i.action.clone());
                e.subject = e.subject.or_else(|| i.subject.clone());
                e.source = e.source.or(i.source);
            }
        }
        match &e.principal {
            Some(p) if *p != token.principal => {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    "the entry's principal is not the token's",
                ));
            }
            Some(_) => {}
            None if matches!(e.kind, Kind::Decision | Kind::Approval) => {
                e.principal = Some(token.principal.clone());
            }
            None => {}
        }
        Ok(e)
    }

    /// Replays, schema checks, then the writes through the lane, then the read-back.
    async fn write(
        &self,
        drafts: Vec<Entry>,
        schemas: Option<&Schemas>,
        trace: Option<Trace>,
    ) -> Result<Vec<Appended>, ApiError> {
        // The same id again: the original entry if the draft is the same, else a conflict.
        let mut done: Vec<Option<Appended>> = vec![];
        let mut seen = HashSet::new();
        for d in &drafts {
            if !seen.insert(d.id.as_str()) {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!("id {} appears twice in the batch", d.id),
                ));
            }
            done.push(self.replay(d)?);
        }
        let mut warnings = vec![];
        for (d, _) in drafts.iter().zip(&done).filter(|(_, r)| r.is_none()) {
            let c = schemas.map(|s| s.check(d)).unwrap_or_default();
            if !c.violations.is_empty() {
                let message = c
                    .violations
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>();
                return Err(ApiError {
                    violations: c
                        .violations
                        .into_iter()
                        .map(|v| Violation {
                            path: v.path,
                            message: v.message,
                        })
                        .collect(),
                    ..ApiError::new(
                        ErrorCode::SchemaViolation,
                        format!("entry {}: {}", d.id, message.join("; ")),
                    )
                });
            }
            warnings.push(c.warnings);
        }
        if done.iter().all(Option::is_some) {
            return Ok(done.into_iter().flatten().collect());
        }

        let new: Vec<Entry> = drafts
            .into_iter()
            .zip(&done)
            .filter(|(_, r)| r.is_none())
            // After the replay check, as `same` takes the stored trace for a draft without one:
            // a retry comes with a new span.
            .map(|(mut d, _)| {
                if d.trace.is_none() {
                    d.trace.clone_from(&trace);
                }
                d
            })
            .collect();
        let n = new.len();
        let results = self.writer.append_batch(new.clone()).await;
        // Whatever reached storage is read back, checked and indexed, failure or not.
        let synced = self.sync().await;
        let failed = results.iter().any(|r| {
            matches!(r, Err(e) if !matches!(e, WriteError::Rejected(_) | WriteError::Backpressure))
        });
        self.writable
            .store(synced.is_ok() && !failed, Ordering::Relaxed);
        synced?;
        let written = results.iter().filter(|r| r.is_ok()).count();
        let mut out = vec![];
        for (d, r) in new.iter().zip(results) {
            out.push(match r {
                Ok(e) => {
                    let ix = self.index.read().expect("index lock");
                    let stored = ix.ids.get(&e.id).map(|&i| ix.entries[i].clone());
                    Appended {
                        stored: stored.ok_or_else(|| {
                            ApiError::new(ErrorCode::Internal, format!("{} not read back", e.id))
                        })?,
                        replayed: false,
                        warnings: vec![],
                    }
                }
                // Written meanwhile by a concurrent request with the same id.
                Err(WriteError::Rejected(e)) if e.code == Code::DuplicateId => {
                    match self.replay(d)? {
                        Some(a) => a,
                        None => return Err(WriteError::Rejected(e).into()),
                    }
                }
                Err(e) => {
                    let mut err = ApiError::from(e);
                    if n > 1 && written > 0 {
                        err.message = format!(
                            "{} ({written} of {n} new entries were written; retrying the batch is safe)",
                            err.message
                        );
                    }
                    return Err(err);
                }
            });
        }
        let mut warnings = warnings.into_iter();
        let mut out = out.into_iter();
        Ok(done
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| {
                    let mut a = out.next().expect("one result per new draft");
                    a.warnings = warnings.next().unwrap_or_default();
                    a
                })
            })
            .collect())
    }

    /// The entry already written with `d`'s id: the same draft is a replay, another a conflict.
    fn replay(&self, d: &Entry) -> Result<Option<Appended>, ApiError> {
        let ix = self.index.read().expect("index lock");
        match ix.ids.get(&d.id).map(|&i| ix.entries[i].clone()) {
            Some(s) if same(d, &s.entry) => Ok(Some(Appended {
                stored: s,
                replayed: true,
                warnings: vec![],
            })),
            Some(_) => Err(ApiError::new(
                ErrorCode::IdempotencyConflict,
                format!("id {} was used for a different entry", d.id),
            )),
            None => Ok(None),
        }
    }

    /// Reads what HEAD has that the index does not, checking it, and publishes it to tails.
    async fn sync(&self) -> Result<(), ApiError> {
        let mut reader = self.reader.lock().await;
        let new = reader.poll().await;
        let mut ix = self.index.write().expect("index lock");
        let new = match new {
            Ok(new) => new,
            Err(tenbri_writer::ReadError::Broken(b)) => {
                ix.broken_from = Some(b.seq);
                return Err(WriteError::Broken(b).into());
            }
            Err(e) => return Err(e.into()),
        };
        for e in new {
            let line = String::from_utf8(canon::to_vec(
                &canon::from_serialize(&e).expect("a stored entry"),
            ))
            .expect("canonical JSON is UTF-8");
            let hash = sign::entry_hash(line.as_bytes());
            let s = Arc::new(Stored {
                entry: e,
                line,
                hash,
            });
            let n = ix.entries.len();
            ix.ids.insert(s.entry.id.clone(), n);
            ix.entries.push(s.clone());
            let _ = self.tx.send(s);
        }
        ix.broken_from = reader.chain().invalidated().map(|b| b.seq);
        Ok(())
    }
}

impl Lane {
    /// Brings the query index up to the entries in `ix`, starting over if it holds anything else.
    fn feed(
        &self,
        qx: &mut dyn tenbri_index::Backend,
        ix: &Index,
        checkpoint: Option<u64>,
    ) -> std::io::Result<()> {
        let state = qx.state()?;
        let mut from = state.as_ref().map_or(0, |s| s.seq as usize);
        let agrees = |s: &tenbri_index::State| {
            s.stream == self.id
                && (1..=ix.entries.len()).contains(&from)
                && ix.entries[from - 1].hash == s.hash
        };
        if state.as_ref().is_some_and(|s| !agrees(s)) {
            qx.clear()?;
            from = 0;
        }
        let new = &ix.entries[from..];
        let same = state.is_some_and(|s| from > 0 && s.checkpoint == checkpoint);
        if ix.entries.is_empty() || (new.is_empty() && same) {
            return Ok(());
        }
        let mut chunks: Vec<&[Arc<Stored>]> = new.chunks(50_000).collect();
        if chunks.is_empty() {
            // Only the checkpoint moved.
            chunks.push(&[]);
        }
        let mut seq = from;
        for chunk in chunks {
            seq += chunk.len();
            let rows: Vec<tenbri_index::Row> = chunk
                .iter()
                .map(|s| tenbri_index::Row::new(&s.entry, &s.line))
                .collect();
            let state = tenbri_index::State {
                stream: self.id.clone(),
                seq: seq as u64,
                hash: ix.entries[seq - 1].hash.clone(),
                checkpoint,
            };
            tenbri_index::append(qx, rows, &state)?;
        }
        Ok(())
    }
}

impl Index {
    fn verification(&self, seq: u64) -> Verification {
        match self.broken_from {
            Some(b) if seq >= b => Verification::Broken,
            _ => Verification::Verified,
        }
    }
}

/// Whether `draft` is the entry the writer made of it: equal but for what the writer filled.
fn same(draft: &Entry, stored: &Entry) -> bool {
    let mut d = draft.clone();
    d.v = stored.v;
    d.stream.clone_from(&stored.stream);
    d.seq = stored.seq;
    d.prev.clone_from(&stored.prev);
    d.signer.clone_from(&stored.signer);
    d.sig.clone_from(&stored.sig);
    if d.ts.is_empty() {
        d.ts.clone_from(&stored.ts);
    }
    if d.trace.is_none() {
        d.trace.clone_from(&stored.trace);
    }
    d == *stored
}

/// Timestamps the store's latest checkpoint unless it already has a token; the token's key.
async fn anchor(store: &AnyStore, url: &str) -> std::io::Result<Option<String>> {
    let Some((size, note)) = tenbri_writer::latest_checkpoint(store).await? else {
        return Ok(None);
    };
    let key = checkpoint::anchor_key(size);
    if store.get(&key).await?.is_some() {
        return Ok(None);
    }
    let note = tenbri_merkle::Note::parse(&note).map_err(std::io::Error::other)?;
    let tsr = tenbri_anchor::timestamp(url, note.text().as_bytes()).await?;
    store.put_if_absent(&key, &tsr).await?;
    Ok(Some(key))
}

/// A `key` value as a fingerprint: `sha256:…` as given, or the fingerprint of `ed25519:…`.
fn pin(s: &str) -> Result<String, String> {
    if encoding::prefixed::<32>(s, "sha256:").is_some() {
        return Ok(s.to_owned());
    }
    sign::decode_key(s)
        .map(|k| sign::fingerprint(&k))
        .map_err(|_| format!("key {s}: expected sha256:<64 hex> or ed25519:<64 hex>"))
}

/// Serves REST on `rest` and gRPC on `grpc` until `shutdown` resolves, then stops accepting,
/// ends tails, lets requests in flight finish and waits for their writes.
pub async fn serve(
    daemon: Arc<Daemon>,
    rest: TcpListener,
    grpc: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let stop = || {
        let mut rx = daemon.shutdown.subscribe();
        async move {
            let _ = rx.wait_for(|s| *s).await;
        }
    };
    let rest = tokio::spawn(rest::serve(daemon.clone(), rest, stop()));
    let grpc = tokio::spawn(grpc::serve(daemon.clone(), grpc, stop()));
    shutdown.await;
    daemon.begin_shutdown();
    let (r, g) = (rest.await, grpc.await);
    daemon.flush().await;
    r.map_err(std::io::Error::other)??;
    g.map_err(std::io::Error::other)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenbri_keys::{Backend, Key, SESSION_LIFETIME_MS};
    use tenbri_store::Bucket;
    use tenbri_store::object_store::memory::InMemory;
    use tenbri_writer::{new_id, now_ms};

    async fn append(d: &Daemon, op: Op, body: &str) -> Result<Appended, ApiError> {
        let t = d.authenticate(Some("Bearer t")).unwrap();
        d.append(
            &t,
            "s",
            op,
            Some(&new_id(now_ms()).unwrap()),
            body.as_bytes(),
            None,
        )
        .await
    }

    /// tenbrid on an in-memory bucket, an object store with S3's conditional-write answers:
    /// replicated intents, group commit across requests, checkpoints, verify.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn on_an_object_store() {
        let dir = std::env::temp_dir().join(format!("tenbrid-unit-bucket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bucket = Bucket::new(Arc::new(InMemory::new()), "audit")
            .await
            .unwrap();
        let stream_key = Key::new_stream().unwrap();
        let id = sign::stream_id(&stream_key.signing.verifying_key());
        let ks = KeyStore::open_for_object_store(&dir.join("keys"), &id).unwrap();
        ks.save(&stream_key, Backend::File).unwrap();
        let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
        Writer::create(bucket.clone(), &stream_key, session)
            .await
            .unwrap();
        let config = format!(
            "keys = \"keys\"\n[streams.s]\npath = \"s3://bucket/audit\"\n\
             [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"a\" }}",
            sign::sha256(b"t")
        );
        let config = Config::parse(&config, &dir, |_| None).unwrap();
        let stores = BTreeMap::from([("s".to_owned(), AnyStore::Bucket(bucket.clone()))]);
        let d = Arc::new(Daemon::with_stores(&config, stores).await.unwrap());
        // No session key was saved: tenbrid certified one with the stream key it holds.
        assert!(d.ready());

        // Intents are replicated unless they ask for less; there is no postgres tier.
        let intent = r#"{"action":{"type":"x"}}"#;
        let a = append(&d, Op::Intent, intent).await.unwrap();
        assert_eq!(a.stored.entry.durability, Some(Durability::Replicated));
        let local = r#"{"durability":"local","action":{"type":"x"}}"#;
        assert!(append(&d, Op::Intent, local).await.is_ok());
        let pg = r#"{"durability":"postgres","action":{"type":"x"}}"#;
        let e = append(&d, Op::Intent, pg).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidEntry);

        // Concurrent requests share batches.
        let tasks: Vec<_> = (0..100)
            .map(|_| {
                let d = d.clone();
                tokio::spawn(async move { append(&d, Op::Batch, r#"{"kind":"note"}"#).await })
            })
            .collect();
        for t in tasks {
            assert!(!t.await.unwrap().unwrap().replayed);
        }
        let entries = d
            .verify(&d.authenticate(Some("Bearer t")).unwrap(), "s")
            .await
            .unwrap();
        let batches = bucket.list("batches/").await.unwrap().len() as u64;
        assert!(batches < entries.entries / 2, "{batches} batches");

        // 1,000 more: a checkpoint, in the bucket and kept with the keys.
        let t = d.authenticate(Some("Bearer t")).unwrap();
        let drafts = (0..1000)
            .map(|_| {
                let id = new_id(now_ms()).unwrap();
                canon::parse(format!(r#"{{"kind":"note","id":"{id}"}}"#).as_bytes()).unwrap()
            })
            .collect();
        assert_eq!(
            d.append_batch(&t, "s", drafts, None).await.unwrap().len(),
            1000
        );
        assert_eq!(bucket.list("checkpoints/").await.unwrap().len(), 1);
        assert!(ks.dir().join(CHECKPOINT_FILE).exists());
        let v = d.verify(&t, "s").await.unwrap();
        assert_eq!((v.broken, v.entries), (None, entries.entries + 1000));

        d.begin_shutdown();
        assert!(!d.ready());
        d.flush().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn error_codes_map_to_http_and_grpc() {
        for (c, http, grpc) in [
            (
                ErrorCode::SchemaViolation,
                422,
                tonic::Code::InvalidArgument,
            ),
            (
                ErrorCode::IdempotencyConflict,
                409,
                tonic::Code::AlreadyExists,
            ),
            (
                ErrorCode::DeadlineExceeded,
                503,
                tonic::Code::ResourceExhausted,
            ),
            (ErrorCode::StoreUnavailable, 503, tonic::Code::Unavailable),
            (ErrorCode::StreamBroken, 500, tonic::Code::DataLoss),
        ] {
            assert_eq!((c.http_status(), c.grpc_code()), (http, grpc), "{c:?}");
        }
        assert!(ErrorCode::DeadlineExceeded.retry() && !ErrorCode::SchemaViolation.retry());
    }
}
