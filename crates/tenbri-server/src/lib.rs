//! tenbrid: the Tenbri REST and gRPC API.
//!
//! One [`Daemon`] holds a writer per configured stream (a lane) and serves the same operations
//! over REST (`/v1`, [`openapi_yaml`]) and gRPC (`tenbri.v1.TenbriService`, [`proto`]): append
//! intents, outcomes, approvals and batches; get, query and tail entries; verify a stream; list
//! the action schemas; health and readiness.
//!
//! - Every write carries an idempotency key, the entry id: the same key and draft return the
//!   original entry, the same key with another draft is `TENBRI_IDEMPOTENCY_CONFLICT`.
//! - Every append is checked against the format and the action schemas before it is written, and
//!   returns once it is durable. Entries are read back from storage and verified before they are
//!   served.
//! - Each stream has a bounded queue; an append waits for it up to the deadline, then fails
//!   with `TENBRI_DEADLINE_EXCEEDED` (backpressure).
//! - Every request but health checks needs a bearer token, bound to one principal.
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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::{Stream, StreamExt, stream};
use tenbri_core::{
    Durability, Entry, Head, Kind, Phase, Principal, Role, Source, canon, encoding, sign,
};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_schema::Schemas;
use tenbri_store::{LocalStore, Store};
use tenbri_writer::{RECONCILE_AFTER_MS, Reader, WriteError, Writer, draft_from_json, now_ms};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, broadcast, watch};
use tokio_stream::wrappers::BroadcastStream;

pub use config::{Config, StreamConfig, TokenConfig};
pub use error::{ApiError, ErrorBody, ErrorCode, Violation};
pub use rest::openapi_yaml;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The most entries one batch may hold.
pub const MAX_BATCH: usize = 1000;

/// How many new entries a tail may fall behind before it is ended with `TENBRI_TAIL_LAGGED`.
const TAIL_BUFFER: usize = 1024;

/// A session key is replaced when it has less than this left.
const SESSION_MARGIN_MS: i64 = 60_000;

/// The caller, from its bearer token.
#[derive(Clone, Debug)]
pub struct Token {
    pub principal: Principal,
    /// Stream names it may use; `None`: all.
    pub streams: Option<Vec<String>>,
}

/// An entry as stored, with its canonical JSON.
#[derive(Debug)]
pub struct Stored {
    pub entry: Entry,
    pub line: String,
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

/// Filters for [`Daemon::query`]; empty ones match everything.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// (ref, version) pairs; all must be among the entry's inputs.
    pub inputs: Vec<(String, String)>,
    pub action: Option<String>,
    /// `kind:id`.
    pub principal: Option<String>,
    pub target: Option<String>,
    pub subject: Option<String>,
    pub after_seq: u64,
    /// 0 means 100; capped at 1000.
    pub limit: usize,
}

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
    path: PathBuf,
    pin: String,
    keys: KeyStore,
    queue: Arc<Semaphore>,
    io: Arc<Mutex<LaneIo>>,
    index: RwLock<Index>,
    tx: broadcast::Sender<Arc<Stored>>,
    writable: AtomicBool,
}

struct LaneIo {
    writer: Writer<LocalStore>,
    /// Reads back what was written, checking it, to feed the index.
    reader: Reader<'static, LocalStore>,
}

/// ponytail: every entry in memory, by position (`seq - 1`) and id; tenbri-index (SQLite or
/// Parquet) when streams outgrow memory.
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
    deadline: Duration,
    shutdown: watch::Sender<bool>,
}

impl Daemon {
    /// Opens every configured stream, checks it from genesis against its pin, and makes sure it
    /// has a session key.
    pub async fn open(config: &Config) -> Result<Daemon, String> {
        let schemas = match &config.schema {
            Some(p) => Some(Arc::new(Schemas::load(p)?)),
            None => None,
        };
        let keys = config
            .keys
            .clone()
            .or_else(tenbri_keys::default_dir)
            .ok_or("no keys directory: set keys or TENBRI_KEYS")?;
        let mut lanes = BTreeMap::new();
        for (name, sc) in &config.streams {
            let lane = Lane::open(name, sc, &keys, config.queue)
                .await
                .map_err(|e| format!("stream {name} ({}): {e}", sc.path.display()))?;
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
            deadline: Duration::from_millis(config.deadline_ms),
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

    /// Appends one draft (a JSON object). `key` is the Idempotency-Key, the entry id.
    pub async fn append(
        &self,
        token: &Token,
        stream: &str,
        op: Op,
        key: Option<&str>,
        draft: &[u8],
    ) -> Result<Appended, ApiError> {
        let key = key.ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "an Idempotency-Key is required: the entry id, a ULID",
            )
        })?;
        let value = canon::parse(draft)?;
        let mut out = self
            .commit(token, stream, op, vec![(Some(key), value)])
            .await?;
        Ok(out.remove(0))
    }

    /// Appends drafts in order, each with its own `id`. Every draft is checked before any is
    /// written; a storage failure part-way leaves the earlier ones written, and retrying the
    /// whole batch is safe.
    pub async fn append_batch(
        &self,
        token: &Token,
        stream: &str,
        drafts: Vec<canon::Value>,
    ) -> Result<Vec<Appended>, ApiError> {
        if drafts.is_empty() || drafts.len() > MAX_BATCH {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                format!("a batch holds 1 to {MAX_BATCH} entries"),
            ));
        }
        let drafts = drafts.into_iter().map(|d| (None, d)).collect();
        self.commit(token, stream, Op::Batch, drafts).await
    }

    async fn commit(
        &self,
        token: &Token,
        stream: &str,
        op: Op,
        drafts: Vec<(Option<&str>, canon::Value)>,
    ) -> Result<Vec<Appended>, ApiError> {
        let lane = self.lane(token, stream)?.clone();
        let mut entries: Vec<Entry> = vec![];
        for (key, value) in drafts {
            let e = lane.prepare(token, op, key, value, &entries)?;
            entries.push(e);
        }
        // Backpressure: wait for room in the queue, then for the writer, up to the deadline.
        let deadline = tokio::time::Instant::now() + self.deadline;
        let busy = || {
            ApiError::new(
                ErrorCode::DeadlineExceeded,
                format!(
                    "stream {stream} is busy: no room in its queue within {} ms",
                    self.deadline.as_millis()
                ),
            )
        };
        let n = u32::try_from(entries.len()).expect("a batch is at most MAX_BATCH");
        let permit = tokio::time::timeout_at(deadline, lane.queue.clone().acquire_many_owned(n))
            .await
            .map_err(|_| busy())?
            .expect("the queue is never closed");
        let io = tokio::time::timeout_at(deadline, lane.io.clone().lock_owned())
            .await
            .map_err(|_| busy())?;
        // Spawned, so a client that goes away cannot cancel a write half-way.
        let schemas = self.schemas.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut io = io;
            lane.write(&mut io, entries, schemas.as_deref()).await
        })
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

    /// Matching entries in sequence order, and the `after_seq` of the next page if there is one.
    pub fn query(
        &self,
        token: &Token,
        stream: &str,
        q: &Query,
    ) -> Result<(Vec<Found>, Option<u64>), ApiError> {
        let lane = self.lane(token, stream)?;
        let limit = match q.limit {
            0 => 100,
            n => n.min(1000),
        };
        let ix = lane.index.read().expect("index lock");
        let start = usize::try_from(q.after_seq)
            .unwrap_or(usize::MAX)
            .min(ix.entries.len());
        let mut out: Vec<_> = ix.entries[start..]
            .iter()
            .filter(|s| q.matches(&s.entry))
            .take(limit + 1)
            .map(|s| (s.clone(), ix.verification(s.entry.seq)))
            .collect();
        let next = (out.len() > limit).then(|| {
            out.truncate(limit);
            out[limit - 1].0.entry.seq
        });
        Ok((out, next))
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

    /// Reads the stream from storage and checks all of it against its pinned key.
    pub async fn verify(&self, token: &Token, stream: &str) -> Result<Verified, ApiError> {
        let lane = self.lane(token, stream)?;
        let r = tenbri_writer::verify(&LocalStore::open(&lane.path)?, Some(&lane.pin)).await?;
        Ok(Verified {
            stream: lane.id.clone(),
            entries: r.entries,
            pinned_key: lane.pin.clone(),
            broken: r.broken,
        })
    }

    /// Stops readiness and ends every tail.
    pub fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Waits for the writes in flight.
    pub async fn flush(&self) {
        for lane in self.lanes.values() {
            drop(lane.io.lock().await);
        }
    }
}

impl Lane {
    async fn open(
        name: &str,
        sc: &StreamConfig,
        keys: &Path,
        queue: usize,
    ) -> Result<Lane, String> {
        let store = LocalStore::open(&sc.path).map_err(|e| e.to_string())?;
        let head = store
            .get("HEAD")
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no stream here (run tenbri init)")?;
        let (head, _) = Head::parse(&head.bytes).map_err(|e| e.to_string())?;
        let ks = KeyStore::open(keys, &sc.path, &head.stream).map_err(|e| e.to_string())?;
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
        let writer = Writer::open(store.clone(), Some(&pin))
            .await
            .map_err(|e| e.to_string())?;
        // One store per stream for the life of the process; the reader borrows it.
        let leaked: &'static LocalStore = Box::leak(Box::new(store));
        let lane = Lane {
            name: name.to_owned(),
            id: head.stream,
            path: sc.path.clone(),
            pin: pin.clone(),
            keys: ks,
            queue: Arc::new(Semaphore::new(queue)),
            io: Arc::new(Mutex::new(LaneIo {
                writer,
                reader: Reader::new(leaked, Some(&pin)),
            })),
            index: RwLock::default(),
            tx: broadcast::channel(TAIL_BUFFER).0,
            writable: AtomicBool::new(false),
        };
        {
            let mut io = lane.io.lock().await;
            lane.sync(&mut io).await.map_err(|e| e.to_string())?;
            match lane.ensure_session(&mut io.writer).await {
                Ok(()) => lane.writable.store(true, Ordering::Relaxed),
                Err(e) => eprintln!("tenbrid: stream {name}: not writable: {e}"),
            }
            lane.sync(&mut io).await.map_err(|e| e.to_string())?;
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
            // ponytail: local disk is the only tier until tenbrid writes to object stores.
            match e.durability.get_or_insert(Durability::Local) {
                Durability::Local => {}
                d => {
                    return Err(ApiError::new(
                        ErrorCode::InvalidEntry,
                        format!(
                            "durability {d:?} is not available: this tenbrid writes to local disk"
                        ),
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

    /// Under the lane's lock: replays, schema checks, then the writes, then the read-back.
    async fn write(
        &self,
        io: &mut LaneIo,
        drafts: Vec<Entry>,
        schemas: Option<&Schemas>,
    ) -> Result<Vec<Appended>, ApiError> {
        // The same id again: the original entry if the draft is the same, else a conflict.
        let mut done: Vec<Option<Appended>> = vec![];
        let mut seen = HashSet::new();
        {
            let ix = self.index.read().expect("index lock");
            for d in &drafts {
                if !seen.insert(d.id.as_str()) {
                    return Err(ApiError::new(
                        ErrorCode::InvalidRequest,
                        format!("id {} appears twice in the batch", d.id),
                    ));
                }
                done.push(match ix.ids.get(&d.id).map(|&i| ix.entries[i].clone()) {
                    Some(s) if same(d, &s.entry) => Some(Appended {
                        stored: s,
                        replayed: true,
                        warnings: vec![],
                    }),
                    Some(_) => {
                        return Err(ApiError::new(
                            ErrorCode::IdempotencyConflict,
                            format!("id {} was used for a different entry", d.id),
                        ));
                    }
                    None => None,
                });
            }
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

        let result = self.write_new(io, &drafts, &done).await;
        // Whatever reached storage is read back, checked and indexed, failure or not.
        let synced = self.sync(io).await;
        self.writable
            .store(result.is_ok() && synced.is_ok(), Ordering::Relaxed);
        let written = result?;
        synced?;
        let ix = self.index.read().expect("index lock");
        let mut warnings = warnings.into_iter();
        let mut written = written.into_iter();
        Ok(done
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| {
                    let id = written.next().expect("one id per new draft");
                    Appended {
                        stored: ix.entries[ix.ids[&id]].clone(),
                        replayed: false,
                        warnings: warnings.next().unwrap_or_default(),
                    }
                })
            })
            .collect())
    }

    /// Writes the drafts not replayed; returns their ids.
    async fn write_new(
        &self,
        io: &mut LaneIo,
        drafts: &[Entry],
        done: &[Option<Appended>],
    ) -> Result<Vec<String>, ApiError> {
        let w = &mut io.writer;
        self.ensure_session(w).await?;
        let keep = drafts.iter().find_map(|d| d.intent.as_deref());
        w.reconcile_stale(now_ms(), RECONCILE_AFTER_MS, keep)
            .await?;
        let new: Vec<&Entry> = drafts
            .iter()
            .zip(done)
            .filter(|(_, r)| r.is_none())
            .map(|(d, _)| d)
            .collect();
        let mut ids = vec![];
        for d in &new {
            match w.append((*d).clone()).await {
                Ok(e) => ids.push(e.id),
                Err(e) if new.len() > 1 && !ids.is_empty() => {
                    let mut err = ApiError::from(e);
                    err.message = format!(
                        "{} ({} of {} new entries were written; retrying the batch is safe)",
                        err.message,
                        ids.len(),
                        new.len()
                    );
                    return Err(err);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(ids)
    }

    /// Reads what HEAD has that the index does not, checking it, and publishes it to tails.
    async fn sync(&self, io: &mut LaneIo) -> Result<(), ApiError> {
        let new = io.reader.poll().await;
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
            let s = Arc::new(Stored { entry: e, line });
            let n = ix.entries.len();
            ix.ids.insert(s.entry.id.clone(), n);
            ix.entries.push(s.clone());
            let _ = self.tx.send(s);
        }
        ix.broken_from = io.reader.chain().invalidated().map(|b| b.seq);
        Ok(())
    }

    /// Signs with a stored session key valid for at least another minute, else certifies a new
    /// one with the stream key, if this machine holds it.
    ///
    /// ponytail: the same steps as `tenbri append`; move both into tenbri-writer once its
    /// alpha.2 API settles.
    async fn ensure_session(&self, w: &mut Writer<LocalStore>) -> Result<(), WriteError> {
        let now = now_ms();
        if w.session()
            .is_some_and(|s| s.valid_at(now + SESSION_MARGIN_MS))
        {
            return Ok(());
        }
        let metas = self.keys.list()?;
        let mut sessions: Vec<_> = metas.iter().filter(|m| m.role == Role::Session).collect();
        sessions.sort_by(|a, b| b.not_after.cmp(&a.not_after));
        for m in sessions {
            if let Ok(k) = self.keys.load(&m.id) {
                if k.valid_at(now + SESSION_MARGIN_MS) && w.use_session(k).is_ok() {
                    return Ok(());
                }
            }
        }
        let current = w
            .chain()
            .stream_key()
            .ok_or_else(|| WriteError::NoSession("the stream has no stream key".into()))?
            .to_owned();
        let stream_key = self.keys.load(&current).map_err(|e| {
            WriteError::NoSession(format!(
                "no usable session key, and the stream key {current} is not in {}: {e}",
                self.keys.dir().display()
            ))
        })?;
        let session = Key::new_session(now, SESSION_LIFETIME_MS)?;
        let backend = metas
            .iter()
            .find(|m| m.id == current)
            .map_or(Backend::File, |m| m.backend);
        self.keys.save(&session, backend)?;
        w.certify_session(&stream_key, session).await?;
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

impl Query {
    fn matches(&self, e: &Entry) -> bool {
        let has = |(r, v): &(String, String)| {
            e.inputs
                .iter()
                .flatten()
                .any(|i| &i.r#ref == r && &i.version == v)
        };
        let action = e.action.as_ref();
        self.inputs.iter().all(has)
            && self
                .action
                .as_ref()
                .is_none_or(|a| action.is_some_and(|x| &x.r#type == a))
            && self
                .target
                .as_ref()
                .is_none_or(|t| action.and_then(|x| x.target.as_ref()) == Some(t))
            && self
                .subject
                .as_ref()
                .is_none_or(|s| e.subject.as_ref() == Some(s))
            && self.principal.as_ref().is_none_or(|p| {
                e.principal.as_ref().is_some_and(|x| {
                    serde_json::to_value(x.kind)
                        .ok()
                        .and_then(|k| k.as_str().map(str::to_owned))
                        .is_some_and(|k| *p == format!("{k}:{}", x.id))
                })
            })
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
    d == *stored
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

    async fn daemon(name: &str) -> (Daemon, PathBuf) {
        let dir = std::env::temp_dir().join(format!("tenbrid-unit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("audit");
        std::fs::create_dir_all(&path).unwrap();
        let stream_key = Key::new_stream().unwrap();
        let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
        let id = sign::stream_id(&stream_key.signing.verifying_key());
        let ks = KeyStore::open(&dir.join("keys"), &path, &id).unwrap();
        ks.save(&stream_key, Backend::File).unwrap();
        Writer::create(LocalStore::open(&path).unwrap(), &stream_key, session)
            .await
            .unwrap();
        let config = format!(
            "keys = \"keys\"\nqueue = 2\ndeadline_ms = 50\n[streams.s]\npath = \"audit\"\n\
             [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"a\" }}",
            sign::sha256(b"t")
        );
        let config = Config::parse(&config, &dir, |_| None).unwrap();
        (Daemon::open(&config).await.unwrap(), dir)
    }

    async fn note(d: &Daemon) -> Result<Appended, ApiError> {
        let t = d.authenticate(Some("Bearer t")).unwrap();
        let key = tenbri_writer::new_id(now_ms()).unwrap();
        d.append(&t, "s", Op::Batch, Some(&key), br#"{"kind":"note"}"#)
            .await
    }

    #[tokio::test]
    async fn backpressure_fails_after_the_deadline() {
        let (d, dir) = daemon("backpressure").await;
        // No session key was saved: tenbrid certified one with the stream key it holds.
        assert!(d.ready());
        assert!(note(&d).await.is_ok());
        // Without a tenbri.toml nothing is checked, and nothing is warned about.
        let t = d.authenticate(Some("bearer t")).unwrap();
        let key = tenbri_writer::new_id(now_ms()).unwrap();
        let a = d
            .append(
                &t,
                "s",
                Op::Intent,
                Some(&key),
                br#"{"action":{"type":"x"}}"#,
            )
            .await
            .unwrap();
        assert!(a.warnings.is_empty());
        assert_eq!(d.schemas_json(), serde_json::json!({ "actions": {} }));

        // The writer busy past the deadline.
        let lane = d.lanes["s"].clone();
        let io = lane.io.lock().await;
        let e = note(&d).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::DeadlineExceeded);
        drop(io);

        // The queue full past the deadline.
        let held = lane.queue.clone().acquire_many_owned(2).await.unwrap();
        assert_eq!(
            note(&d).await.unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
        drop(held);
        assert!(note(&d).await.is_ok(), "room again");

        // Shutdown: not ready, and flush waits for the writer.
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
