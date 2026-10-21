//! What the Python and Node packages share: one stream, opened (or created) on a directory or an
//! S3, R2 or MinIO prefix, written through a group-commit [`Lane`], verified and queried. Drafts
//! and entries cross the boundary as JSON, and every error carries one of tenbrid's stable
//! `TENBRI_*` codes, so each binding is a thin wrapper and the three APIs behave the same.
//!
//! Every method is async and needs a Tokio runtime: the lane's writer runs as a task on it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tenbri_core::{
    Code, Durability, Entry, Head, Kind, Phase, Role, Source, canon, encoding, sign,
};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_store::{AnyStore, Store};
mod remote;

pub use remote::{FORBIDDEN, INTERNAL, SCHEMA_VIOLATION, UNAUTHENTICATED};

use tenbri_writer::{
    CHECKPOINT_FILE, Lane, LaneConfig, ReadError, Reader, WriteError, Writer, draft_from_json,
    now_ms,
};

/// The draft is malformed: not a JSON object, a member that contradicts the call.
pub const INVALID_REQUEST: &str = "TENBRI_INVALID_REQUEST";
/// The entry breaks a rule of format v1; `reason` holds the format's code. Nothing was written.
pub const INVALID_ENTRY: &str = "TENBRI_INVALID_ENTRY";
/// No stream at the location, or no such intent.
pub const NOT_FOUND: &str = "TENBRI_NOT_FOUND";
/// The entry id was used before for a different entry.
pub const IDEMPOTENCY_CONFLICT: &str = "TENBRI_IDEMPOTENCY_CONFLICT";
/// Another writer holds the stream; nothing was written.
pub const WRITE_CONFLICT: &str = "TENBRI_WRITE_CONFLICT";
/// The lane's queue stayed full past the deadline; nothing was written.
pub const DEADLINE_EXCEEDED: &str = "TENBRI_DEADLINE_EXCEEDED";
/// Storage failed; the entry may not be durable. Retrying with the same id is safe.
pub const STORE_UNAVAILABLE: &str = "TENBRI_STORE_UNAVAILABLE";
/// No usable session key and no stream key to certify one: the stream is open read-only.
pub const NO_SESSION_KEY: &str = "TENBRI_NO_SESSION_KEY";
/// The stream does not verify; `reason` holds the format's code.
pub const STREAM_BROKEN: &str = "TENBRI_STREAM_BROKEN";

/// A failure, with tenbrid's code for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// One of the `TENBRI_*` constants of this crate.
    pub code: &'static str,
    pub message: String,
    /// The format v1 error code, for [`INVALID_ENTRY`] and [`STREAM_BROKEN`].
    pub reason: Option<String>,
    /// The id of the entry the call was writing: retry with it, and a write that did land is
    /// returned instead of written twice.
    pub id: Option<String>,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            reason: None,
            id: None,
        }
    }

    fn with_reason(mut self, reason: Code) -> Self {
        self.reason = Some(reason.as_str().into());
        self
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<tenbri_core::Error> for Error {
    fn from(e: tenbri_core::Error) -> Self {
        Error::new(INVALID_ENTRY, e.to_string()).with_reason(e.code)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(STORE_UNAVAILABLE, e.to_string())
    }
}

// The same mapping as tenbrid's (crates/tenbri-server/src/error.rs).
impl From<WriteError> for Error {
    fn from(e: WriteError) -> Self {
        let msg = e.to_string();
        match e {
            WriteError::Rejected(e) => e.into(),
            WriteError::Broken(b) => Error::new(STREAM_BROKEN, msg).with_reason(b.error.code),
            WriteError::Conflict { .. } => Error::new(WRITE_CONFLICT, msg),
            WriteError::NoSession(_) => Error::new(NO_SESSION_KEY, msg),
            WriteError::NoStream => Error::new(NOT_FOUND, msg),
            WriteError::Io(_) | WriteError::Closed | WriteError::Exists => {
                Error::new(STORE_UNAVAILABLE, msg)
            }
            WriteError::Backpressure => Error::new(DEADLINE_EXCEEDED, msg),
        }
    }
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        WriteError::from(e).into()
    }
}

/// A new entry id (a ULID): pass it with a draft to make retries of that append idempotent.
pub fn new_id() -> Result<String, Error> {
    Ok(tenbri_writer::new_id(now_ms())?)
}

/// The action schemas of the `tenbri.toml` at `path`, as JSON (`{"unknown_actions", "actions"}`),
/// checked as `tenbri schema check` checks them.
pub fn schemas(path: &Path) -> Result<String, Error> {
    let s = tenbri_schema::Schemas::load(path).map_err(|e| Error::new(INVALID_REQUEST, e))?;
    Ok(serde_json::to_string(&s).expect("schemas serialize"))
}

/// How to open a stream.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The keys directory; default `$TENBRI_KEYS`, else `~/.config/tenbri/keys`. Never inside the
    /// stream.
    pub keys: Option<PathBuf>,
    /// The genesis key to pin: a fingerprint (`sha256:…`) or public key (`ed25519:…`). Without
    /// it, writes trust the stream key in `keys`, and verification reports "unpinned".
    pub key: Option<String>,
    /// Create the stream and its keys if there is none at the location. Ignored for tenbrid,
    /// whose configuration names its streams.
    pub create: bool,
    /// The bearer token for a tenbrid location; default `$TENBRI_TOKEN`.
    pub token: Option<String>,
}

/// One stream, open for writing and reading: on storage this machine holds the keys of, or
/// through a tenbrid that holds them, so the process writing never sees a signing key.
pub struct Stream(Inner);

enum Inner {
    Local(Local),
    Remote(remote::Remote),
}

impl Stream {
    /// Opens the stream at `location`: a directory (or `file://` URL), `s3://bucket/prefix`,
    /// `r2://bucket/prefix` (credentials from `AWS_*`; `CLOUDFLARE_ACCOUNT_ID` for R2), or a
    /// tenbrid, `https://host[:port]/<stream>` (`http://` on loopback only) with a bearer token.
    pub async fn open(location: &str, o: Options) -> Result<Stream, Error> {
        Ok(Stream(if remote::is_remote(location) {
            Inner::Remote(remote::Remote::open(location, o.token).await?)
        } else {
            Inner::Local(Local::open(location, o).await?)
        }))
    }

    /// The stream id, `tnb1:…`.
    pub fn id(&self) -> &str {
        match &self.0 {
            Inner::Local(l) => &l.id,
            Inner::Remote(r) => r.id(),
        }
    }

    /// The genesis key's fingerprint, pinned or as this machine's keys hold it: what verifiers
    /// should pin. None through tenbrid unless pinned at open: [`Stream::verify`] reports the
    /// key tenbrid pins.
    pub fn fingerprint(&self) -> Option<&str> {
        match &self.0 {
            Inner::Local(l) => l.fingerprint.as_deref(),
            Inner::Remote(_) => None,
        }
    }

    /// Whether this stream can be written here; through tenbrid, the token decides per write.
    pub fn writable(&self) -> bool {
        match &self.0 {
            Inner::Local(l) => l.lane.lock().expect("lane lock").is_ok(),
            Inner::Remote(_) => true,
        }
    }

    /// The keyed digest of an input, `hmac-sha256:<hex>`, under the data key of `subject` (the
    /// tenant's without one), made on first use: from the local key store beside the stream's
    /// keys, or through tenbrid, which holds them. Erasing the subject's key leaves the digest
    /// unconfirmable (spec/privacy.md).
    pub async fn digest(&self, subject: Option<&str>, content: &[u8]) -> Result<String, Error> {
        match &self.0 {
            Inner::Local(l) => l.digest(subject, content),
            Inner::Remote(r) => r.digest(subject, content).await,
        }
    }

    /// Appends a draft entry (JSON object); returns it as stored (canonical JSON), once durable.
    pub async fn append(&self, draft: &[u8]) -> Result<String, Error> {
        self.put(object(draft)?).await
    }

    /// Records an intent, durable before the action runs. `kind` and `phase` may be left out.
    pub async fn intent(&self, draft: &[u8]) -> Result<String, Error> {
        let mut d = object(draft)?;
        set(&mut d, "kind", "decision")?;
        set(&mut d, "phase", "intent")?;
        self.put(d).await
    }

    /// Records the outcome of `intent` (the intent entry, or `{"id": …}`) with `status`.
    /// `principal`, `action`, `subject` and `source` default to the intent's.
    pub async fn outcome(
        &self,
        intent: &[u8],
        status: &str,
        draft: &[u8],
    ) -> Result<String, Error> {
        let intent = object(intent)?;
        let Some(Value::String(id)) = intent.get("id") else {
            return Err(Error::new(INVALID_REQUEST, "the intent has no `id`"));
        };
        let mut d = object(draft)?;
        set(&mut d, "kind", "decision")?;
        set(&mut d, "phase", "outcome")?;
        set(&mut d, "intent", id)?;
        set(&mut d, "status", status)?;
        for k in ["principal", "action", "subject", "source"] {
            if let (None, Some(v)) = (d.get(k), intent.get(k)) {
                d.insert(k.into(), v.clone());
            }
        }
        self.put(d).await
    }

    async fn put(&self, mut d: Map<String, Value>) -> Result<String, Error> {
        match &self.0 {
            Inner::Local(l) => l.write(entry(d)?).await,
            Inner::Remote(r) => {
                // The id is chosen here, before the write, so a caller can retry with it.
                match d.get("id") {
                    None => {
                        d.insert("id".into(), new_id()?.into());
                    }
                    Some(Value::String(id)) if encoding::parse_ulid(id).is_some() => {}
                    Some(v) => {
                        return Err(Error::new(
                            INVALID_REQUEST,
                            format!("the entry id must be a ULID, not {v}"),
                        ));
                    }
                }
                r.write(d).await
            }
        }
    }

    /// Waits for every append queued so far. Through tenbrid every append returns durable.
    pub async fn flush(&self) {
        if let Inner::Local(l) = &self.0 {
            l.flush().await;
        }
    }

    /// Flushes and stops the writer; later writes fail. Reads still work.
    pub async fn close(&self) {
        if let Inner::Local(l) = &self.0 {
            l.close().await;
        }
    }

    /// Checks the whole stream (canonical bytes, chain, signatures, keys, HEAD, latest
    /// checkpoint) against `key`, else the key pinned at open. Returns a JSON report: `stream`,
    /// `entries`, `pinned_key` (null when unpinned), `broken` (`{seq, code, message}` or null)
    /// and `checkpoint` (the size of the latest checkpoint it matched, or null). Through tenbrid,
    /// tenbrid's own check, against the key it pins (`key`, if given, must be it).
    pub async fn verify(&self, key: Option<&str>) -> Result<String, Error> {
        match &self.0 {
            Inner::Local(l) => l.verify(key).await,
            Inner::Remote(r) => r.verify(key.map(pin).transpose()?.as_deref()).await,
        }
    }

    /// Entries matching `filter` (a JSON [`Filter`]), each as `{verification, entry}`, in
    /// sequence order: a JSON array. `verification` is `verified`, `unpinned` (no key pinned at
    /// open) or `broken` (at or after a revocation that reaches back).
    pub async fn query(&self, filter: &[u8]) -> Result<String, Error> {
        let f: Filter = serde_json::from_slice(filter)
            .map_err(|e| Error::new(INVALID_REQUEST, format!("query: {e}")))?;
        match &self.0 {
            Inner::Local(l) => l.query(&f).await,
            Inner::Remote(r) => r.query(&f).await,
        }
    }
}

/// A stream on storage, with this machine's keys.
struct Local {
    store: AnyStore,
    id: String,
    pin: Option<String>,
    fingerprint: Option<String>,
    replicated: bool,
    /// This machine's keys of the stream, which hold its data keys; none when read-only.
    keys: Option<KeyStore>,
    /// The writer, or why there is none: read-only, or closed.
    lane: Mutex<Result<Lane, Error>>,
}

impl Local {
    async fn open(location: &str, o: Options) -> Result<Local, Error> {
        let location = location.strip_prefix("file://").unwrap_or(location);
        let pin = o.key.as_deref().map(pin).transpose()?;
        let keys = o.keys.or_else(tenbri_keys::default_dir);
        if o.create {
            create(location, keys.as_deref()).await?;
        }
        let store = tenbri_store::open(location).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::new(NOT_FOUND, format!("no stream at {location}: {e}"))
            } else {
                e.into()
            }
        })?;
        let head = store
            .get("HEAD")
            .await?
            .ok_or_else(|| Error::new(NOT_FOUND, format!("no stream at {location}")))?;
        let (head, _) = Head::parse(&head.bytes)
            .map_err(|e| Error::new(STREAM_BROKEN, format!("HEAD: {e}")).with_reason(e.code))?;
        // Only a key directory that exists: opening one creates it, and a verifier with no keys
        // leaves nothing behind.
        let ks = match &keys {
            Some(k) if k.join(head.stream.replace(':', "-")).is_dir() => {
                Some(key_store(k, location, &head.stream)?)
            }
            _ => None,
        };
        // As `tenbri append` does: the genesis key as this machine holds it.
        let genesis = match &ks {
            Some(ks) => ks
                .list()?
                .iter()
                .filter(|m| m.role == Role::Stream)
                .filter_map(|m| sign::decode_key(&m.public).ok())
                .find(|k| sign::stream_id(k) == head.stream)
                .map(|k| sign::fingerprint(&k)),
            None => None,
        };
        let fingerprint = pin.clone().or(genesis);
        let held = ks.clone();
        let lane = match (ks, &fingerprint) {
            (Some(ks), Some(fp)) => writer(store.clone(), ks, fp).await,
            _ => Err(Error::new(
                NO_SESSION_KEY,
                format!(
                    "read-only: no stream key for {} in {}",
                    head.stream,
                    keys.as_deref()
                        .map_or("(no keys directory)".into(), |k| k.display().to_string())
                ),
            )),
        };
        if let Err(e) = &lane {
            if e.code == STORE_UNAVAILABLE {
                return Err(e.clone());
            }
        }
        Ok(Local {
            replicated: matches!(store, AnyStore::Bucket(_)),
            store,
            id: head.stream,
            pin,
            fingerprint,
            keys: held,
            lane: Mutex::new(lane),
        })
    }

    /// The keyed digest of an input, `hmac-sha256:<hex>`, under the data key of `subject` (the
    /// tenant's without one) from the local key store beside the stream's keys, made on first use:
    /// erasing the subject's key leaves the digest unconfirmable (spec/privacy.md).
    fn digest(&self, subject: Option<&str>, content: &[u8]) -> Result<String, Error> {
        let ks = self.keys.as_ref().ok_or_else(|| {
            Error::new(
                NO_SESSION_KEY,
                format!(
                    "no keys for {} on this machine, so no data key to digest with",
                    self.id
                ),
            )
        })?;
        tenbri_crypt::DataKeys::open(ks)?
            .digest(subject, content)
            .map_err(|e| match e {
                tenbri_crypt::Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    Error::new(INVALID_REQUEST, e.to_string())
                }
                e => Error::new(STORE_UNAVAILABLE, e.to_string()),
            })
    }

    async fn write(&self, mut e: Entry) -> Result<String, Error> {
        if matches!(e.kind, Kind::Key | Kind::Reconcile) {
            return Err(Error::new(
                INVALID_ENTRY,
                "key and reconcile entries are written by the writer itself",
            ));
        }
        if e.kind == Kind::Decision {
            e.source.get_or_insert(Source::Sdk);
        }
        if e.phase == Some(Phase::Intent) {
            e.durability.get_or_insert(if self.replicated {
                Durability::Replicated
            } else {
                Durability::Local
            });
        }
        // The id is chosen here, before the write, so a caller can retry with it.
        if e.id.is_empty() {
            e.id = new_id()?;
        } else if encoding::parse_ulid(&e.id).is_none() {
            return Err(Error::new(
                INVALID_REQUEST,
                format!("the entry id must be a ULID, not \"{}\"", e.id),
            ));
        }
        let lane = self.lane.lock().expect("lane lock").clone()?;
        match lane.append(e.clone()).await {
            Ok(stored) => Ok(line(&stored)),
            Err(WriteError::Rejected(r)) if r.code == Code::DuplicateId => self.replay(&e).await,
            Err(err) => Err(Error {
                id: Some(e.id),
                ..err.into()
            }),
        }
    }

    /// The entry already written with `draft`'s id: the same entry is returned, another is a
    /// conflict.
    // ponytail: reads the whole stream, on retries only; the index's id lookup once there is one.
    async fn replay(&self, draft: &Entry) -> Result<String, Error> {
        let mut r = Reader::new(&self.store, self.fingerprint.as_deref());
        let stored = r.poll().await?.into_iter().find(|s| s.id == draft.id);
        match stored {
            Some(s) if same(draft, &s) => Ok(line(&s)),
            _ => Err(Error::new(
                IDEMPOTENCY_CONFLICT,
                format!("id {} was used for a different entry", draft.id),
            )),
        }
    }

    /// Waits for every append queued so far.
    async fn flush(&self) {
        let lane = self.lane.lock().expect("lane lock").clone();
        if let Ok(lane) = lane {
            lane.flush().await;
        }
    }

    /// Flushes and stops the writer; later writes fail. Reads still work.
    async fn close(&self) {
        self.flush().await;
        *self.lane.lock().expect("lane lock") = Err(Error::new(STORE_UNAVAILABLE, "closed"));
    }

    /// Checks the whole stream (canonical bytes, chain, signatures, keys, HEAD, latest
    /// checkpoint) against `key`, else the key pinned at open. Returns a JSON report: `stream`,
    /// `entries`, `pinned_key` (null when unpinned), `broken` (`{seq, code, message}` or null)
    /// and `checkpoint` (the size of the latest checkpoint it matched, or null).
    async fn verify(&self, key: Option<&str>) -> Result<String, Error> {
        let pin = key.map(pin).transpose()?.or_else(|| self.pin.clone());
        let r = tenbri_writer::verify(&self.store, pin.as_deref()).await?;
        Ok(json!({
            "stream": r.stream,
            "entries": r.entries,
            "pinned_key": pin.filter(|_| r.pinned),
            "broken": r.broken.map(|b| json!({
                "seq": b.seq,
                "code": b.error.code.as_str(),
                "message": b.error.detail,
            })),
            "checkpoint": r.checkpoint,
        })
        .to_string())
    }

    /// Entries matching `filter` (a JSON [`Filter`]), each as `{verification, entry}`, in
    /// sequence order: a JSON array. `verification` is `verified`, `unpinned` (no key pinned at
    /// open) or `broken` (at or after a revocation that reaches back).
    // ponytail: replays and checks the whole stream per query; tenbri-index replaces the scan.
    async fn query(&self, f: &Filter) -> Result<String, Error> {
        let mut r = Reader::new(&self.store, self.pin.as_deref());
        let entries = r.poll().await?;
        let broken = r.chain().invalidated().map(|b| b.seq);
        let ok = if self.pin.is_some() {
            "verified"
        } else {
            "unpinned"
        };
        let out: Vec<String> = entries
            .iter()
            .filter(|e| e.seq > f.after_seq && f.matches(e))
            .take(f.limit.unwrap_or(usize::MAX))
            .map(|e| {
                let v = if broken.is_some_and(|b| e.seq >= b) {
                    "broken"
                } else {
                    ok
                };
                format!("{{\"verification\":\"{v}\",\"entry\":{}}}", line(e))
            })
            .collect();
        Ok(format!("[{}]", out.join(",")))
    }
}

/// What [`Stream::query`] selects; every member given must match. The names are tenbrid's
/// (`GET /v1/streams/{stream}/entries`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// `[ref, version]` pairs; all must be among the entry's inputs.
    #[serde(default)]
    pub inputs: Vec<(String, String)>,
    pub action: Option<String>,
    /// `kind:id` (`agent:support-assistant`).
    pub principal: Option<String>,
    pub target: Option<String>,
    pub subject: Option<String>,
    /// Only entries after this sequence number.
    #[serde(default)]
    pub after_seq: u64,
    pub limit: Option<usize>,
}

impl Filter {
    fn matches(&self, e: &Entry) -> bool {
        let action = e.action.as_ref();
        let principal = e.principal.as_ref().map(|p| {
            let kind = serde_json::to_value(p.kind).expect("a principal kind");
            format!("{}:{}", kind.as_str().unwrap_or_default(), p.id)
        });
        self.inputs.iter().all(|(r, v)| {
            e.inputs
                .iter()
                .flatten()
                .any(|i| i.r#ref == *r && i.version == *v)
        }) && self
            .action
            .as_ref()
            .is_none_or(|a| action.is_some_and(|x| x.r#type == *a))
            && self
                .target
                .as_ref()
                .is_none_or(|t| action.and_then(|x| x.target.as_ref()) == Some(t))
            && self
                .principal
                .as_ref()
                .is_none_or(|p| principal.as_ref() == Some(p))
            && self
                .subject
                .as_ref()
                .is_none_or(|s| e.subject.as_ref() == Some(s))
    }
}

/// Creates the stream at `location` and its keys, unless there is one, and records its pin in
/// `<keys>/pins`: as `tenbri init` does.
async fn create(location: &str, keys: Option<&Path>) -> Result<(), Error> {
    if !tenbri_store::is_url(location) {
        let dir = Path::new(location);
        if dir.join("HEAD").exists() {
            return Ok(());
        }
        if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
            return Err(Error::new(
                INVALID_REQUEST,
                format!("{location} is not empty and holds no stream"),
            ));
        }
        std::fs::create_dir_all(dir)?;
    }
    let store = tenbri_store::open(location).await?;
    if store.get("HEAD").await?.is_some() {
        return Ok(());
    }
    let keys = keys.ok_or_else(|| {
        Error::new(
            INVALID_REQUEST,
            "no keys directory: pass keys or set TENBRI_KEYS",
        )
    })?;
    let stream_key = Key::new_stream()?;
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS)?;
    let ks = key_store(
        keys,
        location,
        &sign::stream_id(&stream_key.signing.verifying_key()),
    )?;
    ks.save(&stream_key, Backend::File)?;
    ks.save(&session, Backend::File)?;
    Writer::create(store, &stream_key, session).await?;
    // As `tenbri init` does, so `tenbri verify` on this machine needs no --key.
    tenbri_keys::record_pin(keys, location, &stream_key.fingerprint())?;
    Ok(())
}

/// The stream's writer behind a lane, pinned to `fingerprint`, signing with session keys from
/// `ks` and keeping the latest checkpoint there.
async fn writer(store: AnyStore, ks: KeyStore, fingerprint: &str) -> Result<Lane, Error> {
    let mut w = Writer::open(store, Some(fingerprint))
        .await?
        .with_checkpoints(Some(ks.dir().join(CHECKPOINT_FILE)))
        .await?;
    w.use_keys(ks).await?;
    Ok(Lane::spawn(w, LaneConfig::default()))
}

/// The key directory of `stream`, kept apart from it when it is a local directory.
fn key_store(keys: &Path, location: &str, stream: &str) -> std::io::Result<KeyStore> {
    if tenbri_store::is_url(location) {
        KeyStore::open_for_object_store(keys, stream)
    } else {
        KeyStore::open(keys, Path::new(location), stream)
    }
}

/// A key as a fingerprint: `sha256:…` as given, or the fingerprint of `ed25519:…`.
fn pin(s: &str) -> Result<String, Error> {
    if encoding::prefixed::<32>(s, "sha256:").is_some() {
        return Ok(s.to_owned());
    }
    sign::decode_key(s)
        .map(|k| sign::fingerprint(&k))
        .map_err(|_| {
            Error::new(
                INVALID_REQUEST,
                format!("key {s}: expected sha256:<64 hex> or ed25519:<64 hex>"),
            )
        })
}

fn object(bytes: &[u8]) -> Result<Map<String, Value>, Error> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(Error::new(INVALID_REQUEST, "a draft is a JSON object")),
    }
}

/// Sets `k` to `v` in a draft, which may leave it out or say the same.
fn set(d: &mut Map<String, Value>, k: &str, v: &str) -> Result<(), Error> {
    match d.get(k) {
        None => {
            d.insert(k.into(), v.into());
            Ok(())
        }
        Some(Value::String(s)) if s == v => Ok(()),
        Some(_) => Err(Error::new(
            INVALID_REQUEST,
            format!("`{k}` must be \"{v}\" here, or absent"),
        )),
    }
}

fn entry(d: Map<String, Value>) -> Result<Entry, Error> {
    let bytes = serde_json::to_vec(&Value::Object(d)).expect("JSON serializes");
    Ok(draft_from_json(&bytes)?)
}

/// An entry as stored: canonical JSON.
fn line(e: &Entry) -> String {
    String::from_utf8(canon::to_vec(
        &canon::from_serialize(e).expect("a stored entry"),
    ))
    .expect("UTF-8")
}

/// Whether `stored` is `draft` as written: the same draft is a replay (tenbrid's rule).
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
