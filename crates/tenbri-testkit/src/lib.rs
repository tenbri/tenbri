//! Tenbri test kit: prove in an agent's unit tests, with no storage, that a risky action is
//! recorded, refused or approved, and that the record holds.
//!
//! [`TestStream`] is a stream in memory ([`MemStore`]) on a [`FixedClock`] with fixed keys, so the
//! same test writes the same bytes every run: ids, timestamps and signatures included. Hand its
//! [`TestStream::writer`] to the code under test, then assert on what it recorded:
//!
//! - [`TestStream::assert_decision`]: a decision matching a [`Match`] (action, target, principal,
//!   input, rule, status, trace id) was recorded;
//! - [`TestStream::assert_every_intent_has_outcome`]: no intent was left open;
//! - [`TestStream::assert_verifies`]: the stream verifies against its pinned key;
//! - [`TestStream::snapshot`] and [`TestStream::assert_snapshot`]: the whole record as text, to
//!   compare with a file kept next to the test.
//!
//! Each `assert_*` panics with what was recorded instead; the [`check`] functions return the same
//! verdicts as values, for the Python and Node test kits.
//!
//! ```
//! use tenbri_core::{Action, Entry, Kind, Principal, PrincipalKind, Status};
//! use tenbri_testkit::{Match, TestStream, input};
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let kit = TestStream::new().await;
//! let mut log = kit.writer().await;
//!
//! // The agent under test refuses a refund under policy:refund version 14.
//! let intent = log
//!     .intent(Entry {
//!         principal: Some(Principal { kind: PrincipalKind::Agent, id: "support".into() }),
//!         action: Some(Action { r#type: "issue_refund".into(), target: Some("order:1042".into()) }),
//!         inputs: Some(vec![input("policy:refund", "14")]),
//!         ..Entry::new(Kind::Decision)
//!     })
//!     .await
//!     .unwrap();
//! log.outcome(&intent, Status::Refused).await.unwrap();
//!
//! kit.assert_decision(
//!     Match::default()
//!         .action("issue_refund")
//!         .input("policy:refund@14")
//!         .status(Status::Refused),
//! );
//! kit.assert_every_intent_has_outcome();
//! kit.assert_verifies().await;
//! # });
//! ```

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tenbri_core::sign::SigningKey;
use tenbri_core::{Entry, Input, Kind, Role, canon, encoding, sign};
use tenbri_keys::{Key, SESSION_LIFETIME_MS};
use tenbri_store::{Listed, Object, Put, Store, Swap, Version};
use tenbri_writer::{Clock, Report, Writer, split_batch};

pub use check::{Decision, Failure, Match};

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where every [`FixedClock`] starts: 2026-01-01T00:00:00.000Z.
pub const START_MS: i64 = 1_767_225_600_000;

/// Set to `1` to rewrite snapshot files instead of comparing with them.
pub const UPDATE_SNAPSHOTS: &str = "TENBRI_UPDATE_SNAPSHOTS";

/// A clock that stays where it is put; ids are ULIDs of its time and a counter, so they are unique,
/// in order, and the same every run.
#[derive(Debug)]
pub struct FixedClock {
    ms: AtomicI64,
    ids: AtomicU64,
}

impl FixedClock {
    pub fn new(ms: i64) -> FixedClock {
        FixedClock {
            ms: AtomicI64::new(ms),
            ids: AtomicU64::new(0),
        }
    }

    /// Milliseconds since the Unix epoch, as the clock says.
    pub fn now_ms(&self) -> i64 {
        self.ms.load(Ordering::SeqCst)
    }

    pub fn set(&self, ms: i64) {
        self.ms.store(ms, Ordering::SeqCst);
    }

    /// Moves the clock forward by `ms`.
    pub fn advance(&self, ms: i64) {
        self.ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Default for FixedClock {
    fn default() -> Self {
        FixedClock::new(START_MS)
    }
}

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        FixedClock::now_ms(self)
    }

    fn new_id(&self, ms: i64) -> io::Result<String> {
        let n = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(encoding::ulid(((ms as u128) << 80) | n as u128))
    }
}

/// The test kit's stream key: always the same.
pub fn stream_key() -> Key {
    Key::local(
        "stream:testkit".into(),
        Role::Stream,
        None,
        SigningKey::from_bytes(&[1; 32]),
    )
}

/// The test kit's session key: always the same, valid for 24 hours from [`START_MS`], as a real
/// session key is.
pub fn session_key() -> Key {
    Key::local(
        "sess:testkit".into(),
        Role::Session,
        Some(encoding::format_ts(START_MS + SESSION_LIFETIME_MS)),
        SigningKey::from_bytes(&[2; 32]),
    )
}

/// An input `ref` at `version`, for a test entry. Its digest is a placeholder (the SHA-256 of
/// `ref@version`, in the `hmac-sha256:` spelling), not a keyed digest of real content.
pub fn input(r#ref: &str, version: &str) -> Input {
    let digest = sign::sha256(format!("{ref}@{version}").as_bytes());
    Input {
        r#ref: r#ref.into(),
        version: version.into(),
        digest: digest.replacen("sha256:", "hmac-sha256:", 1),
    }
}

/// Objects by key, with their version.
type Objects = BTreeMap<String, (Vec<u8>, u64)>;

/// A [`Store`] in memory. Clones share the same objects.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    objects: Arc<Mutex<Objects>>,
    versions: Arc<AtomicU64>,
}

impl MemStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Objects> {
        self.objects.lock().expect("store lock")
    }

    fn put(&self, map: &mut Objects, key: &str, bytes: &[u8]) -> Version {
        let v = self.versions.fetch_add(1, Ordering::SeqCst) + 1;
        map.insert(key.to_owned(), (bytes.to_vec(), v));
        Version(v.to_string())
    }

    /// The bytes stored under `key`.
    pub fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.lock().get(key).map(|(b, _)| b.clone())
    }

    /// Every key, in order.
    pub fn keys(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// Replaces what `key` holds, bypassing the write protocol: a tampering attacker.
    pub fn overwrite(&self, key: &str, bytes: &[u8]) {
        let mut m = self.lock();
        self.put(&mut m, key, bytes);
    }
}

impl Store for MemStore {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        Ok(self.lock().get(key).map(|(b, v)| Object {
            bytes: b.clone(),
            version: Version(v.to_string()),
        }))
    }

    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        let mut m = self.lock();
        if m.contains_key(key) {
            return Ok(Put::Exists);
        }
        self.put(&mut m, key, bytes);
        Ok(Put::Created)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        let mut m = self.lock();
        let current = m.get(key).map(|(_, v)| Version(v.to_string()));
        if current.as_ref() != expected {
            return Ok(Swap::Mismatch);
        }
        Ok(Swap::Swapped(self.put(&mut m, key, bytes)))
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        Ok(self
            .lock()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .map(|k| Listed {
                key: k.clone(),
                modified: SystemTime::now(),
            })
            .collect())
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        self.lock().remove(key);
        Ok(())
    }
}

/// A stream in memory with the test kit's [`stream_key`], [`session_key`] and a [`FixedClock`]
/// at [`START_MS`]. Every helper panics on failure: it is for tests.
pub struct TestStream {
    store: MemStore,
    clock: Arc<FixedClock>,
}

impl TestStream {
    /// A new stream: its genesis entry and the session key's certificate.
    pub async fn new() -> TestStream {
        let (store, clock) = (MemStore::default(), Arc::new(FixedClock::default()));
        Writer::create_with_clock(store.clone(), &stream_key(), session_key(), clock.clone())
            .await
            .expect("create the test stream");
        TestStream { store, clock }
    }

    pub fn store(&self) -> &MemStore {
        &self.store
    }

    pub fn clock(&self) -> &FixedClock {
        &self.clock
    }

    /// The stream key's fingerprint, which verifiers pin.
    pub fn pin(&self) -> String {
        stream_key().fingerprint()
    }

    /// A writer on this stream, signing with the session key, on the fixed clock. Take one at a
    /// time; [`tenbri_writer::Lane::spawn`] shares it between tasks.
    pub async fn writer(&self) -> Writer<MemStore> {
        let mut w = Writer::open(self.store.clone(), Some(&self.pin()))
            .await
            .expect("open the test stream")
            .with_clock(self.clock.clone());
        w.use_session(session_key()).expect("the test session key");
        w
    }

    /// Every entry stored, in order, as written: not verified, so a test can see what a
    /// tampered stream holds.
    pub fn entries(&self) -> Vec<Entry> {
        self.store
            .keys()
            .iter()
            .filter(|k| k.starts_with("batches/"))
            .flat_map(|k| {
                let bytes = self.store.bytes(k).unwrap_or_default();
                split_batch(&bytes)
                    .expect("a batch of lines")
                    .into_iter()
                    .map(|l| serde_json::from_slice(l).expect("an entry"))
                    .collect::<Vec<Entry>>()
            })
            .collect()
    }

    /// The decision matching `m`; panics, listing the decisions recorded, if there is none.
    #[track_caller]
    pub fn assert_decision(&self, m: Match) -> Decision {
        check::decision(&self.entries(), &m).unwrap_or_else(|f| panic!("{f}"))
    }

    /// Panics, naming them, if any intent has no outcome.
    #[track_caller]
    pub fn assert_every_intent_has_outcome(&self) {
        if let Err(f) = check::every_intent_has_outcome(&self.entries()) {
            panic!("{f}")
        }
    }

    /// The stream checked from genesis against [`TestStream::pin`]: canonical bytes, chain,
    /// signatures, keys, HEAD. Panics at the first break.
    pub async fn assert_verifies(&self) -> Report {
        check::verifies(&self.store, &self.pin())
            .await
            .unwrap_or_else(|f| panic!("{f}"))
    }

    /// The stream as text, one canonical JSON line per entry, without key entries and without
    /// the members that only seal the record (`v`, `stream`, `prev`, `signer`, `sig`).
    pub fn snapshot(&self) -> String {
        check::snapshot(&self.entries())
    }

    /// Compares [`TestStream::snapshot`] with the file at `path`, and panics with both if they
    /// differ. Writes the file if it is missing, or if [`UPDATE_SNAPSHOTS`] is `1`.
    #[track_caller]
    pub fn assert_snapshot(&self, path: impl AsRef<Path>) {
        let (path, now) = (path.as_ref(), self.snapshot());
        let update = std::env::var(UPDATE_SNAPSHOTS).is_ok_and(|v| v == "1");
        match std::fs::read_to_string(path) {
            // A checkout with core.autocrlf (Windows) may have turned LF into CRLF.
            Ok(old) if !update => assert!(
                old.replace("\r\n", "\n") == now,
                "the snapshot {} differs (set {UPDATE_SNAPSHOTS}=1 to accept the new one)\n--- stored\n{old}--- now\n{now}",
                path.display()
            ),
            _ => {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).expect("create the snapshot directory");
                }
                std::fs::write(path, now).expect("write the snapshot");
            }
        }
    }

    /// Changes the stored entry at `seq` in place, as an attacker with write access would: `f`
    /// edits its JSON, which is stored canonical again, so the edit is caught by its signature or
    /// hash, not by its spelling.
    pub fn tamper(&self, seq: u64, f: impl FnOnce(&mut serde_json::Value)) {
        let (key, bytes) = self
            .store
            .keys()
            .into_iter()
            .filter(|k| tenbri_writer::batch_seq(k).is_some_and(|s| s <= seq))
            .filter_map(|k| self.store.bytes(&k).map(|b| (k, b)))
            .next_back()
            .expect("a batch holding seq");
        let first = tenbri_writer::batch_seq(&key).expect("a batch key");
        let mut lines: Vec<Vec<u8>> = split_batch(&bytes)
            .expect("a batch of lines")
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let line = lines
            .get_mut((seq - first) as usize)
            .expect("seq is in the stream");
        let mut v: serde_json::Value = serde_json::from_slice(line).expect("an entry");
        f(&mut v);
        *line = canon::canonicalize(v.to_string().as_bytes()).expect("canonical JSON");
        let mut out = lines.join(&b'\n');
        out.push(b'\n');
        self.store.overwrite(&key, &out);
    }
}

/// The verdicts behind the `assert_*` helpers, as values.
pub mod check {
    use super::*;
    use serde::Deserialize;
    use std::fmt;
    use tenbri_core::{Phase, Status};

    /// Why an assertion failed, with what was recorded.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Failure(pub String);

    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl fmt::Debug for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Failure {}

    /// A decision: its intent and its outcome, as far as they were recorded. An outcome from
    /// ingest has no intent.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Decision {
        pub intent: Option<Entry>,
        pub outcome: Option<Entry>,
    }

    impl Decision {
        fn entries(&self) -> impl Iterator<Item = &Entry> {
            self.intent.iter().chain(self.outcome.iter())
        }

        fn summary(&self) -> String {
            let e = self.entries().next().expect("a decision has an entry");
            let action = e.action.as_ref().map_or("?", |a| a.r#type.as_str());
            let status = match self.outcome.as_ref().and_then(|o| o.status) {
                Some(s) => format!("{s:?}").to_lowercase(),
                None => "no outcome".into(),
            };
            format!("{action} ({status}, {})", e.id)
        }
    }

    /// What a decision must have; every field left `None` matches anything. Deserializable, so a
    /// binding can build it from keyword arguments.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    pub struct Match {
        /// The action type.
        pub action: Option<String>,
        /// The action target, exactly.
        pub target: Option<String>,
        /// `kind:id`, as `agent:support`.
        pub principal: Option<String>,
        /// An input of the intent: `ref@version`, or `ref` for any version.
        pub input: Option<String>,
        /// The intent's rule: `ref@version`, or `ref` for any version.
        pub rule: Option<String>,
        /// The outcome's status; a decision with no outcome never matches one.
        pub status: Option<Status>,
        /// The trace id of the intent or the outcome.
        pub trace_id: Option<String>,
    }

    impl Match {
        pub fn action(mut self, v: &str) -> Self {
            self.action = Some(v.into());
            self
        }
        pub fn target(mut self, v: &str) -> Self {
            self.target = Some(v.into());
            self
        }
        pub fn principal(mut self, v: &str) -> Self {
            self.principal = Some(v.into());
            self
        }
        pub fn input(mut self, v: &str) -> Self {
            self.input = Some(v.into());
            self
        }
        pub fn rule(mut self, v: &str) -> Self {
            self.rule = Some(v.into());
            self
        }
        pub fn status(mut self, v: Status) -> Self {
            self.status = Some(v);
            self
        }
        pub fn trace_id(mut self, v: &str) -> Self {
            self.trace_id = Some(v.into());
            self
        }

        pub fn matches(&self, d: &Decision) -> bool {
            let any = |f: &dyn Fn(&Entry) -> bool| d.entries().any(f);
            let at = |want: &str, r: &str, v: &str| match want.rsplit_once('@') {
                Some((wr, wv)) => wr == r && wv == v,
                None => want == r,
            };
            // Inputs and rule are the intent's; an ingest outcome, which has no intent, has them.
            let first = d.entries().next();
            self.action
                .as_ref()
                .is_none_or(|a| any(&|e| e.action.as_ref().is_some_and(|x| &x.r#type == a)))
                && self.target.as_ref().is_none_or(|t| {
                    any(&|e| e.action.as_ref().and_then(|x| x.target.as_ref()) == Some(t))
                })
                && self.principal.as_ref().is_none_or(|p| {
                    any(&|e| {
                        e.principal.as_ref().is_some_and(|x| {
                            *p == format!("{}:{}", format!("{:?}", x.kind).to_lowercase(), x.id)
                        })
                    })
                })
                && self.input.as_ref().is_none_or(|w| {
                    first.is_some_and(|e| {
                        e.inputs
                            .iter()
                            .flatten()
                            .any(|i| at(w, &i.r#ref, &i.version))
                    })
                })
                && self.rule.as_ref().is_none_or(|w| {
                    first
                        .and_then(|e| e.rule.as_ref())
                        .is_some_and(|r| at(w, &r.r#ref, &r.version))
                })
                && self
                    .status
                    .is_none_or(|s| d.outcome.as_ref().and_then(|o| o.status) == Some(s))
                && self
                    .trace_id
                    .as_ref()
                    .is_none_or(|t| any(&|e| e.trace.as_ref().is_some_and(|x| &x.trace_id == t)))
        }
    }

    /// The decisions in `entries`, in the order their first entry was written.
    pub fn decisions(entries: &[Entry]) -> Vec<Decision> {
        let mut out: Vec<Decision> = vec![];
        let mut by_intent: HashMap<&str, usize> = HashMap::new();
        for e in entries.iter().filter(|e| e.kind == Kind::Decision) {
            match (e.phase, e.intent.as_deref()) {
                (Some(Phase::Intent), _) => {
                    by_intent.insert(&e.id, out.len());
                    out.push(Decision {
                        intent: Some(e.clone()),
                        outcome: None,
                    });
                }
                (_, Some(id)) if by_intent.contains_key(id) => {
                    out[by_intent[id]].outcome = Some(e.clone());
                }
                _ => out.push(Decision {
                    intent: None,
                    outcome: Some(e.clone()),
                }),
            }
        }
        out
    }

    fn recorded(ds: &[Decision]) -> String {
        if ds.is_empty() {
            return "no decision was recorded".into();
        }
        let list: Vec<String> = ds.iter().map(|d| format!("  {}", d.summary())).collect();
        format!("recorded:\n{}", list.join("\n"))
    }

    /// The first decision in `entries` matching `m`.
    pub fn decision(entries: &[Entry], m: &Match) -> Result<Decision, Failure> {
        let ds = decisions(entries);
        ds.iter()
            .find(|d| m.matches(d))
            .cloned()
            .ok_or_else(|| Failure(format!("no decision matches {m:?}; {}", recorded(&ds))))
    }

    /// Every intent in `entries` has its outcome. A `reconcile` entry does not count: it records
    /// that the outcome never came.
    pub fn every_intent_has_outcome(entries: &[Entry]) -> Result<(), Failure> {
        let open: Vec<String> = decisions(entries)
            .iter()
            .filter(|d| d.intent.is_some() && d.outcome.is_none())
            .map(|d| format!("  {}", d.summary()))
            .collect();
        if open.is_empty() {
            Ok(())
        } else {
            Err(Failure(format!(
                "{} intent(s) without an outcome:\n{}",
                open.len(),
                open.join("\n")
            )))
        }
    }

    /// The stream in `store` checked from genesis against the fingerprint `pin`.
    pub async fn verifies<S: Store>(store: &S, pin: &str) -> Result<Report, Failure> {
        let r = tenbri_writer::verify(store, Some(pin))
            .await
            .map_err(|e| Failure(format!("the stream could not be read: {e}")))?;
        match &r.broken {
            Some(b) => Err(Failure(format!(
                "the stream does not verify after {} entries: {b}",
                r.entries
            ))),
            None => Ok(r),
        }
    }

    /// `entries` as text: see [`TestStream::snapshot`].
    pub fn snapshot(entries: &[Entry]) -> String {
        let mut out = String::new();
        for e in entries.iter().filter(|e| e.kind != Kind::Key) {
            let mut v = canon::from_serialize(e).expect("an entry serializes");
            for k in ["v", "stream", "prev", "signer", "sig"] {
                v.remove(k);
            }
            out.push_str(std::str::from_utf8(&canon::to_vec(&v)).expect("JSON is UTF-8"));
            out.push('\n');
        }
        out
    }
}
