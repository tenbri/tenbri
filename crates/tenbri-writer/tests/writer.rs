//! The writer's conformance suite, run on every store: a local directory, an in-memory object
//! store (with the same conditional-write answers as S3), and an S3-compatible bucket when
//! `TENBRI_TEST_S3_BUCKET` and its credentials are set (MinIO in CI, R2 and S3 nightly). Every
//! writer runs with the checkpoint hook, as tenbrid's do.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tenbri_core::{Code, Entry, Kind, Principal, PrincipalKind, Status};
use tenbri_keys::{Key, SESSION_LIFETIME_MS};
use tenbri_merkle::checkpoint;
use tenbri_store::object_store::aws::AmazonS3Builder;
use tenbri_store::object_store::memory::InMemory;
use tenbri_store::{AnyStore, Bucket, Listed, LocalStore, Object, Put, Store, Swap, Version};
use tenbri_writer::{
    Checkpoints, Commit, GC_MIN_AGE, Hook, Lane, LaneConfig, Reader, Report, WriteError, Writer,
    batch_key, batch_seq, gc, now_ms, verify,
};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-writer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn random() -> String {
    format!("{:x}", now_ms()) + &tenbri_writer::new_id(now_ms()).unwrap()[10..]
}

/// The S3-compatible bucket from `TENBRI_TEST_S3_*`, if set, under a fresh prefix.
async fn s3(test: &str) -> Option<Bucket> {
    let var = |k: &str| {
        std::env::var(format!("TENBRI_TEST_S3_{k}"))
            .ok()
            .filter(|v| !v.is_empty())
    };
    let mut b = AmazonS3Builder::new()
        .with_bucket_name(var("BUCKET")?)
        .with_access_key_id(var("ACCESS_KEY_ID")?)
        .with_secret_access_key(var("SECRET_ACCESS_KEY")?)
        .with_region(var("REGION").unwrap_or_else(|| "us-east-1".into()));
    if let Some(e) = var("ENDPOINT") {
        b = b
            .with_endpoint(&e)
            .with_allow_http(e.starts_with("http://"));
    }
    let prefix = format!("tenbri-tests/{test}-{}", random());
    Some(
        Bucket::new(Arc::new(b.build().unwrap()), &prefix)
            .await
            .unwrap(),
    )
}

/// The kinds of store this run can reach.
fn kinds() -> Vec<&'static str> {
    if std::env::var("TENBRI_TEST_S3_BUCKET").is_ok_and(|b| !b.is_empty()) {
        vec!["local", "memory", "s3"]
    } else {
        eprintln!("TENBRI_TEST_S3_* not set: no S3-compatible store in this run");
        vec!["local", "memory"]
    }
}

/// A fresh, empty store of `kind` for `test`. Clones are handles to the same objects.
async fn store(kind: &str, test: &str) -> AnyStore {
    match kind {
        "local" => AnyStore::Local(LocalStore::open(tmp(test)).unwrap()),
        "memory" => AnyStore::Bucket(Bucket::new(Arc::new(InMemory::new()), test).await.unwrap()),
        _ => AnyStore::Bucket(s3(test).await.unwrap()),
    }
}

/// A fresh store of every kind this run can reach.
async fn stores(test: &str) -> Vec<(&'static str, AnyStore)> {
    let mut v = vec![];
    for kind in kinds() {
        v.push((kind, store(kind, &format!("{test}-{kind}")).await));
    }
    v
}

fn decision(action: &str) -> Entry {
    Entry {
        principal: Some(Principal {
            kind: PrincipalKind::Agent,
            id: "support-assistant".into(),
        }),
        action: Some(tenbri_core::Action {
            r#type: action.into(),
            target: Some("zendesk:ticket/1".into()),
        }),
        ..Entry::new(Kind::Decision)
    }
}

async fn new_stream<S: Store>(store: S) -> (Writer<S, Checkpoints>, Key) {
    let sk = Key::new_stream().unwrap();
    let w = Writer::create(
        store,
        &sk,
        Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
    )
    .await
    .unwrap();
    (w.with_checkpoints(None).await.unwrap(), sk)
}

/// The stream in `store`, pinned, with the checkpoint hook.
async fn open<S: Store>(store: S, pin: &str) -> Writer<S, Checkpoints> {
    Writer::open(store, Some(pin))
        .await
        .unwrap()
        .with_checkpoints(None)
        .await
        .unwrap()
}

async fn report<S: Store>(store: &S, pin: &str) -> Report {
    verify(store, Some(pin)).await.unwrap()
}

/// Every stream vector, read through the store.
#[tokio::test]
async fn stream_vectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("streams.json")).unwrap()).unwrap();
    for kind in kinds() {
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let dir = root.join("streams").join(name);
            let store = match store(kind, &format!("vectors-{name}")).await {
                AnyStore::Bucket(b) => {
                    upload(&b, &dir, "").await;
                    AnyStore::Bucket(b)
                }
                AnyStore::Local(_) => AnyStore::Local(LocalStore::open(&dir).unwrap()),
            };
            let r = verify(&store, c["pin"].as_str()).await.unwrap();
            let want = &c["result"];
            if want["ok"].as_bool().unwrap() {
                assert_eq!(
                    (r.broken, r.entries),
                    (None, want["entries"].as_u64().unwrap()),
                    "{kind} {name}"
                );
            } else {
                let b = r.broken.unwrap_or_else(|| panic!("{kind} {name} verified"));
                assert_eq!(
                    (b.seq, b.error.code.as_str()),
                    (
                        want["seq"].as_u64().unwrap(),
                        want["error"].as_str().unwrap()
                    ),
                    "{kind} {name}"
                );
            }
        }
    }
}

async fn upload(s: &Bucket, dir: &Path, prefix: &str) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let key = format!("{prefix}{}", e.file_name().to_string_lossy());
        if e.file_type().unwrap().is_dir() {
            Box::pin(upload(s, &e.path(), &format!("{key}/"))).await;
        } else {
            let bytes = std::fs::read(e.path()).unwrap();
            assert_eq!(s.put_if_absent(&key, &bytes).await.unwrap(), Put::Created);
        }
    }
}

#[tokio::test]
async fn intent_outcome_rotation_revocation_and_reopen() {
    for (kind, store) in stores("lifecycle").await {
        let (mut w, sk) = new_stream(store.clone()).await;
        let pin = sk.fingerprint();
        let i = w.intent(decision("reply_ticket")).await.unwrap();
        let o = w.outcome(&i, Status::Ok).await.unwrap();
        assert_eq!(
            (i.seq, o.seq, o.intent.as_deref()),
            (3, 4, Some(i.id.as_str())),
            "{kind}"
        );

        // A stale intent is reconciled by the next session; its late outcome still lands.
        let mut stale = decision("issue_refund");
        stale.ts = tenbri_core::encoding::format_ts(now_ms() - 2 * 3_600_000);
        let stale = w.intent(stale).await.unwrap();
        let r = w.reconcile_stale(now_ms(), 3_600_000, None).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].intent.as_deref(), Some(stale.id.as_str()));
        w.outcome(&stale, Status::Refused).await.unwrap();
        assert!(w.chain().open_intents().is_empty());

        // Rotate the stream key, certify a new session with the new key, revoke the old session.
        let sk2 = Key::new_stream().unwrap();
        w.rotate(&sk, &sk2).await.unwrap();
        let old = w.session().unwrap().id.clone();
        w.certify_session(
            &sk2,
            Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
        )
        .await
        .unwrap();
        let next = w.chain().seq() + 2;
        w.revoke(&sk2, &old, next).await.unwrap();
        w.append(Entry::new(Kind::Note)).await.unwrap();
        assert!(
            matches!(w.certify_session(&sk, Key::new_session(now_ms(), 1000).unwrap()).await, Err(WriteError::Rejected(e)) if e.code == Code::SignerNotAllowed)
        );
        let n = w.chain().seq();
        drop(w);

        let r = report(&store, &pin).await;
        assert_eq!((r.broken, r.entries, r.pinned), (None, n, true), "{kind}");
        // A verifier pinning another key refuses the stream at its genesis.
        let other = Key::new_stream().unwrap().fingerprint();
        assert_eq!(
            report(&store, &other).await.broken.unwrap().error.code,
            Code::UntrustedRoot
        );

        // Reopened, the writer continues where the stream ends, with a certified session only.
        let mut w = open(store.clone(), &pin).await;
        assert!(matches!(
            w.append(Entry::new(Kind::Note)).await,
            Err(WriteError::NoSession(_))
        ));
        let s = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
        assert!(w.use_session(s.clone()).is_err(), "not certified");
        w.certify_session(&sk2, s).await.unwrap();
        w.append(Entry::new(Kind::Note)).await.unwrap();
        assert_eq!(report(&store, &pin).await.entries, n + 2);
        // A bad entry is refused before anything is written; in a batch, alone.
        let mut bad = decision("x");
        bad.status = Some(Status::Ok);
        assert!(matches!(
            w.intent(bad.clone()).await,
            Err(WriteError::Rejected(_))
        ));
        assert_eq!(report(&store, &pin).await.entries, n + 2);
        let r = w
            .append_batch(vec![Entry::new(Kind::Note), bad, Entry::new(Kind::Note)])
            .await;
        assert!(matches!(r[1], Err(WriteError::Rejected(_))), "{kind}");
        assert_eq!(
            (r[0].as_ref().unwrap().seq, r[2].as_ref().unwrap().seq),
            (n + 3, n + 4)
        );
        assert_eq!(report(&store, &pin).await.entries, n + 4, "{kind}");
    }
}

#[tokio::test]
async fn roll_forward_conflict_and_gc() {
    for (kind, store) in stores("protocol").await {
        let (mut w1, sk) = new_stream(store.clone()).await;
        let pin = sk.fingerprint();
        let session = w1.session().unwrap().clone();
        let mut w2 = open(store.clone(), &pin).await;
        w2.use_session(session.clone()).unwrap();

        // Two writers with the same view: each batch has exactly one winner, nothing is lost.
        let a = w1.append(Entry::new(Kind::Note)).await.unwrap();
        let b = w2.append(Entry::new(Kind::Note)).await.unwrap();
        assert_eq!((a.seq, b.seq), (3, 4), "{kind}");
        assert_eq!(report(&store, &pin).await.entries, 4);

        // A batch left by a crashed writer (written, HEAD not moved) is invisible, then rolled
        // forward.
        let mut w3 = open(store.clone(), &pin).await;
        w3.use_session(session.clone()).unwrap();
        let line = {
            let mut e = Entry {
                id: tenbri_writer::new_id(now_ms()).unwrap(),
                ts: tenbri_core::encoding::format_ts(now_ms()),
                seq: 5,
                stream: w3.head().stream.clone(),
                prev: Some(w3.head().hash.clone()),
                signer: session.id.clone(),
                ..Entry::new(Kind::Note)
            };
            tenbri_core::sign::sign_entry(&mut e, &session.signing).unwrap()
        };
        assert_eq!(
            store
                .put_if_absent(&batch_key(5), &[&line[..], b"\n"].concat())
                .await
                .unwrap(),
            Put::Created
        );
        assert_eq!(
            report(&store, &pin).await.entries,
            4,
            "orphans are invisible"
        );
        assert!(
            gc(&store, Some(&pin), Duration::ZERO)
                .await
                .unwrap()
                .is_empty(),
            "a valid next batch is kept"
        );
        let c = w3.append(Entry::new(Kind::Note)).await.unwrap();
        assert_eq!(c.seq, 6, "{kind}: rolled forward, then appended");
        assert_eq!(report(&store, &pin).await.entries, 6);

        // A batch that does not chain blocks the writer with a conflict, until gc removes it.
        store
            .put_if_absent(&batch_key(7), b"{\"not\":\"an entry\"}\n")
            .await
            .unwrap();
        store
            .put_if_absent("batches/.tmp-1-2-3", b"partial")
            .await
            .unwrap();
        store.put_if_absent("canary/0123", b"1").await.unwrap();
        assert!(matches!(
            w3.append(Entry::new(Kind::Note)).await,
            Err(WriteError::Conflict { seq: 7 })
        ));
        assert!(
            gc(&store, Some(&pin), GC_MIN_AGE).await.unwrap().is_empty(),
            "too young to remove"
        );
        let removed = gc(&store, Some(&pin), Duration::ZERO).await.unwrap();
        assert_eq!(
            removed,
            vec![
                "batches/.tmp-1-2-3".to_owned(),
                batch_key(7),
                "canary/0123".to_owned()
            ],
            "{kind}"
        );
        assert_eq!(w3.append(Entry::new(Kind::Note)).await.unwrap().seq, 7);
        assert_eq!(report(&store, &pin).await.broken, None);
    }
}

/// Seq → entry id, read back by following HEAD.
async fn ids<S: Store>(store: &S, pin: &str) -> BTreeMap<u64, String> {
    let mut r = Reader::new(store, Some(pin));
    r.poll()
        .await
        .unwrap()
        .into_iter()
        .map(|e| (e.seq, e.id))
        .collect()
}

/// Two writers race on one stream, each with its own session key, both going for the same
/// sequence number in every round: every sequence number has exactly one winner, the stream never forks, and each loser rolls
/// the winner forward and retries, so every append lands exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_writers_race() {
    const N: usize = 25;
    for (kind, store) in stores("race").await {
        let (w1, sk) = new_stream(store.clone()).await;
        let pin = sk.fingerprint();
        let mut w2 = open(store.clone(), &pin).await;
        w2.certify_session(
            &sk,
            Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
        )
        .await
        .unwrap();
        let start = w2.chain().seq();
        // Both start each round together, so both go for the same sequence number every time.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let run = |mut w: Writer<AnyStore, Checkpoints>| {
            let barrier = barrier.clone();
            tokio::spawn(async move {
                let mut out = vec![];
                for _ in 0..N {
                    barrier.wait().await;
                    out.push(w.append(Entry::new(Kind::Note)).await.unwrap());
                }
                out
            })
        };
        let (a, b) = (run(w1), run(w2));
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        // Each round has one winner and one loser that lands right after it.
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.seq.abs_diff(y.seq), 1, "{kind}");
        }

        let stored = ids(&store, &pin).await;
        let r = report(&store, &pin).await;
        assert_eq!(
            (r.broken, r.entries),
            (None, start + 2 * N as u64),
            "{kind}"
        );
        let mut seqs = HashSet::new();
        for e in a.iter().chain(&b) {
            assert!(seqs.insert(e.seq), "{kind}: seq {} won twice", e.seq);
            assert_eq!(stored.get(&e.seq), Some(&e.id), "{kind}: seq {}", e.seq);
        }
        // Batches no HEAD points through are what gc would remove; a race leaves none.
        let listed: Vec<u64> = store
            .list("batches/")
            .await
            .unwrap()
            .iter()
            .filter_map(|l| batch_seq(&l.key))
            .collect();
        assert_eq!(listed.len() as u64, r.entries, "{kind}: {listed:?}");
    }
}

/// Many tasks share one lane: their appends are group-committed into far fewer batches than
/// entries, each caller gets its own entry back once durable, and two lanes on one stream still
/// never fork it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_commit_in_lanes() {
    const TASKS: usize = 200;
    for (kind, store) in stores("lanes").await {
        let (w1, sk) = new_stream(store.clone()).await;
        let pin = sk.fingerprint();
        let mut w2 = open(store.clone(), &pin).await;
        w2.certify_session(
            &sk,
            Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
        )
        .await
        .unwrap();
        // w1 has not seen w2's certificate: its first batch retries after it.
        let start = w2.chain().seq();
        let lanes = [
            Lane::spawn(w1, LaneConfig::default()),
            Lane::spawn(w2, LaneConfig::default()),
        ];
        let tasks: Vec<_> = (0..TASKS)
            .map(|i| {
                let lane = lanes[i % 2].clone();
                tokio::spawn(async move {
                    let i = lane.intent(decision("reply_ticket")).await?;
                    let o = lane.outcome(&i, Status::Ok).await?;
                    Ok::<_, WriteError>((i, o))
                })
            })
            .collect();
        let mut written = vec![];
        for t in tasks {
            let (i, o) = t.await.unwrap().unwrap();
            assert!(i.seq < o.seq, "{kind}");
            written.extend([i, o]);
        }
        drop(lanes);

        let stored = ids(&store, &pin).await;
        let r = report(&store, &pin).await;
        assert_eq!(
            (r.broken, r.entries),
            (None, start + 2 * TASKS as u64),
            "{kind}"
        );
        let mut seqs = HashSet::new();
        for e in &written {
            assert!(seqs.insert(e.seq), "{kind}: seq {} twice", e.seq);
            assert_eq!(stored.get(&e.seq), Some(&e.id));
        }
        let batches = store.list("batches/").await.unwrap().len() as u64;
        assert!(
            batches < r.entries / 2,
            "{kind}: {batches} batches for {} entries",
            r.entries
        );
    }
}

/// A store whose writes take `delay`.
#[derive(Clone)]
struct Slow<S> {
    inner: S,
    delay: Duration,
}

impl<S: Store> Store for Slow<S> {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        tokio::time::sleep(self.delay).await;
        self.inner.put_if_absent(key, bytes).await
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        self.inner.compare_and_swap(key, expected, bytes).await
    }
    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        self.inner.list(prefix).await
    }
    async fn delete(&self, key: &str) -> io::Result<()> {
        self.inner.delete(key).await
    }
}

/// A full queue makes a new append wait up to the deadline, then fail closed with nothing
/// written; queued appends still land.
#[tokio::test]
async fn backpressure_fails_closed_after_the_deadline() {
    let dir = tmp("backpressure");
    let (w, sk) = new_stream(LocalStore::open(&dir).unwrap()).await;
    let session = w.session().unwrap().clone();
    drop(w);
    let slow = Slow {
        inner: LocalStore::open(&dir).unwrap(),
        delay: Duration::from_millis(300),
    };
    let mut w = open(slow, &sk.fingerprint()).await;
    w.use_session(session).unwrap();
    let lane = Lane::spawn(
        w,
        LaneConfig {
            max_batch: 1,
            linger: Duration::ZERO,
            queue: 1,
            deadline: Duration::from_millis(50),
            ..LaneConfig::default()
        },
    );
    // The first is being written, the second fills the queue, the third finds no room.
    let first = tokio::spawn({
        let lane = lane.clone();
        async move { lane.append(Entry::new(Kind::Note)).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = tokio::spawn({
        let lane = lane.clone();
        async move { lane.append(Entry::new(Kind::Note)).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t = std::time::Instant::now();
    assert!(matches!(
        lane.append(Entry::new(Kind::Note)).await,
        Err(WriteError::Backpressure)
    ));
    assert!(t.elapsed() >= Duration::from_millis(50));
    assert_eq!(first.await.unwrap().unwrap().seq, 3);
    assert_eq!(second.await.unwrap().unwrap().seq, 4);
    let r = report(&LocalStore::open(&dir).unwrap(), &sk.fingerprint()).await;
    assert_eq!((r.broken, r.entries), (None, 4));
}

/// Records every commit it is told about.
#[derive(Default)]
struct Recorder(Vec<(u64, u64, u64, usize, String)>);

impl<S: Store> Hook<S> for Recorder {
    async fn committed(&mut self, store: &S, c: Commit<'_>) {
        // The batch is durable and under HEAD when the hook runs, signed by a session key.
        assert!(store.get(&batch_key(c.first)).await.unwrap().is_some());
        assert!(c.signer.is_some());
        let last = format!(
            "sha256:{}",
            tenbri_core::encoding::hex(c.hashes.last().unwrap())
        );
        self.0
            .push((c.first, c.head.seq, c.head.counter, c.hashes.len(), last));
    }
}

#[tokio::test]
async fn hook_sees_every_commit_it_makes() {
    for (kind, store) in stores("hook").await {
        let (w, sk) = new_stream(store.clone()).await;
        let mut w = w.with_hook(Recorder::default());
        let r = w
            .append_batch(vec![Entry::new(Kind::Note), Entry::new(Kind::Note)])
            .await;
        let e = w.append(Entry::new(Kind::Note)).await.unwrap();
        let hash = w.head().hash.clone();
        let commits = &w.hook().0;
        assert_eq!(commits.len(), 2, "{kind}");
        assert_eq!(
            (commits[0].0, commits[0].1, commits[1].0, commits[1].1),
            (3, 4, 5, 5)
        );
        assert_eq!(commits[1].2, commits[0].2 + 1, "the counter moves by one");
        assert_eq!(
            (commits[0].3, commits[1].3),
            (4, 5),
            "the whole stream's hashes"
        );
        assert_eq!(commits[1].4, hash);
        assert!(r.iter().all(Result::is_ok) && e.seq == 5);
        assert_eq!(report(&store, &sk.fingerprint()).await.entries, 5);
    }
}

/// A store that "crashes" at its `n`th write: before doing it, or after doing it but before the
/// caller hears back.
struct Crashing<S> {
    inner: S,
    writes: AtomicUsize,
    at: usize,
    after: bool,
}

impl<S> Crashing<S> {
    fn step(&self) -> io::Result<bool> {
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.at && !self.after {
            return Err(io::Error::other("crash before the write"));
        }
        Ok(n == self.at)
    }
}

fn crash<T>(crashed: bool, r: io::Result<T>) -> io::Result<T> {
    if crashed {
        r.and(Err(io::Error::other("crash after the write")))
    } else {
        r
    }
}

impl<S: Store> Store for Crashing<S> {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        let c = self.step()?;
        crash(c, self.inner.put_if_absent(key, bytes).await)
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        let c = self.step()?;
        crash(c, self.inner.compare_and_swap(key, expected, bytes).await)
    }
    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        self.inner.list(prefix).await
    }
    async fn delete(&self, key: &str) -> io::Result<()> {
        let c = self.step()?;
        crash(c, self.inner.delete(key).await)
    }
}

/// The writer is killed at every step of three appends (an intent, its outcome, a note): each
/// put of a batch and each HEAD swap, before and after the write lands. Every time, the stream
/// still verifies, the interrupted entry is either absent or present exactly once, and a new
/// writer carries on.
#[tokio::test]
async fn crash_at_every_step() {
    for kind in kinds() {
        for at in 1..=6 {
            for after in [false, true] {
                let store = store(kind, &format!("crash-{kind}-{at}-{after}")).await;
                let (w, sk) = new_stream(store.clone()).await;
                let (pin, session) = (sk.fingerprint(), w.session().unwrap().clone());
                drop(w);
                let crashing = Crashing {
                    inner: store.clone(),
                    writes: AtomicUsize::new(0),
                    at,
                    after,
                };
                let mut w = open(crashing, &pin).await;
                w.use_session(session.clone()).unwrap();
                let mut written = 0;
                let result: Result<(), WriteError> = async {
                    let i = w.intent(decision("reply_ticket")).await?;
                    written += 1;
                    w.outcome(&i, Status::Ok).await?;
                    written += 1;
                    w.append(Entry::new(Kind::Note)).await?;
                    written += 1;
                    Ok(())
                }
                .await;
                let step = format!("{kind} step {at} after={after}");
                assert!(result.is_err(), "{step} did not crash");
                drop(w);

                let r = report(&store, &pin).await;
                assert_eq!(r.broken, None, "{step}");
                // The entry being written when it crashed is there only if HEAD moved to it.
                assert!(
                    r.entries == 2 + written || r.entries == 3 + written,
                    "{step}: {r:?}"
                );

                let mut w = open(store.clone(), &pin).await;
                w.use_session(session).unwrap();
                let e = w.append(Entry::new(Kind::Note)).await.unwrap();
                let r = report(&store, &pin).await;
                assert_eq!(r.broken, None, "{step}");
                // Odd steps put a batch, even steps swap HEAD. Unless the crash came before a put,
                // the interrupted entry's batch exists: under HEAD already, or rolled forward now.
                // Never twice.
                let landed = at % 2 == 0 || after;
                let expected = 2 + written + u64::from(landed) + 1;
                assert_eq!(r.entries, e.seq, "{step}");
                assert_eq!(r.entries, expected, "{step}");
            }
        }
    }
}

fn notes(n: usize) -> Vec<Entry> {
    (0..n).map(|_| Entry::new(Kind::Note)).collect()
}

/// Every 1,000 entries the writer puts a checkpoint signed by its session key, keeps a copy
/// outside the store, and verify checks the stream against it.
#[tokio::test]
async fn checkpoints_every_thousand_entries() {
    for (kind, store) in stores("checkpoints").await {
        let local = tmp(&format!("checkpoints-local-{kind}")).join("checkpoint.note");
        let (w, sk) = new_stream(store.clone()).await;
        let mut w = w.with_checkpoints(Some(local.clone())).await.unwrap();
        w.append_batch(notes(500)).await;
        assert_eq!(w.hook().size(), 0, "{kind}: not due yet");
        w.append_batch(notes(500)).await;
        // 2 (genesis, session) + 1,000.
        assert_eq!(w.hook().size(), 1002, "{kind}");
        let note = store.get(&checkpoint::key(1002)).await.unwrap().unwrap();
        assert_eq!(std::fs::read(&local).unwrap(), note.bytes);
        let n = tenbri_merkle::Note::parse(&note.bytes).unwrap();
        let session = w.session().unwrap().signing.verifying_key();
        assert_eq!(n.signed_by(&session), Some(true), "{kind}");
        w.append(Entry::new(Kind::Note)).await.unwrap();

        let r = report(&store, &sk.fingerprint()).await;
        assert_eq!(
            (r.broken, r.entries, r.checkpoint),
            (None, 1003, Some(1002)),
            "{kind}"
        );
        // A reopened writer picks up where the last checkpoint was.
        drop(w);
        let w = open(store.clone(), &sk.fingerprint()).await;
        let mut w = w.with_checkpoints(Some(local)).await.unwrap();
        assert_eq!(w.hook().size(), 1002);
        w.append_batch(notes(10)).await;
        assert_eq!(w.hook().size(), 1002, "{kind}: 11 entries since, not due");
    }
}

/// Someone with access to the store puts an older HEAD back and deletes the batches after it:
/// the older HEAD is validly signed, so the stream alone still verifies once its checkpoints are
/// gone too. The writer refuses to open below the checkpoint it keeps locally.
#[tokio::test]
async fn head_rolled_back_below_a_checkpoint_is_refused() {
    for (kind, store) in stores("rollback").await {
        let local = tmp(&format!("rollback-local-{kind}")).join("checkpoint.note");
        let (w, sk) = new_stream(store.clone()).await;
        let pin = sk.fingerprint();
        let mut w = w.with_checkpoints(Some(local.clone())).await.unwrap();
        w.append_batch(notes(3)).await;
        let old = store.get("HEAD").await.unwrap().unwrap().bytes;
        let old_seq = w.head().seq;
        w.append_batch(notes(1000)).await;
        assert_eq!(w.hook().size(), 1005, "{kind}");
        drop(w);

        // The rollback: HEAD swapped back, the batches after it deleted.
        let now = store.get("HEAD").await.unwrap().unwrap();
        assert!(matches!(
            store
                .compare_and_swap("HEAD", Some(&now.version), &old)
                .await
                .unwrap(),
            Swap::Swapped(_)
        ));
        for l in store.list("batches/").await.unwrap() {
            if batch_seq(&l.key).is_some_and(|s| s > old_seq) {
                store.delete(&l.key).await.unwrap();
            }
        }
        let truncated = |r: Result<Writer<AnyStore, Checkpoints>, WriteError>| matches!(r, Err(WriteError::Broken(b)) if b.error.code == Code::Truncated);

        // The stream's own checkpoint is still there: verify and the writer both refuse.
        let r = report(&store, &pin).await;
        assert_eq!(r.broken.unwrap().error.code, Code::Truncated, "{kind}");
        let w = Writer::open(store.clone(), Some(&pin)).await.unwrap();
        assert!(truncated(w.with_checkpoints(None).await), "{kind}");

        // Its checkpoints deleted as well, the stream verifies, but not against the local copy.
        for l in store.list("checkpoints/").await.unwrap() {
            store.delete(&l.key).await.unwrap();
        }
        let r = report(&store, &pin).await;
        assert_eq!(
            (r.broken, r.entries, r.checkpoint),
            (None, old_seq, None),
            "{kind}"
        );
        let w = Writer::open(store.clone(), Some(&pin)).await.unwrap();
        assert!(
            truncated(w.with_checkpoints(Some(local.clone())).await),
            "{kind}"
        );
        // Without it, nothing tells; that is what the local copy is for.
        let w = Writer::open(store.clone(), Some(&pin)).await.unwrap();
        assert!(w.with_checkpoints(None).await.is_ok());
    }
}

/// A lane closes intents open longer than `reconcile_after` in its next batch, but not one the
/// batch holds the outcome of.
#[tokio::test]
async fn lane_reconciles_stale_intents() {
    for (kind, store) in stores("lane-reconcile").await {
        let (mut w, sk) = new_stream(store.clone()).await;
        let mut old = decision("reply_ticket");
        old.ts = tenbri_core::encoding::format_ts(now_ms() - 2 * 3_600_000);
        let a = w.intent(old.clone()).await.unwrap();
        let b = w.intent(old).await.unwrap();
        let lane = Lane::spawn(w, LaneConfig::default());
        let o = lane.outcome(&b, Status::Ok).await.unwrap();
        let mut r = Reader::new(&store, Some(&sk.fingerprint()));
        let entries = r.poll().await.unwrap();
        let reconciled: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == Kind::Reconcile)
            .collect();
        assert_eq!(reconciled.len(), 1, "{kind}");
        assert_eq!(reconciled[0].intent.as_deref(), Some(a.id.as_str()));
        assert_eq!(
            reconciled[0].seq + 1,
            o.seq,
            "{kind}: in the same batch, first"
        );
        assert!(r.chain().open_intents().values().all(|o| o.reconciled));
    }
}
