use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tenbri_core::{Code, Entry, Kind, Principal, PrincipalKind, Status};
use tenbri_keys::{Key, SESSION_LIFETIME_MS};
use tenbri_store::{Listed, LocalStore, Object, Put, Store, Swap, Version};
use tenbri_writer::{GC_MIN_AGE, Report, WriteError, Writer, batch_key, gc, now_ms, verify};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-writer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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

async fn new_stream(dir: &Path) -> (Writer<LocalStore>, Key) {
    let sk = Key::new_stream().unwrap();
    let w = Writer::create(
        LocalStore::open(dir).unwrap(),
        &sk,
        Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
    )
    .await
    .unwrap();
    (w, sk)
}

async fn report(dir: &Path, pin: &str) -> Report {
    verify(&LocalStore::open(dir).unwrap(), Some(pin))
        .await
        .unwrap()
}

#[tokio::test]
async fn stream_vectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("streams.json")).unwrap()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let r = verify(
            &LocalStore::open(root.join("streams").join(name)).unwrap(),
            c["pin"].as_str(),
        )
        .await
        .unwrap();
        let want = &c["result"];
        if want["ok"].as_bool().unwrap() {
            assert_eq!(
                (r.broken, r.entries),
                (None, want["entries"].as_u64().unwrap()),
                "{name}"
            );
        } else {
            let b = r.broken.unwrap_or_else(|| panic!("{name} verified"));
            assert_eq!(
                (b.seq, b.error.code.as_str()),
                (
                    want["seq"].as_u64().unwrap(),
                    want["error"].as_str().unwrap()
                ),
                "{name}"
            );
        }
    }
}

#[tokio::test]
async fn intent_outcome_rotation_revocation_and_reopen() {
    let dir = tmp("lifecycle");
    let (mut w, sk) = new_stream(&dir).await;
    let pin = sk.fingerprint();
    let i = w.intent(decision("reply_ticket")).await.unwrap();
    let o = w.outcome(&i, Status::Ok).await.unwrap();
    assert_eq!(
        (i.seq, o.seq, o.intent.as_deref()),
        (3, 4, Some(i.id.as_str()))
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

    let r = report(&dir, &pin).await;
    assert_eq!((r.broken, r.entries, r.pinned), (None, n, true));
    // A verifier pinning another key refuses the stream at its genesis.
    let other = Key::new_stream().unwrap().fingerprint();
    assert_eq!(
        report(&dir, &other).await.broken.unwrap().error.code,
        Code::UntrustedRoot
    );

    // Reopened, the writer continues where the stream ends, with a certified session only.
    let mut w = Writer::open(LocalStore::open(&dir).unwrap(), Some(&pin))
        .await
        .unwrap();
    assert!(matches!(
        w.append(Entry::new(Kind::Note)).await,
        Err(WriteError::NoSession(_))
    ));
    let s = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    assert!(w.use_session(s.clone()).is_err(), "not certified");
    w.certify_session(&sk2, s).await.unwrap();
    w.append(Entry::new(Kind::Note)).await.unwrap();
    assert_eq!(report(&dir, &pin).await.entries, n + 2);
    // A bad entry is refused before anything is written.
    let mut bad = decision("x");
    bad.status = Some(Status::Ok);
    assert!(matches!(w.intent(bad).await, Err(WriteError::Rejected(_))));
    assert_eq!(report(&dir, &pin).await.entries, n + 2);
}

#[tokio::test]
async fn roll_forward_conflict_race_and_gc() {
    let dir = tmp("protocol");
    let (mut w1, sk) = new_stream(&dir).await;
    let pin = sk.fingerprint();
    let session = w1.session().unwrap().clone();
    let mut w2 = Writer::open(LocalStore::open(&dir).unwrap(), Some(&pin))
        .await
        .unwrap();
    w2.use_session(session.clone()).unwrap();

    // Two writers with the same view: each batch has exactly one winner, nothing is lost.
    let a = w1.append(Entry::new(Kind::Note)).await.unwrap();
    let b = w2.append(Entry::new(Kind::Note)).await.unwrap();
    assert_eq!((a.seq, b.seq), (3, 4));
    assert_eq!(report(&dir, &pin).await.entries, 4);

    // A batch left by a crashed writer (written, HEAD not moved) is invisible, then rolled forward.
    let mut orphan = Entry::new(Kind::Note);
    orphan.id = tenbri_writer::new_id(now_ms()).unwrap();
    let mut w3 = Writer::open(LocalStore::open(&dir).unwrap(), Some(&pin))
        .await
        .unwrap();
    w3.use_session(session.clone()).unwrap();
    let store = LocalStore::open(&dir).unwrap();
    let mut e = orphan.clone();
    e.ts = tenbri_core::encoding::format_ts(now_ms());
    let line = {
        let mut e = Entry {
            seq: 5,
            stream: w3.head().stream.clone(),
            prev: Some(w3.head().hash.clone()),
            signer: session.id.clone(),
            ..e
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
    assert_eq!(report(&dir, &pin).await.entries, 4, "orphans are invisible");
    assert!(
        gc(&store, Some(&pin), Duration::ZERO)
            .await
            .unwrap()
            .is_empty(),
        "a valid next batch is kept"
    );
    let c = w3.append(Entry::new(Kind::Note)).await.unwrap();
    assert_eq!(c.seq, 6, "rolled forward, then appended");
    assert_eq!(report(&dir, &pin).await.entries, 6);

    // A batch that does not chain blocks the writer with a conflict, until gc removes it.
    store
        .put_if_absent(&batch_key(7), b"{\"not\":\"an entry\"}\n")
        .await
        .unwrap();
    std::fs::write(dir.join("batches/.tmp-1-2-3"), b"partial").unwrap();
    assert!(matches!(
        w3.append(Entry::new(Kind::Note)).await,
        Err(WriteError::Conflict { seq: 7 })
    ));
    assert!(
        gc(&store, Some(&pin), GC_MIN_AGE).await.unwrap().is_empty(),
        "too young to remove"
    );
    let removed = gc(&store, Some(&pin), Duration::ZERO).await.unwrap();
    assert_eq!(removed, vec!["batches/.tmp-1-2-3".to_owned(), batch_key(7)]);
    assert_eq!(w3.append(Entry::new(Kind::Note)).await.unwrap().seq, 7);
    assert_eq!(report(&dir, &pin).await.broken, None);
}

/// A store that "crashes" at its `n`th write: before doing it, or after doing it but before the
/// caller hears back.
struct Crashing {
    inner: LocalStore,
    writes: AtomicUsize,
    at: usize,
    after: bool,
}

impl Crashing {
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

impl Store for Crashing {
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
    for at in 1..=6 {
        for after in [false, true] {
            let dir = tmp(&format!("crash-{at}-{after}"));
            let (w, sk) = new_stream(&dir).await;
            let (pin, session) = (sk.fingerprint(), w.session().unwrap().clone());
            drop(w);
            let store = Crashing {
                inner: LocalStore::open(&dir).unwrap(),
                writes: AtomicUsize::new(0),
                at,
                after,
            };
            let mut w = Writer::open(store, Some(&pin)).await.unwrap();
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
            assert!(result.is_err(), "step {at} after={after} did not crash");
            drop(w);

            let r = report(&dir, &pin).await;
            assert_eq!(r.broken, None, "step {at} after={after}");
            // The entry being written when it crashed is there only if HEAD moved to it.
            assert!(
                r.entries == 2 + written || r.entries == 3 + written,
                "step {at} after={after}: {r:?}"
            );

            let mut w = Writer::open(LocalStore::open(&dir).unwrap(), Some(&pin))
                .await
                .unwrap();
            w.use_session(session).unwrap();
            let e = w.append(Entry::new(Kind::Note)).await.unwrap();
            let r = report(&dir, &pin).await;
            assert_eq!(r.broken, None, "step {at} after={after}");
            // Odd steps put a batch, even steps swap HEAD. Unless the crash came before a put, the
            // interrupted entry's batch exists: under HEAD already, or rolled forward now. Never twice.
            let landed = at % 2 == 0 || after;
            let expected = 2 + written + u64::from(landed) + 1;
            assert_eq!(r.entries, e.seq, "step {at} after={after}");
            assert_eq!(r.entries, expected, "step {at} after={after}");
        }
    }
}
