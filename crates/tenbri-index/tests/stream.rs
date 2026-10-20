//! The index on real streams: built incrementally as entries are appended, rebuilt after it is
//! deleted, refusing a stream that no longer extends it, current to the latest checkpoint, and
//! keeping erased subjects out.

use std::path::{Path, PathBuf};

use tenbri_core::{
    Action, Entry, Input, Kind as EntryKind, Phase, Principal, PrincipalKind, Rule, Source, Status,
    Trace,
};
use tenbri_index::{Backend, Filter, Kind, Page, ref_version, search, update};
use tenbri_keys::{Key, SESSION_LIFETIME_MS};
use tenbri_store::LocalStore;
use tenbri_writer::{Checkpoints, Reader, Writer, now_ms};

fn local(dir: PathBuf) -> LocalStore {
    std::fs::create_dir_all(&dir).unwrap();
    LocalStore::open(dir).unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-index-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

/// The `n`th decision: its fields cycle so that filters select different subsets.
fn intent(n: usize) -> Entry {
    Entry {
        principal: Some(Principal {
            kind: PrincipalKind::Agent,
            id: ["support-assistant", "refund-bot"][n % 2].into(),
        }),
        action: Some(Action {
            r#type: ["reply_ticket", "issue_refund", "close_ticket"][n % 3].into(),
            target: Some(format!("zendesk:ticket/{}", n % 4)),
        }),
        subject: (n % 5 == 0).then(|| "subj-1".into()),
        inputs: Some(vec![Input {
            r#ref: "policy:refund".into(),
            version: ["13", "14"][n % 2].into(),
            digest: format!("hmac-sha256:{:064x}", n),
        }]),
        rule: Some(Rule {
            r#ref: "rule:refund-limit".into(),
            version: ["1", "2"][n % 2].into(),
            result: "allow".into(),
        }),
        trace: (n % 3 == 0).then(|| Trace {
            trace_id: "0af7651916cd43dd8448eb211c80319c".into(),
            span_id: format!("{:016x}", n),
        }),
        source: Some(Source::Sdk),
        phase: Some(Phase::Intent),
        ..Entry::new(EntryKind::Decision)
    }
}

async fn write(w: &mut Writer<LocalStore, Checkpoints>, from: usize, to: usize) {
    for n in from..to {
        let i = w.intent(intent(n)).await.unwrap();
        let status = [Status::Ok, Status::Error, Status::Refused][n % 3];
        w.outcome(&i, status).await.unwrap();
    }
}

fn filters() -> Vec<Filter> {
    let f = Filter::default;
    vec![
        f(),
        Filter {
            inputs: vec![ref_version("policy:refund@14")],
            ..f()
        },
        Filter {
            action: Some("issue_refund".into()),
            ..f()
        },
        Filter {
            principal: Some("agent:refund-bot".into()),
            status: Some("ok".into()),
            ..f()
        },
        Filter {
            subject: Some("subj-1".into()),
            ..f()
        },
        Filter {
            rule: Some(ref_version("rule:refund-limit@2")),
            ..f()
        },
        Filter {
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".into()),
            target: Some("zendesk:ticket/3".into()),
            ..f()
        },
        Filter {
            since: Some("2000-01-01T00:00:00.000Z".into()),
            until: Some("2999-01-01T00:00:00.000Z".into()),
            after: 7,
            ..f()
        },
    ]
}

/// What a full, verified scan of the stream answers: seq and entry hash of each match.
async fn scan(store: &LocalStore, f: &Filter) -> Vec<(u64, String)> {
    let mut r = Reader::new(store, None);
    let entries = r.poll().await.unwrap();
    entries
        .iter()
        .zip(r.hashes())
        .filter(|(e, _)| {
            let line = String::from_utf8(tenbri_core::canon::to_vec(
                &tenbri_core::canon::from_serialize(e).unwrap(),
            ))
            .unwrap();
            f.matches_entry(e, &line)
        })
        .map(|(e, h)| (e.seq, format!("sha256:{}", tenbri_core::encoding::hex(h))))
        .collect()
}

fn hits(p: &Page) -> Vec<(u64, String)> {
    p.hits.iter().map(|h| (h.seq, h.hash.clone())).collect()
}

async fn same_as_scan(ix: &dyn Backend, store: &LocalStore) {
    for f in filters() {
        let want = scan(store, &f).await;
        assert!(!want.is_empty() || f.after > 0, "{f:?} matches nothing");
        assert_eq!(
            hits(&search(ix, &f, 10_000).unwrap()),
            want,
            "{} {f:?}",
            ix.kind()
        );
    }
}

#[tokio::test]
async fn incremental_rebuild_and_divergence() {
    let dir = tmp("stream");
    let store = local(dir.join("s"));
    let sk = Key::new_stream().unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let mut w = Writer::create(store.clone(), &sk, session)
        .await
        .unwrap()
        .with_checkpoints(None)
        .await
        .unwrap();
    write(&mut w, 0, 10).await;

    for kind in [Kind::Sqlite, Kind::Parquet] {
        let ixdir = dir.join(format!("ix-{kind}"));
        let mut ix = tenbri_index::open(kind, &ixdir).unwrap();
        let st = update(ix.as_mut(), &store).await.unwrap();
        assert_eq!((st.seq, &st.hash), (w.head().seq, &w.head().hash));
        assert_eq!(st.stream, w.head().stream);
        same_as_scan(ix.as_ref(), &store).await;
        // Nothing new: nothing changes.
        assert_eq!(update(ix.as_mut(), &store).await.unwrap(), st);
    }

    // Snapshot the stream, then append more: the indexes catch up from where they are.
    copy_dir(&dir.join("s"), &dir.join("old"));
    write(&mut w, 10, 25).await;
    for kind in [Kind::Sqlite, Kind::Parquet] {
        let ixdir = dir.join(format!("ix-{kind}"));
        let mut ix = tenbri_index::find(&ixdir).unwrap().unwrap();
        assert_eq!(ix.kind(), kind);
        let before = ix.state().unwrap().unwrap().seq;
        let st = update(ix.as_mut(), &store).await.unwrap();
        assert!(st.seq > before);
        assert_eq!(st.seq, w.head().seq);
        same_as_scan(ix.as_ref(), &store).await;
        let page = search(ix.as_ref(), &Filter::default(), 5).unwrap();
        assert_eq!(page.state.unwrap(), st);
        assert_eq!(page.next, Some(5));

        // The old copy is behind the index: refused, and the index is left as it was.
        let old = local(dir.join("old"));
        let e = update(ix.as_mut(), &old).await.unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        // Another stream: refused.
        let other = local(dir.join(format!("other-{kind}")));
        Writer::create(
            other.clone(),
            &Key::new_stream().unwrap(),
            Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
        )
        .await
        .unwrap();
        let e = update(ix.as_mut(), &other).await.unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        assert_eq!(ix.state().unwrap().unwrap(), st);

        // Deleted and rebuilt: the same answers.
        drop(ix);
        tenbri_index::remove(&ixdir).unwrap();
        assert!(tenbri_index::find(&ixdir).unwrap().is_none());
        let mut ix = tenbri_index::open(kind, &ixdir).unwrap();
        assert_eq!(
            tenbri_index::rebuild(ix.as_mut(), &store).await.unwrap(),
            st
        );
        same_as_scan(ix.as_ref(), &store).await;
        // rebuild also recovers from the other stream.
        let st = tenbri_index::rebuild(ix.as_mut(), &other).await.unwrap();
        assert_eq!(ix.state().unwrap().unwrap(), st);
        assert_eq!(
            search(ix.as_ref(), &Filter::default(), 100)
                .unwrap()
                .hits
                .len() as u64,
            st.seq
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The index records the stream's latest checkpoint at or below what it holds.
#[tokio::test]
async fn current_to_a_checkpoint() {
    let dir = tmp("checkpoint");
    let store = local(dir.join("s"));
    let sk = Key::new_stream().unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let mut w = Writer::create(store.clone(), &sk, session)
        .await
        .unwrap()
        .with_checkpoints(None)
        .await
        .unwrap();
    let mut ix = tenbri_index::open(Kind::Sqlite, &dir.join("ix")).unwrap();
    assert_eq!(update(ix.as_mut(), &store).await.unwrap().checkpoint, None);
    for chunk in 0..5 {
        let batch: Vec<Entry> = (0..250).map(|n| intent(chunk * 250 + n)).collect();
        for r in w.append_batch(batch).await {
            r.unwrap();
        }
    }
    let st = update(ix.as_mut(), &store).await.unwrap();
    let cp = tenbri_index::latest_checkpoint(&store, st.seq)
        .await
        .unwrap();
    assert!(cp.is_some_and(|c| c >= 1000), "{cp:?}");
    assert_eq!(st.checkpoint, cp);
    let _ = std::fs::remove_dir_all(&dir);
}

fn subject(ix: &dyn Backend, s: &str) -> Vec<u64> {
    let f = Filter {
        subject: Some(s.into()),
        ..Filter::default()
    };
    search(ix, &f, 1000)
        .unwrap()
        .hits
        .iter()
        .map(|h| h.seq)
        .collect()
}

/// `tenbri erase` removes a subject's rows; updates and rebuilds keep them out once the stream
/// records the erasure, and index the subject's later entries again.
#[tokio::test]
async fn erased_subjects_stay_out() {
    let dir = tmp("erase");
    let store = local(dir.join("s"));
    let sk = Key::new_stream().unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let mut w = Writer::create(store.clone(), &sk, session)
        .await
        .unwrap()
        .with_checkpoints(None)
        .await
        .unwrap();
    write(&mut w, 0, 10).await;
    let mut ixs: Vec<_> = [Kind::Sqlite, Kind::Parquet]
        .into_iter()
        .map(|k| tenbri_index::open(k, &dir.join(format!("ix-{k}"))).unwrap())
        .collect();
    for ix in &mut ixs {
        update(ix.as_mut(), &store).await.unwrap();
        assert!(!subject(ix.as_ref(), "subj-1").is_empty());
        let all = search(ix.as_ref(), &Filter::default(), 1000)
            .unwrap()
            .hits
            .len();
        let st = ix.state().unwrap();
        ix.erase("subj-1").unwrap();
        assert!(subject(ix.as_ref(), "subj-1").is_empty(), "{}", ix.kind());
        let left = search(ix.as_ref(), &Filter::default(), 1000)
            .unwrap()
            .hits
            .len();
        assert!(left > 0 && left < all, "{}: {left} of {all}", ix.kind());
        assert_eq!(ix.state().unwrap(), st);
    }

    // The erasure note: updates and rebuilds leave the subject out, and list the note.
    let note = w
        .append(tenbri_crypt::erasure_note(Some("subj-1"), "dsr:1", None))
        .await
        .unwrap();
    let erasures = Filter {
        action: Some("tenbri.erase".into()),
        ..Filter::default()
    };
    for ix in &mut ixs {
        for st in [
            update(ix.as_mut(), &store).await.unwrap(),
            tenbri_index::rebuild(ix.as_mut(), &store).await.unwrap(),
        ] {
            assert_eq!(st.seq, note.seq);
            assert!(subject(ix.as_ref(), "subj-1").is_empty(), "{}", ix.kind());
            let page = search(ix.as_ref(), &erasures, 10).unwrap();
            assert_eq!(page.hits.len(), 1);
            assert_eq!(page.hits[0].seq, note.seq);
        }
    }

    // The subject's entries after the erasure are indexed, and survive a rebuild.
    write(&mut w, 10, 20).await;
    let after = scan(
        &store,
        &Filter {
            subject: Some("subj-1".into()),
            after: note.seq,
            ..Filter::default()
        },
    )
    .await;
    assert!(!after.is_empty());
    let after: Vec<u64> = after.into_iter().map(|(seq, _)| seq).collect();
    for ix in &mut ixs {
        update(ix.as_mut(), &store).await.unwrap();
        assert_eq!(subject(ix.as_ref(), "subj-1"), after, "{}", ix.kind());
        tenbri_index::rebuild(ix.as_mut(), &store).await.unwrap();
        assert_eq!(subject(ix.as_ref(), "subj-1"), after, "{}", ix.kind());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
