//! Property tests: a key holder rewrites a stream so it verifies on its own; a checkpoint held
//! outside the operator still catches any edit, insertion, deletion, reorder or truncation of the
//! entries it covers. Changes after it stay undetected by it, as the spec says.

mod common;

use common::Stream;
use proptest::prelude::*;
use serde_json::json;
use tenbri_core::Code;
use tenbri_merkle::{Checkpoint, Note};

#[derive(Clone, Debug)]
enum Change {
    Truncate,
    Edit,
    Insert,
    Delete,
    Swap,
}

fn apply(s: &mut Stream, change: &Change, j: u64) {
    let len = s.lines.len() as u64;
    let rest = |s: &Stream, from: u64| (from..=len).map(|i| s.json(i)).collect::<Vec<_>>();
    match change {
        Change::Truncate => s.lines.truncate(j as usize - 1),
        Change::Edit => {
            let mut e = rest(s, j);
            e[0]["ext"] = json!({"x-test": {"n": "edited"}});
            s.rewrite(j, e);
        }
        Change::Insert => {
            let mut e = rest(s, j);
            e.insert(
                0,
                json!({"kind": "note", "id": tenbri_core::encoding::ulid(u128::MAX >> 3)}),
            );
            s.rewrite(j, e);
        }
        Change::Delete => {
            let e = rest(s, j + 1);
            s.rewrite(j, e);
        }
        Change::Swap => {
            let mut e = rest(s, j);
            e.swap(0, 1);
            s.rewrite(j, e);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn checkpoint_catches_changes_behind_it(
        notes in 2u64..20,
        k_pick in any::<prop::sample::Index>(),
        j_pick in any::<prop::sample::Index>(),
        change in prop_oneof![
            Just(Change::Truncate), Just(Change::Edit), Just(Change::Insert),
            Just(Change::Delete), Just(Change::Swap),
        ],
    ) {
        let mut s = Stream::new();
        for n in 0..notes {
            s.note(n);
        }
        let len = s.lines.len() as u64;
        // A checkpoint at k, signed by sess:a1 (certified at seq 2).
        let k = 2 + k_pick.index((len - 1) as usize) as u64;
        let note = Note::parse(&Checkpoint::new(&s.id, &s.hashes()[..k as usize]).sign(&s.s1)).unwrap();
        // The changed entry j: from seq 3 (keys stay) to the last that has a successor for Swap.
        let j = 3 + j_pick.index((len - 3) as usize) as u64;
        let mut t = s.clone();
        apply(&mut t, &change, j);
        let chain = t.chain().expect("the rewrite verifies on its own");
        let r = note.check(&chain, &t.hashes());
        if j > k {
            prop_assert!(r.is_ok(), "{change:?} at {j} after checkpoint {k}: {r:?}");
        } else {
            let b = r.expect_err("caught");
            let expect = if (t.lines.len() as u64) < k { Code::Truncated } else { Code::Fork };
            prop_assert_eq!(b.error.code, expect);
            prop_assert_eq!(b.seq, if expect == Code::Truncated { t.lines.len() as u64 + 1 } else { k });
        }
    }
}
