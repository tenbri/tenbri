//! Property: any edit, reorder, deletion or insertion inside a stream is detected, at the first
//! entry it touches. Truncating the tail is only detectable against a checkpoint held outside
//! the operator (0.1.0-alpha.2), or against HEAD (tenbri-writer's tests), so it is not tried here.

use proptest::prelude::*;
use tenbri_core::sign::{SigningKey, encode_key, entry_hash, fingerprint, sign_entry, stream_id};
use tenbri_core::{Chain, Entry, KeyEvent, Kind, Role, encoding};

fn stream(notes: &[u64]) -> (String, Vec<Vec<u8>>) {
    let a = SigningKey::from_bytes(&[1; 32]);
    let s = SigningKey::from_bytes(&[2; 32]);
    let sid = stream_id(&a.verifying_key());
    let mut lines: Vec<Vec<u8>> = vec![];
    let mut push = |mut e: Entry, k: &SigningKey, signer: &str| {
        let seq = lines.len() as u64 + 1;
        e.id = encoding::ulid(((1_700_000_000_000u128 + seq as u128) << 80) | seq as u128);
        e.stream = sid.clone();
        e.seq = seq;
        e.ts = encoding::format_ts(1_700_000_000_000 + seq as i64);
        e.prev = lines.last().map(|l| entry_hash(l));
        e.signer = signer.into();
        lines.push(sign_entry(&mut e, k).unwrap());
    };
    let certify = |k: &SigningKey, id: &str, role, not_after| Entry {
        key: Some(KeyEvent::Certify {
            id: id.into(),
            public: encode_key(&k.verifying_key()),
            role,
            not_after,
        }),
        ..Entry::new(Kind::Key)
    };
    push(certify(&a, "stream:a", Role::Stream, None), &a, "stream:a");
    push(
        certify(
            &s,
            "sess:1",
            Role::Session,
            Some("2099-01-01T00:00:00.000Z".into()),
        ),
        &a,
        "stream:a",
    );
    for n in notes {
        let mut e = Entry::new(Kind::Note);
        e.ext = Some(serde_json::from_value(serde_json::json!({ "n": n })).unwrap());
        push(e, &s, "sess:1");
    }
    (fingerprint(&a.verifying_key()), lines)
}

/// The first broken sequence number, if any.
fn first_broken(pin: &str, lines: &[Vec<u8>]) -> Option<u64> {
    let mut c = Chain::new(Some(pin));
    for l in lines {
        if let Err(b) = c.push(l) {
            return Some(b.seq);
        }
    }
    c.invalidated().map(|b| b.seq)
}

#[derive(Debug, Clone)]
enum Tamper {
    Flip { line: usize, byte: usize, mask: u8 },
    Swap(usize, usize),
    Delete(usize),
    Duplicate(usize),
}

fn tamper() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        (any::<usize>(), any::<usize>(), 1..=255u8).prop_map(|(line, byte, mask)| Tamper::Flip {
            line,
            byte,
            mask
        }),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Tamper::Swap(a, b)),
        any::<usize>().prop_map(Tamper::Delete),
        any::<usize>().prop_map(Tamper::Duplicate),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn every_tamper_is_detected(notes in prop::collection::vec(any::<u64>().prop_map(|n| n % (1 << 53)), 1..12), t in tamper()) {
        let (pin, mut lines) = stream(&notes);
        prop_assert_eq!(first_broken(&pin, &lines), None);
        let n = lines.len();
        let expected = match t {
            Tamper::Flip { line, byte, mask } => {
                let l = line % n;
                let b = byte % lines[l].len();
                lines[l][b] ^= mask;
                l + 1
            }
            Tamper::Swap(a, b) => {
                let (a, b) = (a % n, b % n);
                prop_assume!(a != b);
                lines.swap(a, b);
                a.min(b) + 1
            }
            Tamper::Delete(i) => {
                // Not the last entry: dropping the tail is truncation.
                let i = i % (n - 1);
                lines.remove(i);
                i + 1
            }
            Tamper::Duplicate(i) => {
                let i = i % n;
                let l = lines[i].clone();
                lines.insert(i + 1, l);
                i + 2
            }
        };
        prop_assert_eq!(first_broken(&pin, &lines), Some(expected as u64));
    }
}
