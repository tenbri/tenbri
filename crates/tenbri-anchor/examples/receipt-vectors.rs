//! Writes spec/vectors/receipts.json from fixed seeds:
//! `cargo run -p tenbri-anchor --features test-tsa --example receipt-vectors -- spec/vectors`.
//!
//! Released vectors are frozen; this exists so the drafts can be regenerated until then, and so
//! anyone can see how each case was made. The streams are tenbri-merkle's test streams (the seeds
//! of keys.json); the timestamp authority is `test_tsa::TestTsa` from a fixed seed.

#[path = "../../tenbri-merkle/tests/common/mod.rs"]
mod common;

use std::path::Path;

use common::{Stream, key};
use serde_json::{Value as J, json};
use tenbri_anchor::test_tsa::TestTsa;
use tenbri_core::encoding;
use tenbri_core::sign::{encode_key, fingerprint};
use tenbri_merkle::{Checkpoint, receipt};

/// The time the test TSA gives: 2026-10-20T12:00:00Z.
const AT: u64 = 1_792_497_600;

/// A receipt over `s`'s first `size` entries proving `seqs`, with the key history.
fn make(s: &Stream, size: usize, seqs: &[u64], tokens: &[Vec<u8>]) -> Vec<u8> {
    let note = Checkpoint::new(&s.id, &s.hashes()[..size]).sign(&s.s1);
    build(s, &note, size, seqs, tokens)
}

/// The key entries up to `size`, and `seqs`, under `note`.
fn build(s: &Stream, note: &[u8], size: usize, seqs: &[u64], tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut entries: Vec<(u64, &[u8])> = s.lines[..size]
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(r#""kind":"key""#))
        .map(|(i, l)| (i as u64 + 1, l.as_bytes()))
        .collect();
    entries.extend(
        seqs.iter()
            .map(|&q| (q, s.lines[q as usize - 1].as_bytes())),
    );
    receipt::build(note, &s.hashes(), &entries, tokens).expect("a receipt")
}

fn text(note: &[u8]) -> Vec<u8> {
    let n = tenbri_merkle::Note::parse(note).unwrap();
    n.text().as_bytes().to_vec()
}

fn edit(r: &[u8], f: impl FnOnce(&mut J)) -> Vec<u8> {
    let mut j: J = serde_json::from_slice(r).unwrap();
    f(&mut j);
    serde_json::to_vec(&j).unwrap()
}

/// The receipt's entry item at `seq`.
fn item(j: &mut J, seq: u64) -> &mut J {
    j["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|i| i["entry"]["seq"] == seq)
        .unwrap()
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: receipt-vectors <spec/vectors>");
    let tsa = TestTsa::new(b"\x01 tenbri vector tsa");
    let roots = tenbri_anchor::parse_roots(tsa.root_pem().as_bytes()).unwrap();
    let other_tsa = TestTsa::new(b"\x02 tenbri vector tsa, not pinned");

    // genesis (1), sess:a1 (2), an intent (3) and its outcome (4), sess:a2 (5), notes (6 to 9).
    let mut s = Stream::new();
    let s1 = s.s1.clone();
    let decision = |phase: &str| {
        json!({"kind": "decision", "phase": phase, "source": "sdk",
            "principal": {"kind": "agent", "id": "support-assistant"},
            "action": {"type": "reply_ticket", "target": "zendesk:ticket/4521"}})
    };
    s.push(decision("intent"), &s1, "sess:a1");
    let mut outcome = decision("outcome");
    outcome["intent"] = s.json(3)["id"].clone();
    outcome["status"] = json!("ok");
    s.push(outcome, &s1, "sess:a1");
    let a = s.a.clone();
    s.push(s.certify("sess:a2", &key("s2"), "session"), &a, "stream:a");
    for n in 0..4 {
        s.note(n);
    }
    s.chain().expect("the stream verifies");
    let pin = fingerprint(&s.a.verifying_key());
    let n = s.lines.len();

    let valid = make(&s, n, &[4], &[]);
    let note = Checkpoint::new(&s.id, &s.hashes()).sign(&s.s1);
    let token = tsa.respond(&text(&note), AT, None);
    let stamped = build(&s, &note, n, &[4], std::slice::from_ref(&token));

    // An entry signed after its session key's not_after: entry 4 dated two days later.
    let mut late = Stream::new();
    late.push(decision("intent"), &s1, "sess:a1");
    let mut j = decision("outcome");
    j["intent"] = late.json(3)["id"].clone();
    j["status"] = json!("ok");
    j["ts"] = json!(encoding::format_ts(1_792_000_000_000 + 2 * 86_400_000));
    late.push(j, &s1, "sess:a1");

    // sess:a1 signs entry 3, then the stream key revokes it from seq 3 at seq 5.
    let mut revoked = Stream::new();
    revoked.push(decision("intent"), &s1, "sess:a1");
    revoked.push(s.certify("sess:a2", &key("s2"), "session"), &a, "stream:a");
    revoked.push(
        json!({"kind": "key", "key": {"op": "revoke", "id": "sess:a1", "from": 3}}),
        &a,
        "stream:a",
    );
    let revoked_note = Checkpoint::new(&revoked.id, &revoked.hashes()).sign(&key("s2"));

    // The key holder's rewrite of entry 4, re-signed by sess:a1: it verifies on its own, but
    // not against the checkpoint.
    let mut rewritten = s.clone();
    let mut e4 = s.json(4);
    e4["action"]["target"] = json!("zendesk:ticket/9999");
    rewritten.rewrite(4, vec![e4]);
    let line4: J = serde_json::from_str(&rewritten.lines[3]).unwrap();
    let resigned = edit(&valid, |j| item(j, 4)["entry"] = line4);

    let other = Stream {
        id: tenbri_core::sign::stream_id(&key("b").verifying_key()),
        ..s.clone()
    };
    let foreign_note = Checkpoint::new(&other.id, &s.hashes()).sign(&s.s1);
    let attacker_note = Checkpoint::new(&s.id, &s.hashes()).sign(&key("attacker"));
    let short_note = Checkpoint::new(&s.id, &s.hashes()[..n - 1]).sign(&s.s1);
    let wrong_pin = fingerprint(&key("b").verifying_key());

    let cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("valid", &pin, valid.clone()),
        ("valid-several-entries", &pin, make(&s, n, &[3, 4], &[])),
        ("valid-key-entry", &pin, make(&s, n, &[], &[])),
        (
            "valid-at-a-smaller-checkpoint",
            &pin,
            make(&s, 4, &[4], &[]),
        ),
        ("valid-timestamped", &pin, stamped.clone()),
        (
            "valid-whitespace-and-member-order",
            &pin,
            serde_json::to_vec_pretty(&serde_json::from_slice::<J>(&valid).unwrap()).unwrap(),
        ),
        (
            "tampered-entry",
            &pin,
            edit(&valid, |j| {
                item(j, 4)["entry"]["action"]["target"] = json!("zendesk:ticket/9999")
            }),
        ),
        ("tampered-entry-re-signed", &pin, resigned),
        (
            "tampered-proof",
            &pin,
            edit(&valid, |j| {
                let p = &mut item(j, 4)["proof"][0];
                let mut h: Vec<char> = p.as_str().unwrap().chars().collect();
                h[7] = if h[7] == '0' { '1' } else { '0' };
                *p = json!(h.into_iter().collect::<String>());
            }),
        ),
        (
            "wrong-checkpoint",
            &pin,
            edit(&valid, |j| {
                j["checkpoint"] = json!(String::from_utf8(short_note.clone()).unwrap())
            }),
        ),
        (
            "checkpoint-of-another-stream",
            &pin,
            edit(&valid, |j| {
                j["checkpoint"] = json!(String::from_utf8(foreign_note.clone()).unwrap())
            }),
        ),
        (
            "checkpoint-not-signed-by-the-stream",
            &pin,
            edit(&valid, |j| {
                j["checkpoint"] = json!(String::from_utf8(attacker_note.clone()).unwrap())
            }),
        ),
        (
            "entry-beyond-the-checkpoint",
            &pin,
            edit(&make(&s, 4, &[4], &[]), |j| {
                let e = serde_json::from_str::<J>(&s.lines[5]).unwrap();
                j["entries"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"entry": e, "proof": []}));
            }),
        ),
        ("wrong-key", &wrong_pin, valid.clone()),
        (
            "no-genesis-entry",
            &pin,
            edit(&valid, |j| {
                j["entries"].as_array_mut().unwrap().remove(0);
            }),
        ),
        (
            "session-certification-missing",
            &pin,
            edit(&valid, |j| {
                j["entries"].as_array_mut().unwrap().remove(1);
            }),
        ),
        ("expired-session-key", &pin, make(&late, 4, &[4], &[])),
        (
            "revoked-session-key",
            &pin,
            build(&revoked, &revoked_note, 5, &[3], &[]),
        ),
        (
            "tsa-token-for-another-checkpoint",
            &pin,
            build(
                &s,
                &note,
                n,
                &[4],
                &[tsa.respond(&text(&short_note), AT, None)],
            ),
        ),
        (
            "tsa-token-from-an-unpinned-authority",
            &pin,
            build(
                &s,
                &note,
                n,
                &[4],
                &[other_tsa.respond(&text(&note), AT, None)],
            ),
        ),
        (
            "tsa-token-time-changed",
            &pin,
            build(&s, &note, n, &[4], &[tsa.respond_changed(&text(&note), AT)]),
        ),
        (
            "unknown-member",
            &pin,
            edit(&valid, |j| j["note"] = json!("hello")),
        ),
        ("unknown-version", &pin, edit(&valid, |j| j["v"] = json!(2))),
    ];

    let expected = [
        ("valid", None),
        ("valid-several-entries", None),
        ("valid-key-entry", None),
        ("valid-at-a-smaller-checkpoint", None),
        ("valid-timestamped", None),
        ("valid-whitespace-and-member-order", None),
        ("tampered-entry", Some("bad_signature")),
        ("tampered-entry-re-signed", Some("bad_proof")),
        ("tampered-proof", Some("bad_proof")),
        ("wrong-checkpoint", Some("bad_proof")),
        ("checkpoint-of-another-stream", Some("wrong_stream")),
        (
            "checkpoint-not-signed-by-the-stream",
            Some("unknown_signer"),
        ),
        ("entry-beyond-the-checkpoint", Some("bad_proof")),
        ("wrong-key", Some("untrusted_root")),
        ("no-genesis-entry", Some("bad_receipt")),
        ("session-certification-missing", Some("unknown_signer")),
        ("expired-session-key", Some("key_expired")),
        ("revoked-session-key", Some("key_revoked")),
        ("tsa-token-for-another-checkpoint", Some("bad_timestamp")),
        (
            "tsa-token-from-an-unpinned-authority",
            Some("bad_timestamp"),
        ),
        ("tsa-token-time-changed", Some("bad_timestamp")),
        ("unknown-member", Some("bad_receipt")),
        ("unknown-version", Some("bad_receipt")),
    ];

    let mut out = vec![];
    for ((name, pin, bytes), (want_name, want)) in cases.iter().zip(expected) {
        assert_eq!(*name, want_name);
        let result = match tenbri_anchor::verify_receipt(bytes, pin, Some(&roots)) {
            Ok(v) => json!({
                "proves": v.receipt.proved().iter().map(|e| e.seq).collect::<Vec<_>>(),
                "size": v.receipt.checkpoint.size,
                "timestamps": v.timestamps.unwrap().iter().map(|t| t.unix).collect::<Vec<_>>(),
            }),
            Err(e) => json!({"error": e.code.as_str()}),
        };
        assert_eq!(result["error"].as_str(), want, "{name}: {result}");
        out.push(json!({
            "name": name,
            "pin": pin,
            "receipt": String::from_utf8(bytes.clone()).unwrap(),
            "result": result,
        }));
    }
    let doc = json!({
        "tsa_roots": tsa.root_pem(),
        "stream_key_pub": encode_key(&s.a.verifying_key()),
        "cases": out,
    });
    let path = Path::new(&dir).join("receipts.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
