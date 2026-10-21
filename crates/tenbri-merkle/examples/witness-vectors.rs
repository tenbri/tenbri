//! Writes spec/vectors/witness.json from fixed seeds (Experimental: witnesses, spec/checkpoints.md,
//! section 6): `cargo run -p tenbri-merkle --features witness --example witness-vectors --
//! spec/vectors`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::path::Path;

use common::key;
use serde_json::json;
use tenbri_core::sign::encode_key;
use tenbri_merkle::checkpoint::{base64, unbase64};
use tenbri_merkle::witness::{self, Witness, cosign, cosignatures, log_vkey, request};
use tenbri_merkle::{Checkpoint, Hash, Note, receipt};

const T: u64 = 1_792_000_000;

fn main() {
    let dir = std::env::args().nth(1).expect("the output directory");
    let (session, ck) = (key("s1"), key("checkpoint"));
    let (w1k, w2k) = (key("witness1"), key("witness2"));
    let w = |name: &str, k: &tenbri_core::sign::SigningKey| Witness {
        name: name.into(),
        key: k.verifying_key(),
    };
    let (w1, w2) = (w("witness.example/w1", &w1k), w("witness.example/w2", &w2k));
    let leaves: Vec<Hash> = (1..=10u8).map(|i| [i; 32]).collect();
    let origin = "tnb1:170241c12e8724974ea3b10fe536b7d8";
    let cp = Checkpoint::new(origin, &leaves);
    let signed = String::from_utf8(cp.sign_with(&[&session, &ck])).unwrap();
    let text = cp.text();
    let c1 = cosign(&w1.name, &w1k, &text, T);
    let c2 = cosign(&w2.name, &w2k, &text, T + 5);
    let other_time = cosign(&w1.name, &w1k, &text, T + 1);
    let bytes = |l: &str| unbase64(l.trim_end().rsplit(' ').next().unwrap()).unwrap();
    let line = |b: &[u8]| format!("\u{2014} {} {}\n", w1.name, base64(b));
    // The signature with one bit flipped.
    let forged = {
        let mut b = bytes(&c1);
        b[40] ^= 1;
        line(&b)
    };
    // The cosignature at T + 1, presented as made at T.
    let swapped = {
        let (mut a, o) = (bytes(&c1), bytes(&other_time));
        a[12..].copy_from_slice(&o[12..]);
        line(&a)
    };

    // Another history of the same size, signed by the same keys: a split view.
    let mut forked_leaves = leaves.clone();
    forked_leaves[9] = [0xff; 32];
    let forked =
        String::from_utf8(Checkpoint::new(origin, &forked_leaves).sign_with(&[&session, &ck]))
            .unwrap();
    let case_on = |name: &str, base: &str, extra: &str, pinned: &[&Witness], need: usize| {
        let note = format!("{base}{extra}");
        let ws: Vec<Witness> = pinned.iter().map(|w| (*w).clone()).collect();
        let result = match cosignatures(&Note::parse(note.as_bytes()).unwrap(), &ws, need) {
            Ok(c) => {
                json!({"ok": c.iter().map(|c| json!({"name": c.name, "time": c.time})).collect::<Vec<_>>()})
            }
            Err(e) => json!({"error": e.code.as_str()}),
        };
        json!({"name": name, "note": note, "witnesses": ws.iter().map(Witness::vkey).collect::<Vec<_>>(), "need": need, "result": result})
    };
    let case = |name: &str, extra: &str, pinned: &[&Witness], need: usize| {
        case_on(name, &signed, extra, pinned, need)
    };
    let cases = vec![
        case("one-of-one", &c1, &[&w1], 1),
        case("two-of-two", &format!("{c1}{c2}"), &[&w1, &w2], 2),
        case("one-of-two-pinned", &c1, &[&w1, &w2], 1),
        case("missing-cosignature", &c1, &[&w1, &w2], 2),
        case("none-required", "", &[&w1], 0),
        case("unpinned-witness", &c2, &[&w1], 1),
        case("changed-signature", &forged, &[&w1], 1),
        case("changed-time", &swapped, &[&w1], 1),
        case_on("split-view", &forked, &c1, &[&w1], 1),
        case("same-witness-pinned-twice", &c1, &[&w1, &w1], 2),
        case(
            "second-line-by-witness-bad",
            &format!("{c1}{forged}"),
            &[&w1],
            1,
        ),
    ];

    // Receipts of a witnessed stream, checked by `witness::verify`: the checkpoint key's line too.
    let mut st = common::Stream::new();
    st.note(0);
    st.certify_checkpoint_key(&ck);
    st.note(1);
    let scp = Checkpoint::new(&st.id, &st.hashes());
    let snote = String::from_utf8(scp.sign_with(&[&st.s1, &ck])).unwrap()
        + &cosign(&w1.name, &w1k, &scp.text(), T);
    let lines: Vec<(u64, &[u8])> = (1..=st.lines.len() as u64)
        .filter(|&q| q != 3) // the key history (1, 2, 4) and note 1 (5)
        .map(|q| (q, st.lines[q as usize - 1].as_bytes()))
        .collect();
    let receipt_of = |note: &str| {
        String::from_utf8(receipt::build(note.as_bytes(), &st.hashes(), &lines, &[]).unwrap())
            .unwrap()
    };
    // The checkpoint key's line (the second) with one bit of its signature flipped.
    let bad_ck = {
        let mut ls: Vec<String> = snote.lines().map(str::to_owned).collect();
        let (head, b64) = ls[5].rsplit_once(' ').unwrap();
        let mut b = unbase64(b64).unwrap();
        b[40] ^= 1;
        ls[5] = format!("{head} {}", base64(&b));
        ls.join("\n") + "\n"
    };
    let pin = tenbri_core::sign::fingerprint(&st.a.verifying_key());
    let rcase = |name: &str, note: &str, pinned: &[&Witness], need: usize| {
        let r = receipt_of(note);
        let ws: Vec<Witness> = pinned.iter().map(|w| (*w).clone()).collect();
        let v = receipt::verify(r.as_bytes(), &pin).expect("a format v1 verifier accepts it");
        let result = match witness::verify(&v, &ws, need) {
            Ok(c) => {
                json!({"ok": c.iter().map(|c| json!({"name": c.name, "time": c.time})).collect::<Vec<_>>()})
            }
            Err(e) => json!({"error": e.code.as_str()}),
        };
        json!({"name": name, "pin": pin, "receipt": r, "witnesses": ws.iter().map(Witness::vkey).collect::<Vec<_>>(), "need": need, "result": result})
    };
    let receipts = vec![
        rcase("witnessed", &snote, &[&w1], 1),
        rcase("checkpoint-key-line-changed", &bad_ck, &[&w1], 1),
        rcase("witnessed-not-required", &snote, &[], 0),
    ];

    // An independent implementation's cosignature: Geomys's public witness (Go, torchwood) over
    // a checkpoint of markovianprotocol.com/log, read from its monitoring endpoint on 2026-10-22.
    let third_party = json!({
        "source": "https://witness.navigli.skylight.geomys.org/<sha256(origin)>/checkpoint, 2026-10-22",
        "witness": "witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G",
        "text": "markovianprotocol.com/log\n12010\n1jyFVBlENG+Ifo14JNOZDJQ+OeTNaxJx70uRB8VR5Gw=\n",
        "line": "\u{2014} witness.navigli.sunlight.geomys.org o+AP4gAAAABq2S2uIY6RokCS5VsIp5vWJZCzC8t/rkm75Z3yf9ATMgNQr0TzK0MXM6z/h8Q6JCpBzCgTpks4GIknoNJunhYwC+oRAw==\n",
    });
    let tp = Witness::parse(third_party["witness"].as_str().unwrap()).unwrap();
    let time = tp
        .verify_line(
            third_party["text"].as_str().unwrap(),
            third_party["line"].as_str().unwrap(),
        )
        .expect("Geomys's cosignature verifies");
    let mut third_party = third_party;
    third_party["time"] = json!(time);
    let request = |old: u64, proof: &[Hash]| {
        let body = String::from_utf8(request(old, proof, signed.as_bytes())).unwrap();
        json!({"old": old, "proof": proof.iter().map(|h| base64(h)).collect::<Vec<_>>(), "body": body})
    };
    let proof = tenbri_merkle::tree::consistency_proof(&leaves, 7).unwrap();
    let out = json!({
        "keys": [
            {"role": "checkpoint", "origin": origin, "pub": encode_key(&ck.verifying_key()), "vkey": log_vkey(origin, &ck.verifying_key())},
            {"role": "witness", "name": w1.name, "pub": encode_key(&w1.key), "vkey": w1.vkey()},
            {"role": "witness", "name": w2.name, "pub": encode_key(&w2.key), "vkey": w2.vkey()},
        ],
        "checkpoint_key_ext": {"checkpoint_key": encode_key(&ck.verifying_key())},
        "cosignatures": cases,
        "receipts": receipts,
        "third_party": [third_party],
        "requests": [request(0, &[]), request(7, &proof)],
    });
    let mut s = serde_json::to_string_pretty(&out).unwrap();
    s.push('\n');
    std::fs::write(Path::new(&dir).join("witness.json"), s).unwrap();
}
