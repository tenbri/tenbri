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
use tenbri_merkle::witness::{Witness, cosign, cosignatures, log_vkey, request};
use tenbri_merkle::{Checkpoint, Hash, Note};

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

    let case = |name: &str, extra: &str, pinned: &[&Witness], need: usize| {
        let note = format!("{signed}{extra}");
        let ws: Vec<Witness> = pinned.iter().map(|w| (*w).clone()).collect();
        let result = match cosignatures(&Note::parse(note.as_bytes()).unwrap(), &ws, need) {
            Ok(c) => {
                json!({"ok": c.iter().map(|c| json!({"name": c.name, "time": c.time})).collect::<Vec<_>>()})
            }
            Err(e) => json!({"error": e.code.as_str()}),
        };
        json!({"name": name, "note": note, "witnesses": ws.iter().map(Witness::vkey).collect::<Vec<_>>(), "need": need, "result": result})
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
    ];
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
        "requests": [request(0, &[]), request(7, &proof)],
    });
    let mut s = serde_json::to_string_pretty(&out).unwrap();
    s.push('\n');
    std::fs::write(Path::new(&dir).join("witness.json"), s).unwrap();
}
