//! Writes spec/vectors/merkle.json and checkpoints.json from fixed seeds and the `valid` stream of
//! chains.json: `cargo run -p tenbri-merkle --example merkle-vectors -- spec/vectors`.
//!
//! Released vectors are frozen; this exists so the drafts can be regenerated until then, and so
//! anyone can see how each case was made.

#[path = "../tests/common/mod.rs"]
mod common;

use std::fs;
use std::path::Path;

use common::{Stream, key};
use serde_json::{Value as J, json};
use tenbri_core::encoding::hex;
use tenbri_core::sign::{SigningKey, encode_key, fingerprint, stream_id};
use tenbri_merkle::checkpoint::{base64, key_id, unbase64};
use tenbri_merkle::tree::{
    consistency_proof, inclusion_proof, root, verify_consistency, verify_inclusion,
};
use tenbri_merkle::{Checkpoint, Hash, Note};

fn h(x: &Hash) -> String {
    format!("sha256:{}", hex(x))
}

fn hs(xs: &[Hash]) -> Vec<String> {
    xs.iter().map(h).collect()
}

fn flip(mut p: Vec<Hash>, i: usize) -> Vec<Hash> {
    p[i][0] ^= 1;
    p
}

fn merkle(leaves: &[Hash]) -> J {
    let n = leaves.len() as u64;
    let r = |size: u64| root(&leaves[..size as usize]);
    let trees: Vec<J> = (0..=n)
        .map(|s| json!({"size": s, "root": h(&r(s))}))
        .collect();

    let inc = |name: &str, index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash| {
        let valid = verify_inclusion(index, size, leaf, proof, root);
        json!({"name": name, "index": index, "size": size, "leaf": h(leaf), "proof": hs(proof), "root": h(root), "valid": valid})
    };
    let mut inclusion = vec![];
    for size in 1..=n {
        for i in 0..size {
            let p = inclusion_proof(&leaves[..size as usize], i).unwrap();
            inclusion.push(inc("valid", i, size, &leaves[i as usize], &p, &r(size)));
        }
    }
    for (i, size) in [(5, 14), (6, 7), (0, 8), (12, 13)] {
        let p = inclusion_proof(&leaves[..size as usize], i).unwrap();
        let (leaf, root) = (leaves[i as usize], r(size));
        let mut longer = p.clone();
        longer.push(leaves[0]);
        for case in [
            inc(
                "proof-element-flipped",
                i,
                size,
                &leaf,
                &flip(p.clone(), 0),
                &root,
            ),
            inc(
                "proof-last-element-flipped",
                i,
                size,
                &leaf,
                &flip(p.clone(), p.len() - 1),
                &root,
            ),
            inc(
                "proof-element-missing",
                i,
                size,
                &leaf,
                &p[..p.len() - 1],
                &root,
            ),
            inc("proof-element-extra", i, size, &leaf, &longer, &root),
            inc("wrong-leaf", i, size, &leaves[i as usize + 1], &p, &root),
            inc("wrong-index", i + 1, size, &leaf, &p, &root),
            inc("index-not-in-tree", size, size, &leaf, &p, &root),
            inc("wrong-root", i, size, &leaf, &p, &r(size - 1)),
            inc("empty-proof", i, size, &leaf, &[], &root),
        ] {
            assert_eq!(case["valid"], false, "{case}");
            inclusion.push(case);
        }
    }

    let con = |name: &str, m: u64, size: u64, old: &Hash, new: &Hash, proof: &[Hash]| {
        let valid = verify_consistency(m, size, old, new, proof);
        json!({"name": name, "old_size": m, "new_size": size, "old_root": h(old), "new_root": h(new), "proof": hs(proof), "valid": valid})
    };
    let mut consistency = vec![];
    for size in 0..=n {
        for m in 0..=size {
            let p = consistency_proof(&leaves[..size as usize], m).unwrap();
            consistency.push(con("valid", m, size, &r(m), &r(size), &p));
        }
    }
    for (m, size) in [(3, 7), (4, 14), (6, 8), (13, 14)] {
        let p = consistency_proof(&leaves[..size as usize], m).unwrap();
        let (old, new) = (r(m), r(size));
        let mut longer = p.clone();
        longer.push(leaves[0]);
        for case in [
            con(
                "proof-element-flipped",
                m,
                size,
                &old,
                &new,
                &flip(p.clone(), 0),
            ),
            con(
                "proof-last-element-flipped",
                m,
                size,
                &old,
                &new,
                &flip(p.clone(), p.len() - 1),
            ),
            con(
                "proof-element-missing",
                m,
                size,
                &old,
                &new,
                &p[..p.len() - 1],
            ),
            con("proof-element-extra", m, size, &old, &new, &longer),
            con("wrong-old-root", m, size, &r(m - 1), &new, &p),
            con("wrong-new-root", m, size, &old, &r(size - 1), &p),
            con("sizes-swapped", size, m, &new, &old, &p),
            con("empty-proof", m, size, &old, &new, &[]),
        ] {
            assert_eq!(case["valid"], false, "{case}");
            consistency.push(case);
        }
    }
    json!({"leaves": hs(leaves), "trees": trees, "inclusion": inclusion, "consistency": consistency})
}

/// A note with one signature line by `k` under `name`, over `text`.
fn signed(text: &str, name: &str, k: &SigningKey) -> String {
    use tenbri_core::sign::Signer;
    let mut sig = key_id(name, &k.verifying_key()).to_vec();
    sig.extend(k.sign(text.as_bytes()).to_bytes());
    format!("{text}\n\u{2014} {name} {}\n", base64(&sig))
}

fn note_case(name: &str, note: &str, signer: &SigningKey) -> J {
    let result = match Note::parse(note.as_bytes()) {
        Ok(n) => {
            json!({"origin": n.checkpoint.origin, "size": n.checkpoint.size, "root": h(&n.checkpoint.root), "signed_by": n.signed_by(&signer.verifying_key())})
        }
        Err(e) => json!({"error": e.code.as_str()}),
    };
    json!({"name": name, "note": note, "signer_pub": encode_key(&signer.verifying_key()), "result": result})
}

fn notes(base: &Stream) -> J {
    let (s1, attacker, witness) = (key("s1"), key("attacker"), key("approver"));
    let cp = Checkpoint::new(&base.id, &base.hashes()[..10]);
    let text = cp.text();
    let valid = String::from_utf8(cp.sign(&s1)).unwrap();
    let cosigned = valid.clone() + &signed(&text, "witness.example/w1", &witness)[text.len() + 1..];
    let (sig_line, sig) = valid.trim_end().rsplit_once(' ').unwrap();
    let mut bytes = unbase64(sig).unwrap();
    bytes[10] ^= 1;
    let bad_sig = format!("{sig_line} {}\n", base64(&bytes));
    let mut bytes = unbase64(sig).unwrap();
    bytes[0] ^= 1;
    let bad_id = format!("{sig_line} {}\n", base64(&bytes));
    let line = |i: usize| text.lines().nth(i).unwrap();
    let with_text = |t: String| signed(&t, &base.id, &s1);
    let root31 = base64(&cp.root[..31]);
    let mut noncanon = base64(&cp.root);
    noncanon.replace_range(42..43, "B"); // the last digit's two unused bits set
    assert!(unbase64(&noncanon).is_none());
    let other = stream_id(&key("b").verifying_key());
    let mut cases = vec![
        note_case("valid", &valid, &s1),
        note_case("cosigned-by-an-unknown-key", &cosigned, &s1),
        note_case("bad-signature", &bad_sig, &s1),
        note_case(
            "signed-by-another-key",
            &signed(&text, &base.id, &attacker),
            &s1,
        ),
        note_case("key-name-not-the-origin", &signed(&text, &other, &s1), &s1),
        note_case("wrong-key-id", &bad_id, &s1),
    ];
    for (name, note) in [
        ("no-blank-line", valid.replacen("\n\n", "\n", 1)),
        ("no-signature", text.clone() + "\n"),
        ("missing-final-line-feed", valid.trim_end().to_owned()),
        ("crlf", valid.replace('\n', "\r\n")),
        ("tab-in-text", with_text(text.replacen('\n', "\t\n", 1))),
        ("extension-line", with_text(text.clone() + "extension\n")),
        (
            "empty-line-in-text",
            with_text(text.replacen('\n', "\n\n", 1)),
        ),
        (
            "origin-not-a-stream-id",
            with_text(text.replacen(&base.id, "example.com/log", 1)),
        ),
        (
            "size-leading-zero",
            with_text(format!("{}\n010\n{}\n", line(0), line(2))),
        ),
        (
            "size-plus-sign",
            with_text(format!("{}\n+10\n{}\n", line(0), line(2))),
        ),
        (
            "size-above-2^53-1",
            with_text(format!("{}\n9007199254740992\n{}\n", line(0), line(2))),
        ),
        (
            "root-31-bytes",
            with_text(format!("{}\n10\n{root31}\n", line(0))),
        ),
        (
            "root-non-canonical-base64",
            with_text(format!("{}\n10\n{noncanon}\n", line(0))),
        ),
        (
            "root-hex",
            with_text(format!("{}\n10\n{}\n", line(0), hex(&cp.root))),
        ),
        (
            "signature-line-without-em-dash",
            valid.replace('\u{2014}', "-"),
        ),
        (
            "key-name-with-plus",
            valid.replacen(
                &format!("\u{2014} {}", base.id),
                &format!("\u{2014} {}+x", base.id),
                1,
            ),
        ),
        ("signature-not-base64", format!("{sig_line} !!!!\n")),
        (
            "signature-only-a-key-id",
            format!("{sig_line} {}\n", base64(&unbase64(sig).unwrap()[..4])),
        ),
    ] {
        let c = note_case(name, &note, &s1);
        assert_eq!(c["result"]["error"], "bad_checkpoint", "{name}");
        cases.push(c);
    }
    json!(cases)
}

fn stream_case(name: &str, s: &Stream, checkpoint: &[u8]) -> J {
    let chain = s
        .chain()
        .expect("every checkpoint case's stream verifies on its own");
    let note = Note::parse(checkpoint).unwrap();
    let result = match note.check(&chain, &s.hashes()) {
        Ok(now) => json!({"ok": true, "entries": now.size, "root": h(&now.root)}),
        Err(b) => json!({"ok": false, "seq": b.seq, "error": b.error.code.as_str()}),
    };
    json!({"name": name, "pin": fingerprint(&s.a.verifying_key()), "lines": s.lines, "checkpoint": String::from_utf8(checkpoint.to_vec()).unwrap(), "result": result})
}

fn streams(base: &Stream) -> J {
    let (s1, a) = (&base.s1, &base.a);
    let at = |s: &Stream, size: usize, k: &SigningKey| {
        Checkpoint::new(&s.id, &s.hashes()[..size]).sign(k)
    };
    let cp10 = at(base, 10, s1);
    let mut cosigned = cp10.clone();
    let text = Checkpoint::new(&base.id, &base.hashes()[..10]).text();
    cosigned.extend(
        &signed(&text, "witness.example/w1", &key("approver")).as_bytes()[text.len() + 1..],
    );

    let mut short = base.clone();
    short.lines.truncate(8);
    let mut short12 = base.clone();
    short12.lines.truncate(12);
    let rewritten = |seq: u64| {
        let mut s = base.clone();
        let mut entries: Vec<J> = (seq..=14).map(|i| base.json(i)).collect();
        entries[0]["ext"] = json!({"x-rewritten": {"by": "key holder"}});
        s.rewrite(seq, entries);
        s
    };
    let other = Checkpoint {
        origin: stream_id(&key("b").verifying_key()),
        ..Checkpoint::new(&base.id, &base.hashes()[..10])
    };

    // A stream that revokes sess:a1 from seq 4, after its last entry, and continues with sess:a2.
    let mut rev = Stream::new();
    rev.note(3);
    let s2 = key("s2");
    let ra = rev.a.clone();
    rev.push(rev.certify("sess:a2", &s2, "session"), &ra, "stream:a");
    rev.push(
        json!({"kind": "key", "key": {"op": "revoke", "id": "sess:a1", "from": 4}}),
        &ra,
        "stream:a",
    );
    rev.push(json!({"kind": "note"}), &s2, "sess:a2");

    // A witnessed stream (Experimental, section 6): its checkpoint key certified at seq 15, the
    // checkpoint signed by the session key and the checkpoint key, and cosigned. A format v1
    // verifier ignores both extra lines.
    let mut witnessed = base.clone();
    let ck = key("checkpoint");
    witnessed.certify_checkpoint_key(&ck);
    let wcp = Checkpoint::new(&witnessed.id, &witnessed.hashes());
    let mut wnote = wcp.sign_with(&[s1, &ck]);
    wnote.extend(
        common::cosignature(&wcp.text(), "witness.example/w1", &key("witness1")).as_bytes(),
    );

    let cases = vec![
        stream_case("checkpoint-at-head", base, &at(base, 14, s1)),
        stream_case("checkpoint-behind-head", base, &cp10),
        stream_case("checkpoint-cosigned", base, &cosigned),
        stream_case("truncation-behind-checkpoint", &short, &cp10),
        stream_case("truncation-after-checkpoint-not-detected", &short12, &cp10),
        stream_case("rewrite-behind-checkpoint", &rewritten(8), &cp10),
        stream_case(
            "rewrite-after-checkpoint-not-detected",
            &rewritten(12),
            &cp10,
        ),
        stream_case("checkpoint-of-another-stream", base, &other.sign(s1)),
        stream_case("checkpoint-bad-signature", base, &{
            let mut n = cp10.clone();
            let i = n.len() - 10;
            n[i] = if n[i] == b'A' { b'B' } else { b'A' };
            n
        }),
        stream_case(
            "checkpoint-by-unknown-key",
            base,
            &at(base, 10, &key("attacker")),
        ),
        stream_case("checkpoint-by-stream-key", base, &at(base, 10, a)),
        stream_case("checkpoint-before-its-signer", base, &at(base, 1, s1)),
        stream_case("checkpoint-by-key-revoked-later", &rev, &at(&rev, 3, s1)),
        stream_case("checkpoint-by-revoked-key", &rev, &at(&rev, 4, s1)),
        stream_case(
            "checkpoint-after-rotation-of-session",
            &rev,
            &at(&rev, 6, &s2),
        ),
        stream_case("witnessed-stream", &witnessed, &wnote),
    ];
    json!(cases)
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: vectors <spec/vectors>");
    let out = Path::new(&out);
    let chains: J = serde_json::from_slice(&fs::read(out.join("chains.json")).unwrap()).unwrap();
    let valid = chains["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid")
        .unwrap();
    let mut base = Stream::new();
    base.lines = valid["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(base.lines.len(), 14);
    let write = |name: &str, j: J| {
        fs::write(
            out.join(name),
            serde_json::to_string_pretty(&j).unwrap() + "\n",
        )
        .unwrap()
    };
    write("merkle.json", merkle(&base.hashes()));
    write(
        "checkpoints.json",
        json!({"notes": notes(&base), "streams": streams(&base)}),
    );
}
