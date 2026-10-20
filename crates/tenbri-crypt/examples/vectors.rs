//! Writes spec/vectors/privacy.json from fixed seeds:
//! `cargo run -p tenbri-crypt --example vectors -- spec/vectors`.
//!
//! Released vectors are frozen; this exists so the drafts can be regenerated until then, and so
//! anyone can see how each case was made.

use std::path::Path;

use serde_json::{Value as J, json};
use tenbri_core::encoding::{self, hex};
use tenbri_core::sign::{SigningKey, encode_key, entry_hash, fingerprint, sha256, sign_entry};
use tenbri_core::{
    Action, Entry, Input, KeyEvent, Kind, Phase, Principal, PrincipalKind, Role, Source,
};
use tenbri_crypt::{
    DataKey, NONCE_LEN, address, blob_key, blob_path, digest, digest_key, erasure_note, seal,
};

const T0: &str = "2026-10-14T14:02:11.318Z";

fn bytes32(label: &str) -> [u8; 32] {
    encoding::prefixed::<32>(&sha256(label.as_bytes()), "sha256:").unwrap()
}

fn data_key(name: &str) -> DataKey {
    bytes32(&format!("tenbri vector data key {name}"))
}

fn nonce(n: u32) -> [u8; NONCE_LEN] {
    bytes32(&format!("tenbri vector nonce {n}"))[..NONCE_LEN]
        .try_into()
        .unwrap()
}

fn derivation() -> J {
    let cases: Vec<J> = ["cust_42", "cust_7", "tenant"]
        .iter()
        .map(|n| {
            let k = data_key(n);
            json!({"data_key": hex(&k), "blob_key": hex(&*blob_key(&k)), "digest_key": hex(&*digest_key(&k))})
        })
        .collect();
    json!(cases)
}

fn digests() -> J {
    let k = data_key("cust_42");
    let cases: Vec<J> = [
        "ticket 4821: please refund my order",
        "",
        "jane@example.com",
    ]
    .iter()
    .map(|c| json!({"data_key": hex(&k), "content": c, "digest": digest(&k, c.as_bytes())}))
    .collect();
    json!(cases)
}

fn blobs(stream: &str) -> J {
    let k = data_key("cust_42");
    let mut valid = vec![];
    for (n, text) in [
        (1, "Refund of 40 EUR approved under policy:refund@14"),
        (2, ""),
    ] {
        let blob = seal(&k, stream, &nonce(n), text.as_bytes());
        valid.push(json!({
            "data_key": hex(&k), "stream": stream, "nonce": hex(&nonce(n)), "plaintext": text,
            "blob": hex(&blob), "address": address(&blob), "path": blob_path(&address(&blob)),
        }));
    }
    let blob = seal(
        &k,
        stream,
        &nonce(1),
        b"Refund of 40 EUR approved under policy:refund@14",
    );
    let mut flipped = blob.clone();
    flipped[NONCE_LEN + 3] ^= 1;
    let invalid = json!([
        {"why": "another subject's key", "data_key": hex(&data_key("cust_7")), "stream": stream,
         "blob": hex(&blob), "address": address(&blob), "error": "not_opened"},
        {"why": "sealed for another stream", "data_key": hex(&k),
         "stream": "tnb1:00000000000000000000000000000000",
         "blob": hex(&blob), "address": address(&blob), "error": "not_opened"},
        {"why": "a ciphertext byte changed, address recomputed", "data_key": hex(&k), "stream": stream,
         "blob": hex(&flipped), "address": address(&flipped), "error": "not_opened"},
        {"why": "a ciphertext byte changed, address kept", "data_key": hex(&k), "stream": stream,
         "blob": hex(&flipped), "address": address(&blob), "error": "address_mismatch"},
        {"why": "shorter than a nonce", "data_key": hex(&k), "stream": stream,
         "blob": hex(&blob[..10]), "address": address(&blob[..10]), "error": "not_opened"},
    ]);
    json!({"valid": valid, "invalid": invalid})
}

/// A stream with bodies and digests for two subjects, then subject `cust_42` erased: its key is
/// gone from `keys`, and the stream still verifies.
fn erased(stream_key: &SigningKey, session: &SigningKey) -> J {
    let stream = tenbri_core::sign::stream_id(&stream_key.verifying_key());
    let t0 = encoding::parse_ts(T0).unwrap();
    let mut lines: Vec<String> = vec![];
    let mut push = |mut e: Entry, k: &SigningKey, signer: &str| {
        let seq = lines.len() as u64 + 1;
        let ms = t0 + 1000 * (seq as i64 - 1);
        e.id = encoding::ulid(((ms as u128) << 80) | seq as u128);
        e.stream = stream.clone();
        e.seq = seq;
        e.ts = encoding::format_ts(ms);
        e.prev = lines.last().map(|l| entry_hash(l.as_bytes()));
        e.signer = signer.into();
        lines.push(String::from_utf8(sign_entry(&mut e, k).unwrap()).unwrap());
    };
    let certify = |k: &SigningKey, id: &str, role, not_after: Option<i64>| Entry {
        key: Some(KeyEvent::Certify {
            id: id.into(),
            public: encode_key(&k.verifying_key()),
            role,
            not_after: not_after.map(encoding::format_ts),
        }),
        ..Entry::new(Kind::Key)
    };
    push(
        certify(stream_key, "stream:p", Role::Stream, None),
        stream_key,
        "stream:p",
    );
    push(
        certify(session, "sess:p1", Role::Session, Some(t0 + 86_400_000)),
        stream_key,
        "stream:p",
    );
    let mut blobs = serde_json::Map::new();
    let mut bodies = serde_json::Map::new();
    let mut inputs = vec![];
    for (n, subject, text, content) in [
        (
            11,
            "cust_42",
            "Refund of 40 EUR approved",
            "ticket 4821 from jane@example.com",
        ),
        (
            12,
            "cust_7",
            "Address change confirmed",
            "ticket 4822 from sam@example.com",
        ),
    ] {
        let k = data_key(subject);
        let blob = seal(&k, &stream, &nonce(n), text.as_bytes());
        let addr = address(&blob);
        blobs.insert(addr.clone(), json!(hex(&blob)));
        bodies.insert(
            addr.clone(),
            if subject == "cust_42" {
                J::Null
            } else {
                json!(text)
            },
        );
        inputs.push(
            json!({"subject": subject, "content": content, "digest": digest(&k, content.as_bytes()),
                           "confirmable": subject != "cust_42"}),
        );
        push(
            Entry {
                phase: Some(Phase::Intent),
                source: Some(Source::Sdk),
                principal: Some(Principal {
                    kind: PrincipalKind::Agent,
                    id: "support-assistant".into(),
                }),
                action: Some(Action {
                    r#type: "reply_ticket".into(),
                    target: Some(format!("zendesk:ticket/48{n}")),
                }),
                subject: Some(subject.into()),
                inputs: Some(vec![Input {
                    r#ref: format!("ticket:48{n}"),
                    version: "1".into(),
                    digest: digest(&k, content.as_bytes()),
                }]),
                body: Some(addr),
                ..Entry::new(Kind::Decision)
            },
            session,
            "sess:p1",
        );
    }
    let dpo = Principal {
        kind: PrincipalKind::Person,
        id: "dpo@example.com".into(),
    };
    push(
        erasure_note(Some("cust_42"), "dsr:2026-1042", Some(dpo)),
        session,
        "sess:p1",
    );
    json!({
        "pin": fingerprint(&stream_key.verifying_key()),
        "lines": lines,
        "blobs": blobs,
        "keys": {"cust_7": hex(&data_key("cust_7"))},
        "erased": ["cust_42"],
        "bodies": bodies,
        "inputs": inputs,
        "result": {"ok": 5},
    })
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: vectors <spec/vectors>");
    let key = |n: &str| SigningKey::from_bytes(&bytes32(&format!("tenbri vector key {n}")));
    let (p, p1) = (key("p"), key("p1"));
    let stream = tenbri_core::sign::stream_id(&p.verifying_key());
    let j = json!({
        "derivation": derivation(),
        "digests": digests(),
        "blobs": blobs(&stream),
        "erased": erased(&p, &p1),
    });
    std::fs::write(
        Path::new(&out).join("privacy.json"),
        serde_json::to_string_pretty(&j).unwrap() + "\n",
    )
    .unwrap();
}
