//! Streams from fixed seeds, shared by the tests and the vectors example.
#![allow(dead_code)]

use serde_json::{Value as J, json};
use tenbri_core::sign::{SigningKey, encode_key, entry_hash, sha256, sign_entry, stream_id};
use tenbri_core::{Broken, Chain, Entry, encoding};
use tenbri_merkle::Hash;

/// The seeds of spec/vectors/keys.json: SHA-256 of "tenbri vector key <name>".
pub fn key(name: &str) -> SigningKey {
    let h = sha256(format!("tenbri vector key {name}").as_bytes());
    SigningKey::from_bytes(&encoding::prefixed::<32>(&h, "sha256:").unwrap())
}

pub fn hash(line: &str) -> Hash {
    encoding::prefixed::<32>(&entry_hash(line.as_bytes()), "sha256:").unwrap()
}

const T0: i64 = 1_792_000_000_000;

/// A stream: genesis by `stream:a`, session `sess:a1` (key `s1`) certified at seq 2.
#[derive(Clone)]
pub struct Stream {
    pub id: String,
    pub lines: Vec<String>,
    pub a: SigningKey,
    pub s1: SigningKey,
}

impl Stream {
    pub fn new() -> Self {
        let (a, s1) = (key("a"), key("s1"));
        let mut s = Stream {
            id: stream_id(&a.verifying_key()),
            lines: vec![],
            a: a.clone(),
            s1: s1.clone(),
        };
        s.push(s.certify("stream:a", &a, "stream"), &a, "stream:a");
        s.push(s.certify("sess:a1", &s1, "session"), &a, "stream:a");
        s
    }

    pub fn certify(&self, id: &str, k: &SigningKey, role: &str) -> J {
        let mut ev =
            json!({"op": "certify", "id": id, "pub": encode_key(&k.verifying_key()), "role": role});
        if role == "session" {
            ev["not_after"] = json!(encoding::format_ts(T0 + 86_400_000));
        }
        json!({"kind": "key", "key": ev})
    }

    /// Appends `template` (members the writer fills are added) signed by `k` as `signer`.
    pub fn push(&mut self, template: J, k: &SigningKey, signer: &str) {
        let seq = self.lines.len() as u64 + 1;
        let mut j = template;
        let m = j.as_object_mut().unwrap();
        for (name, v) in [
            ("v", json!(1)),
            (
                "id",
                json!(encoding::ulid(((T0 as u128) << 80) | seq as u128)),
            ),
            ("stream", json!(self.id)),
            ("ts", json!(encoding::format_ts(T0 + seq as i64 * 1000))),
            ("sig", json!("")),
        ] {
            m.entry(name).or_insert(v);
        }
        m.insert("seq".into(), json!(seq));
        m.insert("signer".into(), json!(signer));
        m.remove("prev");
        if seq > 1 {
            m.insert(
                "prev".into(),
                json!(entry_hash(self.lines.last().unwrap().as_bytes())),
            );
        }
        let mut e: Entry = serde_json::from_value(j).unwrap();
        let line = String::from_utf8(sign_entry(&mut e, k).unwrap()).unwrap();
        self.lines.push(line);
    }

    /// A note signed by `sess:a1`, told apart by `n`.
    pub fn note(&mut self, n: u64) {
        let s1 = self.s1.clone();
        self.push(
            json!({"kind": "note", "ext": {"x-test": {"n": n}}}),
            &s1,
            "sess:a1",
        );
    }

    /// The key holder's rewrite: `entries` (stored lines' JSON) replace everything from `seq`,
    /// renumbered, rechained and re-signed by `sess:a1`, so the stream verifies on its own.
    pub fn rewrite(&mut self, seq: u64, entries: Vec<J>) {
        self.lines.truncate(seq as usize - 1);
        let s1 = self.s1.clone();
        for e in entries {
            self.push(e, &s1, "sess:a1");
        }
    }

    pub fn json(&self, seq: u64) -> J {
        serde_json::from_str(&self.lines[seq as usize - 1]).unwrap()
    }

    pub fn hashes(&self) -> Vec<Hash> {
        self.lines.iter().map(|l| hash(l)).collect()
    }

    /// The stream verified on its own, pinned to `stream:a`.
    pub fn chain(&self) -> Result<Chain, Broken> {
        let pin = tenbri_core::sign::fingerprint(&self.a.verifying_key());
        let mut c = Chain::new(Some(&pin));
        for l in &self.lines {
            c.push(l.as_bytes())?;
        }
        match c.invalidated() {
            Some(b) => Err(b.clone()),
            None => Ok(c),
        }
    }
}
