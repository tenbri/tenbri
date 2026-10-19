//! Writes spec/vectors/ from fixed seeds: `cargo run -p tenbri-core --example vectors -- spec/vectors`.
//!
//! Released vectors are frozen; this exists so the drafts can be regenerated until then, and so
//! anyone can see how each case was made. The canonical-JSON cases are written by hand below, not
//! computed, so they also check the implementation.

use std::fs;
use std::path::Path;

use serde_json::{Value as J, json};
use tenbri_core::sign::{
    SigningKey, attest, encode_key, entry_hash, fingerprint, sha256, sign_entry, sign_head,
    stream_id,
};
use tenbri_core::{Entry, Head, canon, encoding};

const T0: &str = "2026-10-14T14:02:11.318Z";
const DAY: i64 = 86_400_000;

fn key(name: &str) -> SigningKey {
    let h = sha256(format!("tenbri vector key {name}").as_bytes());
    SigningKey::from_bytes(&encoding::prefixed::<32>(&h, "sha256:").unwrap())
}

fn t0() -> i64 {
    encoding::parse_ts(T0).unwrap()
}

fn digest(s: &str) -> String {
    format!("hmac-sha256:{}", &sha256(s.as_bytes())["sha256:".len()..])
}

/// An entry from a JSON template; the builder fills what the template leaves out.
fn draft(mut j: J) -> Entry {
    let m = j.as_object_mut().unwrap();
    for (k, v) in [
        ("v", json!(1)),
        ("id", json!("")),
        ("stream", json!("")),
        ("seq", json!(0)),
        ("ts", json!("")),
        ("signer", json!("")),
        ("sig", json!("")),
    ] {
        m.entry(k).or_insert(v);
    }
    serde_json::from_value(j).unwrap()
}

fn certify(id: &str, k: &SigningKey, role: &str, not_after: Option<i64>) -> Entry {
    let mut ev =
        json!({"op": "certify", "id": id, "pub": encode_key(&k.verifying_key()), "role": role});
    if let Some(t) = not_after {
        ev["not_after"] = json!(encoding::format_ts(t));
    }
    draft(json!({"kind": "key", "key": ev}))
}

fn intent(action: &str, target: &str) -> Entry {
    draft(json!({
        "kind": "decision", "phase": "intent", "source": "sdk",
        "principal": {"kind": "agent", "id": "support-assistant"},
        "action": {"type": action, "target": target},
    }))
}

fn outcome(intent: &str, status: &str) -> Entry {
    draft(json!({
        "kind": "decision", "phase": "outcome", "source": "sdk", "intent": intent, "status": status,
        "principal": {"kind": "agent", "id": "support-assistant"},
        "action": {"type": "reply_ticket", "target": "zendesk:ticket/4821"},
    }))
}

fn note() -> Entry {
    draft(json!({"kind": "note"}))
}

#[derive(Clone)]
struct B {
    stream: String,
    ms: i64,
    entries: Vec<Entry>,
    lines: Vec<String>,
}

impl B {
    fn new(genesis: &SigningKey) -> Self {
        B {
            stream: stream_id(&genesis.verifying_key()),
            ms: t0(),
            entries: vec![],
            lines: vec![],
        }
    }

    fn seq(&self) -> u64 {
        self.entries.len() as u64
    }

    fn hash(&self, seq: u64) -> String {
        entry_hash(self.lines[seq as usize - 1].as_bytes())
    }

    fn id(&self, seq: u64) -> String {
        self.entries[seq as usize - 1].id.clone()
    }

    /// Fills, signs and appends `e`; returns its seq.
    fn push(&mut self, mut e: Entry, k: &SigningKey, signer: &str) -> u64 {
        let seq = self.seq() + 1;
        if e.id.is_empty() {
            e.id = encoding::ulid(((self.ms as u128) << 80) | seq as u128);
        }
        if e.stream.is_empty() {
            e.stream = self.stream.clone();
        }
        if e.seq == 0 {
            e.seq = seq;
        }
        if e.ts.is_empty() {
            e.ts = encoding::format_ts(self.ms);
        }
        e.prev = (seq > 1).then(|| self.hash(seq - 1));
        e.signer = signer.to_owned();
        let line = String::from_utf8(sign_entry(&mut e, k).unwrap()).unwrap();
        self.ms += 1000;
        self.entries.push(e);
        self.lines.push(line);
        seq
    }

    /// Replaces entry `seq`'s line with `f(entry)` signed by `k`, leaving later entries alone.
    fn resign(&mut self, seq: u64, k: &SigningKey, f: impl FnOnce(&mut Entry)) {
        let mut e = self.entries[seq as usize - 1].clone();
        f(&mut e);
        self.lines[seq as usize - 1] = String::from_utf8(sign_entry(&mut e, k).unwrap()).unwrap();
    }

    /// Edits entry `seq`'s line as JSON without signing it again.
    fn edit(&mut self, seq: u64, f: impl FnOnce(&mut J)) {
        let mut j: J = serde_json::from_str(&self.lines[seq as usize - 1]).unwrap();
        f(&mut j);
        self.lines[seq as usize - 1] =
            String::from_utf8(canon::to_vec(&canon::from_serialize(&j).unwrap())).unwrap();
    }
}

struct K {
    a: SigningKey,
    s1: SigningKey,
    s2: SigningKey,
    b: SigningKey,
    attacker: SigningKey,
    approver: SigningKey,
}

/// Genesis by stream key `stream:a` and a 24-hour session `sess:a1`.
fn genesis(k: &K) -> B {
    let mut b = B::new(&k.a);
    b.push(certify("stream:a", &k.a, "stream", None), &k.a, "stream:a");
    b.push(
        certify("sess:a1", &k.s1, "session", Some(t0() + DAY)),
        &k.a,
        "stream:a",
    );
    b
}

/// The 14-entry stream most cases start from: every kind and most optional members.
fn basic(k: &K) -> B {
    let mut b = genesis(k);
    let mut e = intent("reply_ticket", "zendesk:ticket/4821");
    e.subject = Some("subj_7f3c91d2".into());
    e.durability = Some(tenbri_core::Durability::Local);
    e.hlc = Some(tenbri_core::Hlc {
        wall: t0() as u64 + 2000,
        count: 0,
    });
    e.trace = Some(tenbri_core::Trace {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
    });
    e.inputs = Some(vec![
        tenbri_core::Input {
            r#ref: "policy:refund".into(),
            version: "14".into(),
            digest: digest("policy:refund@14"),
        },
        tenbri_core::Input {
            r#ref: "contract:acme-sante".into(),
            version: "3".into(),
            digest: digest("contract:acme-sante@3"),
        },
    ]);
    e.rule = Some(tenbri_core::Rule {
        r#ref: "grants:support-assistant".into(),
        version: "7".into(),
        result: "allow".into(),
    });
    e.body = Some(format!(
        "blob:ct-sha256:{}",
        &sha256(b"ciphertext")["sha256:".len()..]
    ));
    let s = b.push(e, &k.s1, "sess:a1"); // 3
    let mut o = outcome(&b.id(s), "ok");
    o.hlc = Some(tenbri_core::Hlc {
        wall: t0() as u64 + 3000,
        count: 1,
    });
    b.push(o, &k.s1, "sess:a1"); // 4
    let ap = b.push(
        draft(json!({"kind": "approval", "principal": {"kind": "person", "id": "alice"}, "action": {"type": "issue_refund", "target": "stripe:refund/re_42"}})),
        &k.s1,
        "sess:a1",
    ); // 5
    let mut e = intent("issue_refund", "stripe:refund/re_42");
    e.approval = Some(tenbri_core::Approval {
        by: tenbri_core::Principal {
            kind: tenbri_core::PrincipalKind::Person,
            id: "alice".into(),
        },
        entry: b.hash(ap),
    });
    e.stream = b.stream.clone();
    e.id = encoding::ulid(((b.ms as u128) << 80) | 6);
    e.ts = encoding::format_ts(b.ms);
    e.attestations = Some(vec![attest(&e, &k.approver).unwrap()]);
    let s = b.push(e, &k.s1, "sess:a1"); // 6
    b.push(outcome(&b.id(s), "refused"), &k.s1, "sess:a1"); // 7
    let s = b.push(
        intent("close_ticket", "zendesk:ticket/4821"),
        &k.s1,
        "sess:a1",
    ); // 8
    b.push(
        draft(json!({"kind": "reconcile", "intent": b.id(s), "status": "unknown"})),
        &k.s1,
        "sess:a1",
    ); // 9
    b.push(outcome(&b.id(s), "ok"), &k.s1, "sess:a1"); // 10
    let other = stream_id(&k.b.verifying_key());
    b.push(
        draft(json!({
            "kind": "note", "ext": {"x-demo": {"n": 1, "s": "é \u{2028} /"}}, "degraded": true,
            "links": [{"stream": other, "seq": 1, "hash": sha256(b"other"), "rel": "cause"}],
        })),
        &k.s1,
        "sess:a1",
    ); // 11
    b.push(
        draft(json!({"kind": "decision", "phase": "outcome", "source": "ingest", "status": "ok",
            "principal": {"kind": "service", "id": "otel-collector"}, "action": {"type": "search_kb"}})),
        &k.s1,
        "sess:a1",
    ); // 12
    let mut e = intent("send_email", "mailto:customer");
    e.source = Some(tenbri_core::Source::Proxy);
    let s = b.push(e, &k.s1, "sess:a1"); // 13
    let mut o = outcome(&b.id(s), "error");
    o.source = Some(tenbri_core::Source::Proxy);
    b.push(o, &k.s1, "sess:a1"); // 14
    b
}

fn chain_case(name: &str, pin: Option<&SigningKey>, b: &B, result: J) -> J {
    json!({"name": name, "pin": pin.map(|k| fingerprint(&k.verifying_key())), "lines": b.lines, "result": result})
}

fn ok(n: u64) -> J {
    json!({"ok": true, "entries": n})
}

fn broken(seq: u64, error: &str) -> J {
    json!({"ok": false, "seq": seq, "error": error})
}

fn chains(k: &K) -> Vec<J> {
    let base = basic(k);
    let a = Some(&k.a);
    let mut out = vec![
        chain_case("valid", a, &base, ok(14)),
        chain_case(
            "unpinned",
            None,
            &base,
            json!({"ok": true, "entries": 14, "pinned": false}),
        ),
        chain_case(
            "wrong-pin",
            Some(&k.attacker),
            &base,
            broken(1, "untrusted_root"),
        ),
    ];
    let mut add = |name: &str, b: B, r: J| out.push(chain_case(name, a, &b, r));

    let mut b = base.clone();
    b.edit(3, |j| j["action"]["target"] = json!("zendesk:ticket/9999"));
    add("edit-field", b, broken(3, "bad_signature"));
    let mut b = base.clone();
    b.lines[2] = b.lines[2].replacen("{", "{ ", 1);
    add("edit-whitespace", b, broken(3, "not_canonical"));
    let mut b = base.clone();
    b.lines[2] = b.lines[2]
        .replacen("\"kind\":\"decision\",", "", 1)
        .replacen("{", "{\"kind\":\"decision\",", 1);
    add("edit-key-order", b, broken(3, "not_canonical"));
    let mut b = base.clone();
    b.resign(3, &k.attacker, |e| {
        e.action.as_mut().unwrap().target = Some("zendesk:ticket/9999".into())
    });
    add("edit-signed-by-attacker", b, broken(3, "bad_signature"));
    let mut b = base.clone();
    b.resign(3, &k.s1, |e| {
        e.action.as_mut().unwrap().target = Some("zendesk:ticket/9999".into())
    });
    add("edit-signed-by-session-key", b, broken(4, "bad_prev"));
    let mut b = base.clone();
    b.lines.swap(2, 3);
    add("reorder", b, broken(3, "bad_seq"));
    let mut b = base.clone();
    b.lines.remove(4);
    add("delete", b, broken(5, "bad_seq"));
    let mut b = base.clone();
    let dup = b.lines[2].clone();
    b.lines.insert(3, dup);
    add("insert-duplicate", b, broken(4, "bad_seq"));

    let mut b = genesis(k);
    b.push(note(), &k.s1, "sess:a1");
    let mut e = note();
    e.id = b.id(3);
    b.push(e, &k.s1, "sess:a1");
    add("duplicate-id", b, broken(4, "duplicate_id"));
    let mut b = genesis(k);
    let mut e = note();
    e.stream = stream_id(&k.attacker.verifying_key());
    b.push(e, &k.s1, "sess:a1");
    add("wrong-stream", b, broken(3, "wrong_stream"));
    let mut b = genesis(k);
    b.push(note(), &k.attacker, "sess:x");
    add("unknown-signer", b, broken(3, "unknown_signer"));
    let mut b = genesis(k);
    b.push(note(), &k.a, "stream:a");
    add("stream-key-signs-note", b, broken(3, "signer_not_allowed"));
    let mut b = genesis(k);
    b.push(
        certify("sess:a2", &k.s2, "session", Some(t0() + DAY)),
        &k.s1,
        "sess:a1",
    );
    add("session-key-certifies", b, broken(3, "signer_not_allowed"));
    let mut b = genesis(k);
    b.ms = t0() + DAY + 1;
    b.push(note(), &k.s1, "sess:a1");
    add("expired-session", b, broken(3, "key_expired"));

    let mut b = genesis(k);
    b.push(outcome(&encoding::ulid(42), "ok"), &k.s1, "sess:a1");
    add("outcome-without-intent", b, broken(3, "bad_intent"));
    let mut b = genesis(k);
    let s = b.push(intent("reply_ticket", "zendesk:ticket/1"), &k.s1, "sess:a1");
    b.push(outcome(&b.id(s), "ok"), &k.s1, "sess:a1");
    b.push(outcome(&b.id(s), "ok"), &k.s1, "sess:a1");
    add("duplicate-outcome", b.clone(), broken(5, "bad_intent"));
    b.entries.pop();
    b.lines.pop();
    b.push(
        draft(json!({"kind": "reconcile", "intent": b.id(s), "status": "unknown"})),
        &k.s1,
        "sess:a1",
    );
    add("reconcile-after-outcome", b, broken(5, "bad_intent"));
    let mut b = genesis(k);
    let s = b.push(intent("reply_ticket", "zendesk:ticket/1"), &k.s1, "sess:a1");
    let mut e = intent("issue_refund", "stripe:refund/re_1");
    e.approval = Some(tenbri_core::Approval {
        by: tenbri_core::Principal {
            kind: tenbri_core::PrincipalKind::Person,
            id: "alice".into(),
        },
        entry: b.hash(s),
    });
    b.push(e, &k.s1, "sess:a1");
    add(
        "approval-not-an-approval-entry",
        b,
        broken(4, "bad_approval"),
    );
    let mut b = genesis(k);
    let mut e = note();
    e.attestations = Some(vec![attest(&note(), &k.approver).unwrap()]);
    b.push(e, &k.s1, "sess:a1");
    add("bad-attestation", b, broken(3, "bad_signature"));
    let mut b = genesis(k);
    let mut e = note();
    e.hlc = Some(tenbri_core::Hlc {
        wall: 2000,
        count: 0,
    });
    b.push(e, &k.s1, "sess:a1");
    let mut e = note();
    e.hlc = Some(tenbri_core::Hlc {
        wall: 1999,
        count: 9,
    });
    b.push(e, &k.s1, "sess:a1");
    add("hlc-backwards", b, broken(4, "bad_hlc"));

    let mut b = B::new(&k.a);
    b.push(note(), &k.a, "stream:a");
    add("genesis-not-a-key-event", b, broken(1, "bad_genesis"));
    let mut b = B::new(&k.attacker);
    b.push(certify("stream:a", &k.a, "stream", None), &k.a, "stream:a");
    add("genesis-stream-id-mismatch", b, broken(1, "bad_genesis"));

    // Rotation: stream:a hands over to stream:b; sessions certified by either keep signing.
    let mut rot = genesis(k);
    let s = rot.push(intent("reply_ticket", "zendesk:ticket/1"), &k.s1, "sess:a1");
    rot.push(outcome(&rot.id(s), "ok"), &k.s1, "sess:a1");
    rot.push(draft(json!({"kind": "key", "key": {"op": "rotate", "id": "stream:b", "pub": encode_key(&k.b.verifying_key())}})), &k.a, "stream:a");
    rot.push(
        certify("sess:b1", &k.s2, "session", Some(t0() + DAY)),
        &k.b,
        "stream:b",
    );
    rot.push(note(), &k.s2, "sess:b1");
    rot.push(note(), &k.s1, "sess:a1");
    add("rotation", rot.clone(), ok(8));
    let mut b = rot.clone();
    b.push(
        certify("sess:a2", &k.attacker, "session", Some(t0() + DAY)),
        &k.a,
        "stream:a",
    );
    add(
        "retired-stream-key-certifies",
        b,
        broken(9, "signer_not_allowed"),
    );
    let mut b = genesis(k);
    b.push(draft(json!({"kind": "key", "key": {"op": "rotate", "id": "stream:b", "pub": encode_key(&k.b.verifying_key())}})), &k.s1, "sess:a1");
    add("session-key-rotates", b, broken(3, "signer_not_allowed"));
    let mut b = genesis(k);
    b.push(draft(json!({"kind": "key", "key": {"op": "rotate", "id": "sess:a1", "pub": encode_key(&k.b.verifying_key())}})), &k.a, "stream:a");
    add("rotate-reuses-key-id", b, broken(3, "bad_key_event"));
    let mut b = genesis(k);
    b.push(
        certify("sess:a2", &k.s1, "session", Some(t0() + DAY)),
        &k.a,
        "stream:a",
    );
    add("certify-reuses-public-key", b, broken(3, "bad_key_event"));
    let mut b = genesis(k);
    b.push(certify("stream:b", &k.b, "stream", None), &k.a, "stream:a");
    add("second-stream-certification", b, broken(3, "bad_key_event"));

    // Revocation: from the next entry on, and reaching back to entries already written.
    let revoke = |id: &str, from: u64| {
        draft(json!({"kind": "key", "key": {"op": "revoke", "id": id, "from": from}}))
    };
    let mut b = genesis(k);
    b.push(note(), &k.s1, "sess:a1");
    b.push(revoke("sess:a1", 5), &k.a, "stream:a");
    b.push(note(), &k.s1, "sess:a1");
    add("revoked-key-signs", b, broken(5, "key_revoked"));
    let mut b = genesis(k);
    for _ in 0..4 {
        b.push(note(), &k.s1, "sess:a1"); // 3..6
    }
    b.push(revoke("sess:a1", 5), &k.a, "stream:a"); // 7
    b.push(
        certify("sess:a2", &k.s2, "session", Some(t0() + DAY)),
        &k.a,
        "stream:a",
    ); // 8
    b.push(note(), &k.s2, "sess:a2"); // 9
    add("revocation-reaches-back", b, broken(5, "key_revoked"));
    let mut b = genesis(k);
    b.push(revoke("stream:a", 1), &k.a, "stream:a");
    add("revoke-current-stream-key", b, broken(3, "bad_key_event"));
    let mut b = genesis(k);
    b.push(revoke("sess:zz", 1), &k.a, "stream:a");
    add("revoke-unknown-key", b, broken(3, "bad_key_event"));

    out.push(json!({"name": "truncation-behind-checkpoint", "skip": "checkpoints land in 0.1.0-alpha.2: a verifier holding a checkpoint at seq 10 must reject this 8-entry stream", "pin": fingerprint(&k.a.verifying_key()), "lines": base.lines[..8]}));
    out.push(json!({"name": "rewrite-behind-checkpoint", "skip": "checkpoints land in 0.1.0-alpha.2: a stream re-signed from seq 3 by its key holder verifies on its own and fails against a checkpoint held outside the operator", "pin": fingerprint(&k.a.verifying_key())}));
    out
}

fn entries(k: &K) -> J {
    let base = basic(k);
    let names = [
        "genesis",
        "certify-session",
        "intent",
        "outcome-ok",
        "approval",
        "intent-approved-attested",
        "outcome-refused",
        "intent-reconciled",
        "reconcile",
        "outcome-after-reconcile",
        "note-ext-links",
        "outcome-ingest",
        "intent-proxy",
        "outcome-proxy-error",
    ];
    let mut valid: Vec<J> = base
        .lines
        .iter()
        .zip(&base.entries)
        .zip(names)
        .map(|((line, e), name)| {
            let signer = if e.signer == "stream:a" { &k.a } else { &k.s1 };
            let mut v = canon::parse(line.as_bytes()).unwrap();
            v.remove("sig");
            let mut msg = b"tenbri/entry/v1\0".to_vec();
            msg.extend(canon::to_vec(&v));
            json!({"name": name, "line": line, "signer_pub": encode_key(&signer.verifying_key()), "signing_input": String::from_utf8(msg).unwrap(), "hash": entry_hash(line.as_bytes())})
        })
        .collect();
    let mut b = genesis(k);
    b.push(
        draft(
            json!({"kind": "note", "approval": null, "links": [], "attestations": [], "ext": {}}),
        ),
        &k.s1,
        "sess:a1",
    );
    valid.push(json!({"name": "null-and-empty-optionals", "line": b.lines[2], "signer_pub": encode_key(&k.s1.verifying_key()), "hash": b.hash(3)}));

    // Each invalid case breaks one rule of an otherwise valid, freshly signed entry 3.
    let mut invalid = vec![];
    let mut case = |name: &str, f: &dyn Fn(&mut J), error: &str| {
        let mut b = basic(k);
        b.edit(3, |j| f(j));
        let mut j: J = serde_json::from_str(&b.lines[2]).unwrap();
        j.as_object_mut().unwrap().remove("sig");
        let mut msg = b"tenbri/entry/v1\0".to_vec();
        msg.extend(canon::to_vec(&canon::from_serialize(&j).unwrap()));
        use tenbri_core::sign::Signer;
        let sig = k.s1.sign(&msg);
        j["sig"] = json!(format!("ed25519:{}", encoding::hex(&sig.to_bytes())));
        let line = String::from_utf8(canon::to_vec(&canon::from_serialize(&j).unwrap())).unwrap();
        invalid.push(json!({"name": name, "line": line, "error": error}));
    };
    case("unknown-field", &|j| j["extra"] = json!(1), "unknown_field");
    case(
        "missing-signer",
        &|j| {
            j.as_object_mut().unwrap().remove("signer");
        },
        "invalid_field",
    );
    case("version-2", &|j| j["v"] = json!(2), "invalid_field");
    case(
        "lowercase-id",
        &|j| j["id"] = json!(j["id"].as_str().unwrap().to_lowercase()),
        "invalid_field",
    );
    case("seq-zero", &|j| j["seq"] = json!(0), "invalid_field");
    case(
        "ts-without-milliseconds",
        &|j| j["ts"] = json!("2026-10-14T14:02:13Z"),
        "invalid_field",
    );
    case(
        "ts-not-a-date",
        &|j| j["ts"] = json!("2026-02-30T14:02:13.000Z"),
        "invalid_field",
    );
    case(
        "uppercase-prev",
        &|j| {
            j["prev"] = json!(
                j["prev"]
                    .as_str()
                    .unwrap()
                    .to_uppercase()
                    .replacen("SHA256", "sha256", 1)
            )
        },
        "invalid_field",
    );
    case(
        "decision-without-phase",
        &|j| {
            j.as_object_mut().unwrap().remove("phase");
        },
        "invalid_field",
    );
    case(
        "intent-with-status",
        &|j| j["status"] = json!("ok"),
        "invalid_field",
    );
    case(
        "outcome-without-intent",
        &|j| {
            j["phase"] = json!("outcome");
            j["status"] = json!("ok");
        },
        "invalid_field",
    );
    case(
        "proxy-with-rule",
        &|j| j["source"] = json!("proxy"),
        "invalid_field",
    );
    case(
        "ingest-intent",
        &|j| {
            j["source"] = json!("ingest");
            j.as_object_mut().unwrap().remove("rule");
        },
        "invalid_field",
    );
    case(
        "key-member-on-decision",
        &|j| j["key"] = json!({"op": "revoke", "id": "sess:a1", "from": 1}),
        "invalid_field",
    );
    case(
        "unknown-nested-field",
        &|j| j["principal"]["email"] = json!("a@example.com"),
        "invalid_field",
    );
    case(
        "unknown-enum-value",
        &|j| j["kind"] = json!("decree"),
        "invalid_field",
    );
    case(
        "empty-principal-id",
        &|j| j["principal"]["id"] = json!(""),
        "invalid_field",
    );
    case(
        "prev-missing",
        &|j| {
            j.as_object_mut().unwrap().remove("prev");
        },
        "invalid_field",
    );
    case(
        "group-after-genesis",
        &|j| j["group"] = json!("tenant-a"),
        "invalid_field",
    );
    case(
        "unkeyed-digest",
        &|j| j["inputs"][0]["digest"] = json!(sha256(b"x")),
        "invalid_field",
    );

    let line = &base.lines[2];
    let raw =
        |name: &str, line: String, error: &str| json!({"name": name, "line": line, "error": error});
    invalid.extend([
        raw("whitespace", line.replacen(",", ", ", 1), "not_canonical"),
        raw("trailing-line-feed", format!("{line}\n"), "not_canonical"),
        raw(
            "escaped-letter",
            line.replacen("support-assistant", "\\u0073upport-assistant", 1),
            "not_canonical",
        ),
        raw(
            "duplicate-key",
            line.replacen("{", "{\"v\":1,", 1),
            "duplicate_key",
        ),
        raw(
            "float-in-ext",
            line.replacen("{", "{\"ext\":{\"x\":1.5},", 1),
            "not_integer",
        ),
        raw(
            "exponent",
            line.replacen("\"v\":1", "\"v\":1e0", 1),
            "not_integer",
        ),
        raw(
            "integer-too-large",
            line.replacen("{", "{\"ext\":{\"x\":9007199254740992},", 1),
            "integer_range",
        ),
        raw("not-an-object", "[1]".into(), "invalid_field"),
        raw(
            "uppercase-signature",
            {
                let at = line.find("\"sig\":\"ed25519:").unwrap() + "\"sig\":\"ed25519:".len();
                format!(
                    "{}{}{}",
                    &line[..at],
                    line[at..at + 128].to_uppercase(),
                    &line[at + 128..]
                )
            },
            "invalid_field",
        ),
        raw("truncated", line[..line.len() - 1].to_owned(), "parse"),
    ]);
    // Signatures: valid entries whose signature is over the wrong message.
    let sig_case = |name: &str, prefix: &[u8], flip: bool| {
        let mut v = canon::parse(line.as_bytes()).unwrap();
        v.remove("sig");
        let mut msg = prefix.to_vec();
        msg.extend(canon::to_vec(&v));
        use tenbri_core::sign::Signer;
        let mut sig = k.s1.sign(&msg).to_bytes();
        if flip {
            sig[0] ^= 1;
        }
        let mut j: J = serde_json::from_str(line).unwrap();
        j["sig"] = json!(format!("ed25519:{}", encoding::hex(&sig)));
        json!({"name": name, "line": String::from_utf8(canon::to_vec(&canon::from_serialize(&j).unwrap())).unwrap(), "signer_pub": encode_key(&k.s1.verifying_key()), "error": "bad_signature"})
    };
    invalid.push(sig_case(
        "signature-flipped-bit",
        b"tenbri/entry/v1\0",
        true,
    ));
    invalid.push(sig_case("signature-without-prefix", b"", false));
    invalid.push(sig_case(
        "signature-with-head-prefix",
        b"tenbri/head/v1\0",
        false,
    ));
    invalid.push(json!({"name": "signature-by-other-key", "line": line, "signer_pub": encode_key(&k.attacker.verifying_key()), "error": "bad_signature"}));
    json!({"valid": valid, "invalid": invalid})
}

fn head(b: &B, signer: &str, k: &SigningKey, batch: u64, counter: u64) -> Head {
    let mut h = Head {
        v: 1,
        stream: b.stream.clone(),
        seq: b.seq(),
        hash: b.hash(b.seq()),
        counter,
        batch,
        signer: signer.into(),
        sig: String::new(),
    };
    sign_head(&mut h, k);
    h
}

fn heads(k: &K) -> J {
    let b = basic(k);
    let h = head(&b, "sess:a1", &k.s1, 8, 14);
    let bytes = String::from_utf8(canon::to_vec(&canon::from_serialize(&h).unwrap())).unwrap();
    let mut v = canon::from_serialize(&h).unwrap();
    v.remove("sig");
    let input = format!(
        "tenbri/head/v1\0{}",
        String::from_utf8(canon::to_vec(&v)).unwrap()
    );
    let mut entry_prefixed = h.clone();
    {
        use tenbri_core::sign::Signer;
        let mut msg = b"tenbri/entry/v1\0".to_vec();
        msg.extend(canon::to_vec(&v));
        entry_prefixed.sig = format!("ed25519:{}", encoding::hex(&k.s1.sign(&msg).to_bytes()));
    }
    let ser = |h: &J| String::from_utf8(canon::to_vec(&canon::from_serialize(h).unwrap())).unwrap();
    let mut extra: J = serde_json::to_value(&h).unwrap();
    extra["lease"] = json!("w1");
    let mut over: J = serde_json::to_value(&h).unwrap();
    over["batch"] = json!(15);
    let pk = encode_key(&k.s1.verifying_key());
    json!({"cases": [
        {"name": "valid", "head": bytes, "signer_pub": pk, "signing_input": input},
        {"name": "signed-with-entry-prefix", "head": ser(&serde_json::to_value(&entry_prefixed).unwrap()), "signer_pub": pk, "error": "bad_signature"},
        {"name": "unknown-field", "head": ser(&extra), "signer_pub": pk, "error": "unknown_field"},
        {"name": "batch-after-seq", "head": ser(&over), "signer_pub": pk, "error": "bad_head"},
        {"name": "not-canonical", "head": bytes.replacen(",", ", ", 1), "signer_pub": pk, "error": "not_canonical"},
    ]})
}

fn write_stream(dir: &Path, b: &B, batches: &[(u64, u64)], head_bytes: &[u8]) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir.join("batches")).unwrap();
    for (first, last) in batches {
        let body: String = b.lines[*first as usize - 1..*last as usize]
            .iter()
            .map(|l| format!("{l}\n"))
            .collect();
        fs::write(dir.join(format!("batches/{first:012}.jsonl")), body).unwrap();
    }
    fs::write(dir.join("HEAD"), head_bytes).unwrap();
}

fn streams(k: &K, root: &Path) -> J {
    let b = basic(k);
    let hb = |h: &Head| canon::to_vec(&canon::from_serialize(h).unwrap());
    let good = hb(&head(&b, "sess:a1", &k.s1, 8, 14));
    let layout = [(1, 2), (3, 7), (8, 14)];
    write_stream(&root.join("basic"), &b, &layout, &good);
    let mut longer = b.clone();
    longer.push(note(), &k.s1, "sess:a1");
    write_stream(
        &root.join("orphan-batch"),
        &longer,
        &[(1, 2), (3, 7), (8, 14), (15, 15)],
        &good,
    );
    write_stream(&root.join("missing-batch"), &b, &[(1, 2), (8, 14)], &good);
    let mut bad = head(&b, "sess:a1", &k.s1, 8, 14);
    bad.hash = b.hash(13);
    sign_head(&mut bad, &k.s1);
    write_stream(&root.join("head-not-last-entry"), &b, &layout, &hb(&bad));
    let mut short = b.clone();
    short.entries.truncate(10);
    short.lines.truncate(10);
    write_stream(
        &root.join("head-mid-batch"),
        &b,
        &layout,
        &hb(&head(&short, "sess:a1", &k.s1, 8, 10)),
    );
    let pin = fingerprint(&k.a.verifying_key());
    json!({"cases": [
        {"name": "basic", "pin": pin, "result": ok(14)},
        {"name": "orphan-batch", "pin": pin, "result": ok(14), "note": "batch 15 chains from HEAD but HEAD does not name it: readers do not see it, a writer rolls it forward"},
        {"name": "missing-batch", "pin": pin, "result": broken(3, "missing_batch")},
        {"name": "head-not-last-entry", "pin": pin, "result": broken(14, "bad_head")},
        {"name": "head-mid-batch", "pin": pin, "result": broken(10, "bad_head")},
    ]})
}

fn canonical() -> J {
    let c = |name: &str, input: &str, canonical: &str| json!({"name": name, "input": input, "canonical": canonical});
    let e = |name: &str, input: &str, error: &str| json!({"name": name, "input": input, "error": error});
    json!({"cases": [
        c("already-canonical", r#"{"a":1,"b":[true,false,null]}"#, r#"{"a":1,"b":[true,false,null]}"#),
        c("whitespace", "{ \"a\" : 1 ,\n\t\"b\" : [ 1 , 2 ] }\r\n", r#"{"a":1,"b":[1,2]}"#),
        c("key-order", r#"{"b":1,"a":2,"c":{"z":0,"y":0}}"#, r#"{"a":2,"b":1,"c":{"y":0,"z":0}}"#),
        c("key-order-utf16", "{\"\u{fb33}\":1,\"\u{1f600}\":2,\"\u{20ac}\":3,\"a\":4}", "{\"a\":4,\"\u{20ac}\":3,\"\u{1f600}\":2,\"\u{fb33}\":1}"),
        c("key-order-case", r#"{"b":1,"B":2,"a":3,"_":4}"#, r#"{"B":2,"_":4,"a":3,"b":1}"#),
        c("empty", r#"{ "o" : { } , "a" : [ ] , "s" : "" }"#, r#"{"a":[],"o":{},"s":""}"#),
        c("integers", r#"[0,-1,9007199254740991,-9007199254740991,42]"#, r#"[0,-1,9007199254740991,-9007199254740991,42]"#),
        c("escapes-shortened", r#"["\u0041","\/","\u00e9","\u20ac","\ud83d\ude00"]"#, "[\"A\",\"/\",\"é\",\"€\",\"😀\"]"),
        c("escapes-kept", r#"["\"","\\","\b","\t","\n","\f","\r","\u0000","\u001F","\u007f"]"#, "[\"\\\"\",\"\\\\\",\"\\b\",\"\\t\",\"\\n\",\"\\f\",\"\\r\",\"\\u0000\",\"\\u001f\",\"\u{7f}\"]"),
        c("line-separator-literal", "[\"\\u2028\\u2029\"]", "[\"\u{2028}\u{2029}\"]"),
        c("literals", r#"[ true , false , null ]"#, r#"[true,false,null]"#),
        e("duplicate-key", r#"{"a":1,"a":1}"#, "duplicate_key"),
        e("duplicate-key-different-values", r#"{"a":1,"b":2,"a":3}"#, "duplicate_key"),
        e("duplicate-key-nested", r#"{"x":[{"k":1,"k":2}]}"#, "duplicate_key"),
        e("duplicate-key-by-escape", r#"{"a":1,"\u0061":2}"#, "duplicate_key"),
        e("fraction", r#"{"a":1.0}"#, "not_integer"),
        e("fraction-nonzero", r#"[1.5]"#, "not_integer"),
        e("exponent", r#"[1e2]"#, "not_integer"),
        e("exponent-upper", r#"[1E2]"#, "not_integer"),
        e("negative-zero", r#"[-0]"#, "not_integer"),
        e("too-large", r#"[9007199254740992]"#, "integer_range"),
        e("too-small", r#"[-9007199254740992]"#, "integer_range"),
        e("leading-zero", r#"[01]"#, "parse"),
        e("plus-sign", r#"[+1]"#, "parse"),
        e("lone-surrogate", r#"["\ud800"]"#, "parse"),
        e("trailing-data", r#"{"a":1} {"b":2}"#, "parse"),
        e("trailing-comma", r#"[1,]"#, "parse"),
        e("single-quotes", r#"{'a':1}"#, "parse"),
        e("byte-order-mark", "\u{feff}{\"a\":1}", "parse"),
        e("raw-control-character", "[\"a\u{1}b\"]", "parse"),
        json!({"name": "invalid-utf8", "input_hex": "5b22ff225d", "error": "parse"}),
    ]})
}

fn keys(k: &K) -> J {
    let one = |name: &str, id: &str, key: &SigningKey| json!({"name": name, "id": id, "seed": encoding::hex(key.as_bytes()), "pub": encode_key(&key.verifying_key()), "fingerprint": fingerprint(&key.verifying_key()), "stream_id_if_genesis": stream_id(&key.verifying_key())});
    json!({"seeds": "SHA-256 of \"tenbri vector key <name>\"; Ed25519 seeds as in RFC 8032", "keys": [
        one("a", "stream:a", &k.a), one("s1", "sess:a1", &k.s1), one("s2", "sess:a2 or sess:b1", &k.s2),
        one("b", "stream:b", &k.b), one("attacker", "", &k.attacker), one("approver", "", &k.approver),
    ]})
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: vectors <spec/vectors>");
    let out = Path::new(&out);
    let k = K {
        a: key("a"),
        s1: key("s1"),
        s2: key("s2"),
        b: key("b"),
        attacker: key("attacker"),
        approver: key("approver"),
    };
    let write = |name: &str, j: J| {
        fs::write(
            out.join(name),
            serde_json::to_string_pretty(&j).unwrap() + "\n",
        )
        .unwrap()
    };
    write("keys.json", keys(&k));
    write("canonical.json", canonical());
    write("entries.json", entries(&k));
    write("chains.json", json!({"cases": chains(&k)}));
    write("heads.json", heads(&k));
    write("streams.json", streams(&k, &out.join("streams")));
}
