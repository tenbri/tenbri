//! The entry of format v1 and the rules one entry must follow on its own (spec/format-v1.md,
//! section 4). Rules that need the rest of the stream are in [`crate::chain`].

use serde::{Deserialize, Serialize};

use crate::canon::{self, MAX_INT};
use crate::encoding::{is_key_id, parse_ts, parse_ulid, prefixed, unhex};
use crate::error::{Code, Error, invalid};

/// The format version this crate reads and writes. Changed only by hand, never by a release.
pub const FORMAT_VERSION: u64 = 1;

/// The top-level members format v1 defines; anything else is `unknown_field`.
pub const FIELDS: [&str; 29] = [
    "v",
    "id",
    "stream",
    "seq",
    "ts",
    "hlc",
    "trace",
    "durability",
    "group",
    "kind",
    "phase",
    "intent",
    "status",
    "source",
    "degraded",
    "principal",
    "action",
    "subject",
    "inputs",
    "rule",
    "approval",
    "links",
    "body",
    "attestations",
    "ext",
    "key",
    "prev",
    "signer",
    "sig",
];

/// One signed record. Build one with [`Entry::new`]; the writer fills `v`, `id`, `stream`, `seq`,
/// `ts`, `prev`, `signer` and `sig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub v: u64,
    pub id: String,
    pub stream: String,
    pub seq: u64,
    pub ts: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<Trace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability: Option<Durability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<Input>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<Rule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<Vec<Attestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub signer: String,
    pub sig: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hlc {
    pub wall: u64,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub trace_id: String,
    pub span_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    Local,
    Replicated,
    Postgres,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Decision,
    Approval,
    Key,
    Reconcile,
    #[default]
    Note,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Intent,
    Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
    Refused,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Sdk,
    Proxy,
    Ingest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Agent,
    Person,
    Service,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub r#ref: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub r#ref: String,
    pub version: String,
    pub result: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub by: Principal,
    pub entry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub stream: String,
    pub seq: u64,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel: Option<Rel>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rel {
    Cause,
    Handoff,
    Approval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub key: String,
    pub sig: String,
}

/// The key event of a `key` entry (spec/format-v1.md, section 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum KeyEvent {
    Certify {
        id: String,
        #[serde(rename = "pub")]
        public: String,
        role: Role,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_after: Option<String>,
    },
    Rotate {
        id: String,
        #[serde(rename = "pub")]
        public: String,
    },
    Revoke {
        id: String,
        from: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Stream,
    Session,
}

impl Entry {
    /// A draft of `kind` for a writer to complete and sign.
    pub fn new(kind: Kind) -> Self {
        Entry {
            v: FORMAT_VERSION,
            kind,
            ..Default::default()
        }
    }
}

/// Parses one stored line and checks every rule that needs no other entry: canonical bytes, the
/// members, their encodings and the kind rules. Returns the entry and its canonical value.
pub fn parse_line(line: &[u8]) -> Result<(Entry, canon::Value), Error> {
    let value = canon::parse_stored(line)?;
    if !matches!(value, canon::Value::Obj(_)) {
        return Err(invalid("an entry is a JSON object"));
    }
    if let Some(k) = value.keys().find(|k| !FIELDS.contains(k)) {
        return Err(Error::new(Code::UnknownField, format!("`{k}`")));
    }
    let entry: Entry = serde_json::from_slice(line).map_err(|e| invalid(e.to_string()))?;
    validate(&entry)?;
    Ok((entry, value))
}

fn check(ok: bool, what: impl FnOnce() -> String) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(invalid(what())) }
}

fn non_empty(s: &str, name: &str) -> Result<(), Error> {
    check(!s.is_empty(), || format!("`{name}` is empty"))
}

pub(crate) fn is_hash(s: &str) -> bool {
    prefixed::<32>(s, "sha256:").is_some()
}

pub(crate) fn is_stream_id(s: &str) -> bool {
    prefixed::<16>(s, "tnb1:").is_some()
}

/// Every single-entry rule of spec/format-v1.md, sections 2 and 4.
pub fn validate(e: &Entry) -> Result<(), Error> {
    check(e.v == FORMAT_VERSION, || format!("`v` is {}, not 1", e.v))?;
    check(parse_ulid(&e.id).is_some(), || {
        format!("`id` {:?} is not a ULID", e.id)
    })?;
    check(is_stream_id(&e.stream), || {
        format!("`stream` {:?} is not a stream id", e.stream)
    })?;
    check((1..=MAX_INT as u64).contains(&e.seq), || {
        "`seq` is out of range".into()
    })?;
    check(parse_ts(&e.ts).is_some(), || {
        format!("`ts` {:?} is not a timestamp", e.ts)
    })?;
    if let Some(h) = e.hlc {
        check(
            h.wall <= MAX_INT as u64 && h.count <= MAX_INT as u64,
            || "`hlc` out of range".into(),
        )?;
    }
    if let Some(t) = &e.trace {
        check(
            unhex::<16>(&t.trace_id).is_some() && unhex::<8>(&t.span_id).is_some(),
            || "`trace` ids must be 32 and 16 lowercase hex digits".into(),
        )?;
    }
    if let Some(g) = &e.group {
        non_empty(g, "group")?;
        check(e.seq == 1, || {
            "`group` is only allowed on the genesis entry".into()
        })?;
    }
    if let Some(i) = &e.intent {
        check(parse_ulid(i).is_some(), || {
            format!("`intent` {i:?} is not a ULID")
        })?;
    }
    if let Some(p) = &e.principal {
        non_empty(&p.id, "principal.id")?;
    }
    if let Some(a) = &e.action {
        non_empty(&a.r#type, "action.type")?;
        if let Some(t) = &a.target {
            non_empty(t, "action.target")?;
        }
    }
    if let Some(s) = &e.subject {
        non_empty(s, "subject")?;
    }
    for i in e.inputs.iter().flatten() {
        non_empty(&i.r#ref, "inputs.ref")?;
        non_empty(&i.version, "inputs.version")?;
        check(prefixed::<32>(&i.digest, "hmac-sha256:").is_some(), || {
            format!("input digest {:?} is not hmac-sha256:<64 hex>", i.digest)
        })?;
    }
    if let Some(r) = &e.rule {
        non_empty(&r.r#ref, "rule.ref")?;
        non_empty(&r.version, "rule.version")?;
        non_empty(&r.result, "rule.result")?;
    }
    if let Some(a) = &e.approval {
        non_empty(&a.by.id, "approval.by.id")?;
        check(is_hash(&a.entry), || {
            "`approval.entry` is not a hash".into()
        })?;
    }
    for l in e.links.iter().flatten() {
        check(
            is_stream_id(&l.stream) && (1..=MAX_INT as u64).contains(&l.seq) && is_hash(&l.hash),
            || "a link needs a stream id, a seq and a hash".into(),
        )?;
    }
    if let Some(b) = &e.body {
        check(prefixed::<32>(b, "blob:ct-sha256:").is_some(), || {
            format!("`body` {b:?} is not blob:ct-sha256:<64 hex>")
        })?;
    }
    for a in e.attestations.iter().flatten() {
        check(
            prefixed::<32>(&a.key, "ed25519:").is_some()
                && prefixed::<64>(&a.sig, "ed25519:").is_some(),
            || "an attestation needs an ed25519 key and signature".into(),
        )?;
    }
    match (&e.prev, e.seq) {
        (None, 1) => {}
        (Some(p), s) if s > 1 => check(is_hash(p), || "`prev` is not a hash".into())?,
        (None, _) => return Err(invalid("`prev` is required after the genesis entry")),
        (Some(_), _) => return Err(invalid("the genesis entry has no `prev`")),
    }
    check(is_key_id(&e.signer), || {
        format!("`signer` {:?} is not a key id", e.signer)
    })?;
    check(prefixed::<64>(&e.sig, "ed25519:").is_some(), || {
        "`sig` is not an ed25519 signature".into()
    })?;
    if let Some(k) = &e.key {
        validate_key_event(k)?;
    }
    kind_rules(e)
}

fn validate_key_event(k: &KeyEvent) -> Result<(), Error> {
    let (id, public) = match k {
        KeyEvent::Certify {
            id,
            public,
            role,
            not_after,
        } => {
            match (role, not_after) {
                (Role::Session, Some(t)) => check(parse_ts(t).is_some(), || {
                    "`key.not_after` is not a timestamp".into()
                })?,
                (Role::Session, None) => return Err(invalid("a session key needs `not_after`")),
                (Role::Stream, Some(_)) => return Err(invalid("a stream key has no `not_after`")),
                (Role::Stream, None) => {}
            }
            (id, Some(public))
        }
        KeyEvent::Rotate { id, public } => (id, Some(public)),
        KeyEvent::Revoke { id, from } => {
            check((1..=MAX_INT as u64).contains(from), || {
                "`key.from` is out of range".into()
            })?;
            (id, None)
        }
    };
    check(is_key_id(id), || format!("`key.id` {id:?} is not a key id"))?;
    if let Some(p) = public {
        check(prefixed::<32>(p, "ed25519:").is_some(), || {
            "`key.pub` is not an ed25519 key".into()
        })?;
    }
    Ok(())
}

fn kind_rules(e: &Entry) -> Result<(), Error> {
    let need = |ok: bool, what: &str| check(ok, || format!("a {} entry {what}", kind_name(e)));
    if e.kind != Kind::Key {
        need(e.key.is_none(), "has no `key`")?;
    }
    if matches!(e.source, Some(Source::Proxy | Source::Ingest)) {
        need(e.rule.is_none(), "from a proxy or ingest has no `rule`")?;
    }
    match e.kind {
        Kind::Decision => {
            need(e.source.is_some(), "needs `source`")?;
            need(e.principal.is_some(), "needs `principal`")?;
            need(e.action.is_some(), "needs `action`")?;
            match e.phase {
                Some(Phase::Intent) => {
                    need(
                        e.intent.is_none() && e.status.is_none(),
                        "intent has no `intent` or `status`",
                    )?;
                    need(
                        e.source != Some(Source::Ingest),
                        "from ingest is never an intent",
                    )?;
                }
                Some(Phase::Outcome) => {
                    need(e.status.is_some(), "outcome needs `status`")?;
                    if e.source == Some(Source::Ingest) {
                        need(e.intent.is_none(), "from ingest has no `intent`")?;
                    } else {
                        need(e.intent.is_some(), "outcome needs `intent`")?;
                    }
                }
                None => return Err(invalid("a decision entry needs `phase`")),
            }
        }
        Kind::Approval => {
            need(
                e.principal.is_some() && e.action.is_some(),
                "needs `principal` and `action`",
            )?;
            need(
                e.phase.is_none() && e.intent.is_none() && e.status.is_none(),
                "has no `phase`, `intent` or `status`",
            )?;
        }
        Kind::Key => {
            need(e.key.is_some(), "needs `key`")?;
            need(
                e.phase.is_none() && e.intent.is_none() && e.status.is_none(),
                "has no `phase`, `intent` or `status`",
            )?;
        }
        Kind::Reconcile => {
            need(e.intent.is_some(), "needs `intent`")?;
            need(e.status == Some(Status::Unknown), "has `status: unknown`")?;
            need(e.phase.is_none(), "has no `phase`")?;
        }
        Kind::Note => {
            need(
                e.phase.is_none() && e.intent.is_none() && e.status.is_none(),
                "has no `phase`, `intent` or `status`",
            )?;
        }
    }
    Ok(())
}

fn kind_name(e: &Entry) -> &'static str {
    match e.kind {
        Kind::Decision => "decision",
        Kind::Approval => "approval",
        Kind::Key => "key",
        Kind::Reconcile => "reconcile",
        Kind::Note => "note",
    }
}
