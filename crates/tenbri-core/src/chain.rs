//! A stream's state, entry by entry: the chain, the keys, the open intents (spec/format-v1.md,
//! sections 4.3, 5, 6 and 9). Feed it stored lines in order.

use std::collections::{HashMap, HashSet};

use crate::canon::Value;
use crate::encoding::{parse_ts, parse_ulid};
use crate::entry::{Entry, KeyEvent, Kind, Phase, Role, parse_line};
use crate::error::{Broken, Code, Error};
use crate::head::Head;
use crate::sign::{
    ATTESTATION_PREFIX, ENTRY_PREFIX, HEAD_PREFIX, NOT_ATTESTED, VerifyingKey, decode_key,
    entry_hash, fingerprint, message, stream_id, verify,
};

/// A key the stream certified.
#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub public: VerifyingKey,
    pub role: Role,
    /// Sessions only: the last timestamp the key may sign at.
    pub not_after: Option<String>,
    /// Entries this key signed at this sequence number or later are invalid.
    pub revoked_from: Option<u64>,
    /// The sequence number of the entry that certified it.
    pub certified_at: u64,
}

/// An intent with no outcome yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenIntent {
    pub ts: String,
    pub reconciled: bool,
}

/// An entry that passed every check against the stream so far; [`Chain::apply`] adds it.
#[derive(Clone, Debug)]
pub struct Checked {
    pub entry: Entry,
    pub hash: String,
    /// For a revocation: the earliest entry already in the stream that it makes invalid.
    pub invalidates: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Chain {
    pin: Option<String>,
    stream: Option<String>,
    seq: u64,
    last_hash: Option<String>,
    keys: HashMap<String, KeyInfo>,
    publics: HashSet<[u8; 32]>,
    stream_key: Option<String>,
    signed: HashMap<String, Vec<u64>>,
    ids: HashSet<u128>,
    open: HashMap<String, OpenIntent>,
    approvals: HashSet<String>,
    hlc: Option<(u64, u64)>,
    invalidated: Option<Broken>,
}

impl Chain {
    /// An empty stream. `pin` is the fingerprint (`sha256:…`) the genesis key must have; without
    /// one the chain is only consistent with itself.
    pub fn new(pin: Option<&str>) -> Self {
        Chain {
            pin: pin.map(str::to_owned),
            ..Default::default()
        }
    }

    pub fn pinned(&self) -> bool {
        self.pin.is_some()
    }
    /// The last sequence number added, 0 for an empty stream.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn last_hash(&self) -> Option<&str> {
        self.last_hash.as_deref()
    }
    pub fn stream(&self) -> Option<&str> {
        self.stream.as_deref()
    }
    pub fn key(&self, id: &str) -> Option<&KeyInfo> {
        self.keys.get(id)
    }
    /// The id of the current stream key.
    pub fn stream_key(&self) -> Option<&str> {
        self.stream_key.as_deref()
    }
    pub fn keys(&self) -> impl Iterator<Item = (&str, &KeyInfo)> {
        self.keys.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// Intents with no outcome yet, by id.
    pub fn open_intents(&self) -> &HashMap<String, OpenIntent> {
        &self.open
    }
    /// The earliest entry a later revocation made invalid, if any.
    pub fn invalidated(&self) -> Option<&Broken> {
        self.invalidated.as_ref()
    }

    /// Checks `line` against every rule, as the next entry, without changing the chain.
    pub fn check(&self, line: &[u8]) -> Result<Checked, Error> {
        self.check_at(line, false)
    }

    /// Checks `line` as a later entry that may skip some, as a receipt holds them
    /// (spec/receipts.md): its `seq` is above the last one's, and only the rules one entry and the
    /// keys before it decide apply: genesis, stream, signer, signature, attestations, key events.
    /// `prev`, id uniqueness, `hlc`, intents and approvals need the entries in between; the
    /// receipt's inclusion proofs stand in for them. Feed it every key entry in order, then
    /// [`Chain::apply`] what it accepts.
    pub fn check_detached(&self, line: &[u8]) -> Result<Checked, Error> {
        self.check_at(line, true)
    }

    fn check_at(&self, line: &[u8], detached: bool) -> Result<Checked, Error> {
        let (entry, value) = parse_line(line)?;
        let seq = if detached { entry.seq } else { self.seq + 1 };
        if entry.seq != seq || entry.seq <= self.seq {
            return Err(Error::new(
                Code::BadSeq,
                format!("expected seq {}, found {}", self.seq + 1, entry.seq),
            ));
        }
        let signer_key = if seq == 1 {
            self.check_genesis(&entry)?
        } else {
            if Some(entry.stream.as_str()) != self.stream() {
                return Err(Error::new(
                    Code::WrongStream,
                    format!("`stream` is {}", entry.stream),
                ));
            }
            if !detached && entry.prev.as_deref() != self.last_hash() {
                return Err(Error::new(
                    Code::BadPrev,
                    "`prev` is not the previous entry's hash",
                ));
            }
            None
        };
        let id = parse_ulid(&entry.id).expect("validated");
        if !detached && self.ids.contains(&id) {
            return Err(Error::new(
                Code::DuplicateId,
                format!("id {} is used before", entry.id),
            ));
        }
        let public = match signer_key {
            Some(k) => k,
            None => self.check_signer(&entry, seq)?,
        };
        verify(
            &public,
            &message(ENTRY_PREFIX, &value, &["sig"]),
            &entry.sig,
        )?;
        check_attestations(&entry, &value)?;
        if !detached {
            if let Some(h) = entry.hlc {
                if self.hlc.is_some_and(|last| (h.wall, h.count) < last) {
                    return Err(Error::new(Code::BadHlc, "`hlc` went backwards"));
                }
            }
            self.check_links(&entry)?;
        }
        let invalidates = match (seq, &entry.key) {
            (1, _) | (_, None) => None,
            (_, Some(k)) => self.check_key_event(k)?,
        };
        Ok(Checked {
            hash: entry_hash(line),
            entry,
            invalidates,
        })
    }

    /// Adds an entry [`Chain::check`] accepted.
    pub fn apply(&mut self, c: Checked) -> Entry {
        let Checked {
            entry: e,
            hash,
            invalidates,
        } = c;
        self.seq = e.seq;
        self.ids.insert(parse_ulid(&e.id).expect("validated"));
        self.signed.entry(e.signer.clone()).or_default().push(e.seq);
        if let Some(h) = e.hlc {
            self.hlc = Some((h.wall, h.count));
        }
        match e.kind {
            Kind::Decision if e.phase == Some(Phase::Intent) => {
                self.open.insert(
                    e.id.clone(),
                    OpenIntent {
                        ts: e.ts.clone(),
                        reconciled: false,
                    },
                );
            }
            Kind::Decision => {
                if let Some(i) = &e.intent {
                    self.open.remove(i);
                }
            }
            Kind::Reconcile => {
                if let Some(o) = e.intent.as_ref().and_then(|i| self.open.get_mut(i)) {
                    o.reconciled = true;
                }
            }
            Kind::Approval => {
                self.approvals.insert(hash.clone());
            }
            Kind::Key | Kind::Note => {}
        }
        match &e.key {
            Some(KeyEvent::Certify {
                id,
                public,
                role,
                not_after,
            }) => {
                self.add_key(id, public, *role, not_after.clone(), e.seq);
                if e.seq == 1 {
                    self.stream = Some(e.stream.clone());
                    self.stream_key = Some(id.clone());
                }
            }
            Some(KeyEvent::Rotate { id, public }) => {
                self.add_key(id, public, Role::Stream, None, e.seq);
                self.stream_key = Some(id.clone());
            }
            Some(KeyEvent::Revoke { id, from }) => {
                if let Some(k) = self.keys.get_mut(id) {
                    k.revoked_from = Some(k.revoked_from.map_or(*from, |f| f.min(*from)));
                }
                if let Some(s) = invalidates {
                    if self.invalidated.as_ref().is_none_or(|b| s < b.seq) {
                        self.invalidated = Some(Broken {
                            seq: s,
                            error: Error::new(
                                Code::KeyRevoked,
                                format!("{id} is revoked from seq {from}"),
                            ),
                        });
                    }
                }
            }
            None => {}
        }
        self.last_hash = Some(hash);
        e
    }

    /// Checks and adds the next entry; the error carries its sequence number.
    pub fn push(&mut self, line: &[u8]) -> Result<Entry, Broken> {
        let c = self.check(line).map_err(|error| Broken {
            seq: self.seq + 1,
            error,
        })?;
        Ok(self.apply(c))
    }

    /// Checks stored HEAD bytes against the stream as it stands: same stream, pointing at the last
    /// entry, which is in the batch starting at `batch`, signed by a key valid there.
    pub fn check_head(&self, bytes: &[u8], batch: u64) -> Result<Head, Error> {
        let (head, value) = Head::parse(bytes)?;
        let bad = |d: &str| Error::new(Code::BadHead, d.to_owned());
        if Some(head.stream.as_str()) != self.stream() {
            return Err(Error::new(
                Code::WrongStream,
                format!("HEAD is for {}", head.stream),
            ));
        }
        if head.seq != self.seq || Some(head.hash.as_str()) != self.last_hash() {
            return Err(bad("HEAD does not name the last entry"));
        }
        if head.batch != batch {
            return Err(bad("HEAD names the wrong batch"));
        }
        let key = self.keys.get(&head.signer).ok_or_else(|| {
            Error::new(Code::UnknownSigner, format!("HEAD signer {}", head.signer))
        })?;
        let current = self.stream_key() == Some(head.signer.as_str());
        if !(current || key.role == Role::Session) {
            return Err(Error::new(
                Code::SignerNotAllowed,
                "HEAD signed by a retired stream key",
            ));
        }
        if key.revoked_from.is_some_and(|f| f <= head.seq) {
            return Err(Error::new(
                Code::KeyRevoked,
                format!("HEAD signer {} is revoked", head.signer),
            ));
        }
        verify(
            &key.public,
            &message(HEAD_PREFIX, &value, &["sig"]),
            &head.sig,
        )
        .map_err(|_| bad("the HEAD signature does not verify"))?;
        Ok(head)
    }

    fn add_key(&mut self, id: &str, public: &str, role: Role, not_after: Option<String>, seq: u64) {
        let public = decode_key(public).expect("validated");
        self.publics.insert(public.to_bytes());
        self.keys.insert(
            id.to_owned(),
            KeyInfo {
                public,
                role,
                not_after,
                revoked_from: None,
                certified_at: seq,
            },
        );
    }

    fn check_genesis(&self, e: &Entry) -> Result<Option<VerifyingKey>, Error> {
        let bad = |d: &str| Error::new(Code::BadGenesis, d.to_owned());
        let Some(KeyEvent::Certify {
            id,
            public,
            role: Role::Stream,
            ..
        }) = &e.key
        else {
            return Err(bad("entry 1 must certify the stream key"));
        };
        let public = decode_key(public)?;
        if e.stream != stream_id(&public) {
            return Err(bad("`stream` is not derived from the genesis key"));
        }
        if &e.signer != id {
            return Err(bad("the genesis key signs entry 1 itself"));
        }
        if let Some(pin) = &self.pin {
            if *pin != fingerprint(&public) {
                return Err(Error::new(
                    Code::UntrustedRoot,
                    format!(
                        "the genesis key is {}, not the pinned {pin}",
                        fingerprint(&public)
                    ),
                ));
            }
        }
        Ok(Some(public))
    }

    fn check_signer(&self, e: &Entry, seq: u64) -> Result<VerifyingKey, Error> {
        let key = self.keys.get(&e.signer).ok_or_else(|| {
            Error::new(
                Code::UnknownSigner,
                format!("{} was never certified", e.signer),
            )
        })?;
        let allowed = if e.kind == Kind::Key {
            self.stream_key() == Some(e.signer.as_str())
        } else {
            key.role == Role::Session
        };
        if !allowed {
            return Err(Error::new(
                Code::SignerNotAllowed,
                format!("{} may not sign this entry", e.signer),
            ));
        }
        if key.revoked_from.is_some_and(|f| f <= seq) {
            return Err(Error::new(
                Code::KeyRevoked,
                format!("{} is revoked", e.signer),
            ));
        }
        if let Some(na) = &key.not_after {
            if parse_ts(&e.ts) > parse_ts(na) {
                return Err(Error::new(
                    Code::KeyExpired,
                    format!("{} expired at {na}", e.signer),
                ));
            }
        }
        Ok(key.public)
    }

    fn check_links(&self, e: &Entry) -> Result<(), Error> {
        let intent = e.intent.as_deref();
        match e.kind {
            Kind::Decision if e.phase == Some(Phase::Outcome) => {
                if let Some(i) = intent {
                    if !self.open.contains_key(i) {
                        return Err(Error::new(Code::BadIntent, format!("no open intent {i}")));
                    }
                }
            }
            Kind::Reconcile => {
                let i = intent.expect("validated");
                if self.open.get(i).is_none_or(|o| o.reconciled) {
                    return Err(Error::new(
                        Code::BadIntent,
                        format!("no unreconciled intent {i}"),
                    ));
                }
            }
            _ => {}
        }
        if let Some(a) = &e.approval {
            if !self.approvals.contains(&a.entry) {
                return Err(Error::new(
                    Code::BadApproval,
                    format!("{} is no earlier approval", a.entry),
                ));
            }
        }
        Ok(())
    }

    fn check_key_event(&self, k: &KeyEvent) -> Result<Option<u64>, Error> {
        let bad = |d: String| Error::new(Code::BadKeyEvent, d);
        let new_key = |id: &str, public: &str| {
            if self.keys.contains_key(id) {
                return Err(bad(format!("key id {id} is used before")));
            }
            if self.publics.contains(&decode_key(public)?.to_bytes()) {
                return Err(bad("the public key is used before".into()));
            }
            Ok(None)
        };
        match k {
            KeyEvent::Certify {
                role: Role::Stream, ..
            } => Err(bad(
                "only the genesis entry certifies a stream key; rotate instead".into(),
            )),
            KeyEvent::Certify { id, public, .. } | KeyEvent::Rotate { id, public } => {
                new_key(id, public)
            }
            KeyEvent::Revoke { id, from } => {
                if !self.keys.contains_key(id) {
                    return Err(bad(format!("no key {id} to revoke")));
                }
                if self.stream_key() == Some(id.as_str()) {
                    return Err(bad("the current stream key is rotated, not revoked".into()));
                }
                let seqs = self.signed.get(id).map_or(&[][..], Vec::as_slice);
                Ok(seqs.get(seqs.partition_point(|s| s < from)).copied())
            }
        }
    }
}

fn check_attestations(e: &Entry, value: &Value) -> Result<(), Error> {
    let Some(atts) = &e.attestations else {
        return Ok(());
    };
    let msg = message(ATTESTATION_PREFIX, value, &NOT_ATTESTED);
    for a in atts {
        verify(&decode_key(&a.key)?, &msg, &a.sig)?;
    }
    Ok(())
}
