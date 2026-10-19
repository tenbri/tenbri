//! HEAD: the signed pointer to a stream's latest entry (spec/format-v1.md, section 6.4).

use serde::{Deserialize, Serialize};

use crate::canon::{self, MAX_INT, Value};
use crate::encoding::{is_key_id, prefixed};
use crate::entry::{FORMAT_VERSION, is_hash, is_stream_id};
use crate::error::{Code, Error};

const FIELDS: [&str; 8] = [
    "v", "stream", "seq", "hash", "counter", "batch", "signer", "sig",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub v: u64,
    pub stream: String,
    pub seq: u64,
    pub hash: String,
    pub counter: u64,
    pub batch: u64,
    pub signer: String,
    pub sig: String,
}

impl Head {
    /// Parses stored HEAD bytes and checks their form; [`crate::Chain::check_head`] checks them
    /// against the stream.
    pub fn parse(bytes: &[u8]) -> Result<(Head, Value), Error> {
        let value = canon::parse_stored(bytes)?;
        if let Some(k) = value.keys().find(|k| !FIELDS.contains(k)) {
            return Err(Error::new(Code::UnknownField, format!("HEAD has `{k}`")));
        }
        let bad = |d: String| Error::new(Code::BadHead, d);
        let head: Head = serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        let in_range = |n: u64| (1..=MAX_INT as u64).contains(&n);
        if head.v != FORMAT_VERSION
            || !is_stream_id(&head.stream)
            || !in_range(head.seq)
            || !in_range(head.batch)
            || head.batch > head.seq
            || head.counter > MAX_INT as u64
            || !is_hash(&head.hash)
            || !is_key_id(&head.signer)
            || prefixed::<64>(&head.sig, "ed25519:").is_none()
        {
            return Err(bad("a HEAD member is malformed".into()));
        }
        Ok((head, value))
    }
}
