//! A C2SP witness in memory (c2sp.org/tlog-witness), for tests: never for production, its key
//! comes from a seed anyone can read.

use std::collections::HashMap;
use std::sync::Mutex;

use tenbri_core::sign::{SigningKey, VerifyingKey};
use tenbri_merkle::tree::{Hash, root, verify_consistency};
use tenbri_merkle::witness::{self, Witness, parse_request};
use tenbri_merkle::{Checkpoint, Note};

/// A witness: a name, a cosigning key, and per log origin the log's key and the size and root it
/// last cosigned.
pub struct TestWitness {
    name: String,
    key: SigningKey,
    logs: Mutex<HashMap<String, (VerifyingKey, u64, Hash)>>,
}

impl TestWitness {
    /// The witness `name`, keyed from `seed`.
    pub fn new(name: &str, seed: [u8; 32]) -> TestWitness {
        TestWitness {
            name: name.to_owned(),
            key: SigningKey::from_bytes(&seed),
            logs: Mutex::default(),
        }
    }

    /// What a verifier pins.
    pub fn witness(&self) -> Witness {
        Witness {
            name: self.name.clone(),
            key: self.key.verifying_key(),
        }
    }

    /// Accepts checkpoints of `origin` signed by `key` (the stream's checkpoint key).
    pub fn add_log(&self, origin: &str, key: VerifyingKey) {
        self.logs
            .lock()
            .expect("lock")
            .insert(origin.to_owned(), (key, 0, root(&[])));
    }

    /// The size this witness last cosigned for `origin`.
    pub fn size(&self, origin: &str) -> Option<u64> {
        self.logs.lock().expect("lock").get(origin).map(|l| l.1)
    }

    /// Answers an `add-checkpoint` request body at `now`: status, content type and body.
    pub fn add_checkpoint(&self, body: &[u8], now: u64) -> (u16, &'static str, Vec<u8>) {
        const TEXT: &str = "text/plain; charset=utf-8";
        let fail = |status, msg: &str| (status, TEXT, format!("{msg}\n").into_bytes());
        let Some((old, proof, note)) = parse_request(body) else {
            return fail(400, "malformed request");
        };
        let Ok(note) = Note::parse(note) else {
            return fail(400, "malformed checkpoint");
        };
        let Checkpoint { origin, size, root } = &note.checkpoint;
        let mut logs = self.logs.lock().expect("lock");
        let Some((key, last, last_root)) = logs.get_mut(origin) else {
            return fail(404, "unknown log");
        };
        if note.signed_by(key) != Some(true) {
            return fail(403, "not signed by the log's key");
        }
        if old > *size {
            return fail(400, "old size above the checkpoint's");
        }
        if old != *last {
            return (409, "text/x.tlog.size", format!("{last}\n").into_bytes());
        }
        if (old == 0 && !proof.is_empty())
            || !verify_consistency(old, *size, last_root, root, &proof)
        {
            // A fork: the log showed this witness a different history before.
            return fail(422, "inconsistent with the checkpoint cosigned before");
        }
        (*last, *last_root) = (*size, *root);
        let line = witness::cosign(&self.name, &self.key, note.text(), now);
        (200, TEXT, line.into_bytes())
    }

    /// Serves tlog-witness over HTTP on 127.0.0.1, whatever the path, until the process ends.
    /// Returns its URL, the submission prefix.
    pub async fn serve(self: std::sync::Arc<Self>) -> std::io::Result<String> {
        crate::test_http::serve(move |body| self.add_checkpoint(body, crate::test_http::now()))
            .await
    }
}
