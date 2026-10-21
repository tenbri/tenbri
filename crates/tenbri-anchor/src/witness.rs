//! Submitting checkpoints to a C2SP witness over HTTP (c2sp.org/tlog-witness).

use std::io;
use std::time::Duration;

use tenbri_merkle::Note;
use tenbri_merkle::tree::Hash;
use tenbri_merkle::witness::{Witness, request};

/// What a witness answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// Its cosignature line, checked against the witness's pinned key.
    Cosigned(String),
    /// 409: it last cosigned the log at this size, not the `old` sent; send again from there.
    Conflict(u64),
}

/// Sends `note` with `old`, the size the witness last cosigned, and the consistency proof from
/// it, to the witness `w` whose submission prefix is `url` (`POST <url>/add-checkpoint`). Keeps
/// only a cosignature line by `w` that verifies; anything else is an error, a 422 (the checkpoint
/// contradicts one the witness cosigned: a fork) among them.
pub async fn add_checkpoint(
    url: &str,
    w: &Witness,
    old: u64,
    proof: &[Hash],
    note: &[u8],
) -> io::Result<Added> {
    let url = format!("{}/add-checkpoint", url.trim_end_matches('/'));
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(io::Error::other)?
        .post(&url)
        .body(request(old, proof, note))
        .send()
        .await
        .map_err(io::Error::other)?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(io::Error::other)?;
    let err = |msg: String| io::Error::other(format!("witness {}: {msg}", w.name));
    match status {
        200 => {
            let mut signed = note.to_vec();
            for line in body.lines().filter(|l| l.starts_with("\u{2014} ")) {
                signed.truncate(note.len());
                signed.extend(format!("{line}\n").bytes());
                let parsed = Note::parse(&signed).map_err(|e| err(e.to_string()))?;
                if let Some(t) = w.cosigned(&parsed) {
                    t.map_err(|e| err(e.to_string()))?;
                    return Ok(Added::Cosigned(format!("{line}\n")));
                }
            }
            Err(err("no cosignature by its pinned key".into()))
        }
        409 => body
            .trim()
            .parse()
            .map(Added::Conflict)
            .map_err(|_| err(format!("409 with body {body:?}"))),
        422 => Err(err(format!(
            "422: the checkpoint is inconsistent with one it cosigned (a fork?): {}",
            body.trim()
        ))),
        s => Err(err(format!("HTTP {s}: {}", body.trim()))),
    }
}
