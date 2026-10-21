//! Submitting checkpoints to a C2SP witness over HTTP (c2sp.org/tlog-witness).

use std::io;
use std::time::Duration;

use tenbri_merkle::Note;
use tenbri_merkle::tree::Hash;
use tenbri_merkle::witness::{Witness, request};

/// The most of a witness's answer read: litewitness and omniwitness take 10 and 16 KiB requests,
/// and an answer is a few signature lines.
const MAX_BODY: usize = 16 * 1024;

/// What a witness answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// Its cosignature line, checked against the witness's pinned key.
    Cosigned(String),
    /// 409: it last cosigned the log at this size, not the `old` sent; send again from there.
    Conflict(u64),
    /// 422: the checkpoint contradicts one the witness cosigned. A fork, never retried; the
    /// witness's words, sanitised.
    Fork(String),
}

/// Sends `note` with `old`, the size the witness last cosigned, and the consistency proof from
/// it, to the witness `w` whose submission prefix is `url` (`POST <url>/add-checkpoint`). Keeps
/// only a cosignature line by `w` that verifies. Errors never carry the URL, which may hold
/// credentials, nor more than a short, printable part of the witness's answer.
pub async fn add_checkpoint(
    url: &str,
    w: &Witness,
    old: u64,
    proof: &[Hash],
    note: &[u8],
) -> io::Result<Added> {
    let err = |msg: String| io::Error::other(format!("witness {}: {msg}", w.name));
    let url = format!("{}/add-checkpoint", url.trim_end_matches('/'));
    let mut resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(io::Error::other)?
        .post(&url)
        .body(request(old, proof, note))
        .send()
        .await
        .map_err(|e| err(e.without_url().to_string()))?;
    let status = resp.status().as_u16();
    let mut body = vec![];
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| err(e.without_url().to_string()))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(err(format!(
                "HTTP {status}, an answer over {MAX_BODY} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&body);
    match status {
        200 => {
            let mut signed = note.to_vec();
            for line in body.lines().filter(|l| l.starts_with("\u{2014} ")) {
                signed.truncate(note.len());
                signed.extend(format!("{line}\n").bytes());
                let Ok(parsed) = Note::parse(&signed) else {
                    continue;
                };
                if let Some(t) = w.cosigned(&parsed) {
                    t.map_err(|e| err(e.detail))?;
                    return Ok(Added::Cosigned(format!("{line}\n")));
                }
            }
            Err(err("no cosignature by its pinned key".into()))
        }
        409 => body
            .trim()
            .parse()
            .map(Added::Conflict)
            .map_err(|_| err(format!("HTTP 409: {}", shown(&body)))),
        422 => Ok(Added::Fork(shown(&body))),
        s => Err(err(format!("HTTP {s}: {}", shown(&body)))),
    }
}

/// At most 200 characters of `s`, on one line, printable ASCII only.
fn shown(s: &str) -> String {
    s.trim()
        .chars()
        .take(200)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}
