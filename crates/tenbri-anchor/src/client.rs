//! Asking a timestamp authority over HTTP (RFC 3161, section 3.4).

use std::io;
use std::time::Duration;

use crate::{check_reply, request};

/// Asks the TSA at `url` to timestamp `text` (a checkpoint's note text) and returns its response
/// (DER `TimeStampResp`, what `anchors/<size>.tsr` holds), after checking that it is granted,
/// for this text, and echoes the request's nonce. The signature is checked by whoever verifies,
/// against the TSA roots they pinned.
pub async fn timestamp(url: &str, text: &[u8]) -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    // A positive INTEGER: clear the top bit.
    let nonce = u64::from_be_bytes(nonce) >> 1;
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(io::Error::other)?
        .post(url)
        .header("content-type", "application/timestamp-query")
        .body(request(text, Some(nonce)))
        .send()
        .await
        .map_err(io::Error::other)?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "TSA {url}: HTTP {}",
            resp.status()
        )));
    }
    let tsr = resp.bytes().await.map_err(io::Error::other)?.to_vec();
    check_reply(&tsr, text, Some(nonce))
        .map_err(|e| io::Error::other(format!("TSA {url}: {}", e.detail)))?;
    Ok(tsr)
}
