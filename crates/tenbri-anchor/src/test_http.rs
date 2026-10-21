//! A minimal HTTP/1.1 server on 127.0.0.1 for the test TSA and the test witness.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Seconds since the Unix epoch, by the clock.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// Answers every request with `handle(body)`: status, content type and body. Returns the URL.
pub(crate) async fn serve<F>(handle: F) -> std::io::Result<String>
where
    F: Fn(&[u8]) -> (u16, &'static str, Vec<u8>) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/", listener.local_addr()?);
    let handle = std::sync::Arc::new(handle);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let handle = handle.clone();
            tokio::spawn(async move {
                // ponytail: one request per connection, the headers in the first 64 KiB.
                let mut buf = vec![0; 65536];
                let mut n = 0;
                let body = loop {
                    let Ok(r) = s.read(&mut buf[n..]).await else {
                        return;
                    };
                    if r == 0 {
                        return;
                    }
                    n += r;
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let Some(end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if n >= end + 4 + len {
                        break buf[end + 4..end + 4 + len].to_vec();
                    }
                };
                let (status, ctype, body) = handle(&body);
                let head = format!(
                    "HTTP/1.1 {status} -\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    Ok(url)
}
