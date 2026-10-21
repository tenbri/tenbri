//! A stream written through tenbrid: the agent holds a bearer token, tenbrid holds the keys.
//!
//! The location is `https://host[:port]/<stream>`, `<stream>` being the stream's name in
//! tenbrid's configuration or its id; `http://` only to a loopback host. Every write is a batch of
//! one (`POST /v1/streams/{stream}/entries`) carrying its id, so a retry after a timeout returns
//! the entry written the first time.

use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    DEADLINE_EXCEEDED, Error, Filter, IDEMPOTENCY_CONFLICT, INVALID_ENTRY, INVALID_REQUEST,
    NO_SESSION_KEY, NOT_FOUND, STORE_UNAVAILABLE, STREAM_BROKEN, WRITE_CONFLICT,
};

/// No bearer token, or one tenbrid does not know.
pub const UNAUTHENTICATED: &str = "TENBRI_UNAUTHENTICATED";
/// The token may not use this stream, or the entry names another principal than the token's.
pub const FORBIDDEN: &str = "TENBRI_FORBIDDEN";
/// The entry breaks its action's schema in tenbrid's tenbri.toml. Nothing was written.
pub const SCHEMA_VIOLATION: &str = "TENBRI_SCHEMA_VIOLATION";
/// tenbrid failed on a bug of its own.
pub const INTERNAL: &str = "TENBRI_INTERNAL";

/// Whether `location` names a tenbrid rather than a stream's storage.
pub(crate) fn is_remote(location: &str) -> bool {
    location.starts_with("https://") || location.starts_with("http://")
}

pub(crate) struct Remote {
    http: Client,
    /// `<scheme>://<host>/v1/streams/<stream>`.
    base: Url,
    token: String,
    id: String,
}

impl Remote {
    pub(crate) async fn open(location: &str, token: Option<String>) -> Result<Remote, Error> {
        let bad = |m: String| Error::new(INVALID_REQUEST, m);
        let url = Url::parse(location).map_err(|e| bad(format!("{location}: {e}")))?;
        // The token is a credential: never in clear text off this machine.
        let loopback = match url.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            None => false,
        };
        if url.scheme() == "http" && !loopback {
            return Err(bad(format!(
                "{location}: tenbrid over http:// only on this machine; use https://"
            )));
        }
        let stream = match url.path_segments().map(|s| s.collect::<Vec<_>>()) {
            Some(s) if s.len() == 1 && !s[0].is_empty() => s[0].to_owned(),
            _ => {
                return Err(bad(format!(
                    "{location}: expected https://host[:port]/<stream>"
                )));
            }
        };
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
            return Err(bad(format!(
                "{location}: no credentials or query in the URL; the token goes in TENBRI_TOKEN"
            )));
        }
        let token = token
            .or_else(|| std::env::var("TENBRI_TOKEN").ok())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| bad("no token for tenbrid: pass token or set TENBRI_TOKEN".into()))?;
        let mut base = url.clone();
        base.path_segments_mut()
            .expect("an http URL has a path")
            .clear()
            .extend(["v1", "streams", &stream]);
        let mut r = Remote {
            http: Client::new(),
            base,
            token,
            id: String::new(),
        };
        // One cheap read: checks the token and the stream, and learns the stream's id.
        let page: Page = r.call(Method::GET, "entries?limit=1", None).await?;
        r.id = page.as_of.stream;
        Ok(r)
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Writes `draft` (with its id) and returns the entry as tenbrid stored it.
    pub(crate) async fn write(&self, draft: Map<String, Value>) -> Result<String, Error> {
        let id = draft.get("id").and_then(Value::as_str).map(str::to_owned);
        let body = serde_json::to_vec(&serde_json::json!({ "entries": [draft] }))
            .expect("JSON serializes");
        let out: Batch = self
            .call(Method::POST, "entries", Some(body))
            .await
            .map_err(|e| Error {
                id: id.clone(),
                ..e
            })?;
        match out.entries.into_iter().next() {
            Some(a) => Ok(a.entry.get().to_owned()),
            None => Err(Error {
                id,
                ..Error::new(INTERNAL, "tenbrid returned no entry")
            }),
        }
    }

    /// tenbrid's check of the whole stream, in the shape of [`crate::Stream::verify`]. tenbrid
    /// checks against the key it pins; a `key` given here must be that key.
    // ponytail: trusts tenbrid's report; a verifier that must not trust it checks receipts
    // (`GET .../receipt`, `tenbri receipt verify`) or reads the stream's storage itself.
    pub(crate) async fn verify(&self, key: Option<&str>) -> Result<String, Error> {
        let r: Verified = self.call(Method::GET, "verify", None).await?;
        if let Some(k) = key {
            if k != r.pinned_key {
                return Err(Error::new(
                    STREAM_BROKEN,
                    format!("tenbrid pins {}, not {k}", r.pinned_key),
                ));
            }
        }
        Ok(serde_json::json!({
            "stream": r.stream,
            "entries": r.entries,
            "pinned_key": r.pinned_key,
            "broken": r.broken,
            "checkpoint": null,
        })
        .to_string())
    }

    /// The keyed digest of an input under tenbrid's data key for `subject`.
    pub(crate) async fn digest(
        &self,
        subject: Option<&str>,
        content: &[u8],
    ) -> Result<String, Error> {
        let body = serde_json::json!({
            "subject": subject,
            "content": tenbri_merkle::checkpoint::base64(content),
        });
        let out: Digest = self
            .call(Method::POST, "digest", Some(body.to_string().into_bytes()))
            .await?;
        Ok(out.digest)
    }

    /// The entries matching `f`, as [`crate::Stream::query`] returns them, page by page.
    pub(crate) async fn query(&self, f: &Filter) -> Result<String, Error> {
        let mut out = Vec::new();
        let mut after = f.after_seq;
        let want = f.limit.unwrap_or(usize::MAX);
        while out.len() < want {
            // Built apart from the await: the serializer is not Send.
            let q = {
                let mut q = url::form_urlencoded::Serializer::new(String::new());
                for (r, v) in &f.inputs {
                    q.append_pair("input", &format!("{r}@{v}"));
                }
                for (k, v) in [
                    ("action", &f.action),
                    ("principal", &f.principal),
                    ("target", &f.target),
                    ("subject", &f.subject),
                ] {
                    if let Some(v) = v {
                        q.append_pair(k, v);
                    }
                }
                q.append_pair("after_seq", &after.to_string());
                q.append_pair("limit", &(want - out.len()).min(1000).to_string());
                q.finish()
            };
            let page: Page = self
                .call(Method::GET, &format!("entries?{q}"), None)
                .await?;
            out.extend(page.entries.into_iter().map(|e| {
                format!(
                    "{{\"verification\":\"{}\",\"entry\":{}}}",
                    e.verification,
                    e.entry.get()
                )
            }));
            match page.next_after_seq {
                Some(n) => after = n,
                None => break,
            }
        }
        Ok(format!("[{}]", out.join(",")))
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, Error> {
        let url = format!("{}/{path}", self.base);
        let mut req = self.http.request(method, &url).bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        let res = req
            .send()
            .await
            .map_err(|e| Error::new(STORE_UNAVAILABLE, format!("tenbrid at {url}: {e}")))?;
        let status = res.status();
        let bytes = res
            .bytes()
            .await
            .map_err(|e| Error::new(STORE_UNAVAILABLE, format!("tenbrid at {url}: {e}")))?;
        if !status.is_success() {
            return Err(failure(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            Error::new(
                INTERNAL,
                format!("tenbrid at {url}: unexpected answer: {e}"),
            )
        })
    }
}

/// tenbrid's error body as this crate's error; one without a known code by its HTTP status.
fn failure(status: StatusCode, body: &[u8]) -> Error {
    #[derive(Deserialize)]
    struct Body {
        error: Inner,
    }
    #[derive(Deserialize)]
    struct Inner {
        code: String,
        message: String,
        reason: Option<String>,
    }
    let known = [
        INVALID_REQUEST,
        INVALID_ENTRY,
        SCHEMA_VIOLATION,
        UNAUTHENTICATED,
        FORBIDDEN,
        NOT_FOUND,
        IDEMPOTENCY_CONFLICT,
        WRITE_CONFLICT,
        DEADLINE_EXCEEDED,
        STORE_UNAVAILABLE,
        NO_SESSION_KEY,
        STREAM_BROKEN,
        INTERNAL,
    ];
    match serde_json::from_slice::<Body>(body) {
        Ok(Body { error: i }) => {
            let code = known.into_iter().find(|c| *c == i.code).unwrap_or(INTERNAL);
            Error {
                reason: i.reason,
                ..Error::new(code, i.message)
            }
        }
        Err(_) => Error::new(
            if status.is_server_error() {
                STORE_UNAVAILABLE
            } else {
                INVALID_REQUEST
            },
            format!("tenbrid answered {status}"),
        ),
    }
}

#[derive(Deserialize)]
struct Page {
    entries: Vec<Queried>,
    next_after_seq: Option<u64>,
    as_of: AsOf,
}

#[derive(Deserialize)]
struct AsOf {
    stream: String,
}

#[derive(Deserialize)]
struct Queried {
    verification: String,
    entry: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
struct Batch {
    entries: Vec<Appended>,
}

#[derive(Deserialize)]
struct Appended {
    entry: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
struct Digest {
    digest: String,
}

#[derive(Deserialize)]
struct Verified {
    stream: String,
    entries: u64,
    pinned_key: String,
    broken: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_a_token_in_clear_text_off_this_machine() {
        let e = Remote::open("http://tenbrid.example/support", Some("t".into()))
            .await
            .err()
            .unwrap();
        assert_eq!(e.code, INVALID_REQUEST);
        assert!(e.message.contains("https://"), "{e}");
    }

    #[tokio::test]
    async fn needs_one_stream_segment_and_a_token() {
        for l in ["https://tenbrid.example/", "https://tenbrid.example/a/b"] {
            let e = Remote::open(l, Some("t".into())).await.err().unwrap();
            assert_eq!(e.code, INVALID_REQUEST, "{l}");
        }
        let e = Remote::open("https://u:p@tenbrid.example/s", Some("t".into()))
            .await
            .err()
            .unwrap();
        assert_eq!(e.code, INVALID_REQUEST);
    }

    #[test]
    fn maps_tenbrids_errors() {
        let e = failure(
            StatusCode::FORBIDDEN,
            br#"{"error":{"code":"TENBRI_FORBIDDEN","message":"no"}}"#,
        );
        assert_eq!((e.code, e.message.as_str()), (FORBIDDEN, "no"));
        assert_eq!(
            failure(StatusCode::BAD_GATEWAY, b"<html>").code,
            STORE_UNAVAILABLE
        );
    }
}
