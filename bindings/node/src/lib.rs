//! The native addon under the `tenbri` npm package (tenbri.js). Drafts and entries cross as JSON
//! strings; an error's message is a JSON object (`code`, `message`, `reason`, `id`) that tenbri.js
//! turns into its typed errors. Every method returns a Promise, resolved from napi-rs's Tokio
//! runtime, so concurrent appends share one lane's group commit.

use std::path::PathBuf;
use std::sync::Arc;

use napi::{Error, Result};
use napi_derive::napi;
use tenbri_bindings::Options;

fn err(e: tenbri_bindings::Error) -> Error {
    let body = serde_json::json!({
        "code": e.code,
        "message": e.message,
        "reason": e.reason,
        "id": e.id,
    });
    Error::from_reason(body.to_string())
}

/// The package's version.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// A new entry id (ULID), for idempotent retries.
#[napi]
pub fn new_id() -> Result<String> {
    tenbri_bindings::new_id().map_err(err)
}

/// The action schemas of the `tenbri.toml` at `path`, as JSON.
#[napi]
pub fn schemas(path: String) -> Result<String> {
    tenbri_bindings::schemas(std::path::Path::new(&path)).map_err(err)
}

#[napi(object)]
pub struct OpenOptions {
    pub keys: Option<String>,
    pub key: Option<String>,
    pub create: Option<bool>,
}

/// One open stream; see tenbri_bindings::Stream.
#[napi]
pub struct Stream(Arc<tenbri_bindings::Stream>);

#[napi]
impl Stream {
    #[napi]
    pub async fn open(location: String, options: Option<OpenOptions>) -> Result<Stream> {
        let o = options.map_or_else(Options::default, |o| Options {
            keys: o.keys.map(PathBuf::from),
            key: o.key,
            create: o.create.unwrap_or(false),
            ..Options::default()
        });
        let s = tenbri_bindings::Stream::open(&location, o)
            .await
            .map_err(err)?;
        Ok(Stream(Arc::new(s)))
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.0.id().into()
    }

    #[napi(getter)]
    pub fn fingerprint(&self) -> Option<String> {
        self.0.fingerprint().map(Into::into)
    }

    #[napi(getter)]
    pub fn writable(&self) -> bool {
        self.0.writable()
    }

    /// The keyed digest of `content` under `subject`'s data key (the tenant's without one) from
    /// this machine's key store.
    #[napi]
    pub fn digest(
        &self,
        subject: Option<String>,
        content: napi::bindgen_prelude::Buffer,
    ) -> Result<String> {
        self.0.digest(subject.as_deref(), &content).map_err(err)
    }

    #[napi]
    pub async fn append(&self, draft: String) -> Result<String> {
        self.0.append(draft.as_bytes()).await.map_err(err)
    }

    #[napi]
    pub async fn intent(&self, draft: String) -> Result<String> {
        self.0.intent(draft.as_bytes()).await.map_err(err)
    }

    #[napi]
    pub async fn outcome(&self, intent: String, status: String, draft: String) -> Result<String> {
        let s = &self.0;
        s.outcome(intent.as_bytes(), &status, draft.as_bytes())
            .await
            .map_err(err)
    }

    #[napi]
    pub async fn verify(&self, key: Option<String>) -> Result<String> {
        self.0.verify(key.as_deref()).await.map_err(err)
    }

    #[napi]
    pub async fn query(&self, filter: String) -> Result<String> {
        self.0.query(filter.as_bytes()).await.map_err(err)
    }

    #[napi]
    pub async fn flush(&self) {
        self.0.flush().await
    }

    #[napi]
    pub async fn close(&self) {
        self.0.close().await
    }
}
