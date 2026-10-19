//! tenbrid's configuration: a TOML file, then `TENBRI_*` environment variables over it.
//!
//! ```toml
//! listen = "127.0.0.1:7070"        # REST; TENBRI_LISTEN
//! grpc_listen = "127.0.0.1:7071"   # gRPC; TENBRI_GRPC_LISTEN
//! keys = "/var/lib/tenbri/keys"    # TENBRI_KEYS; default ~/.config/tenbri/keys
//! schema = "tenbri.toml"           # action schemas; TENBRI_SCHEMA; none: nothing is checked
//! queue = 10000                    # entries waiting per stream; TENBRI_QUEUE
//! deadline_ms = 2000               # how long an append waits for the queue; TENBRI_DEADLINE_MS
//!
//! [streams.support]                # the stream's name in URLs (its tnb1: id works too)
//! path = "/var/lib/tenbri/audit/support"
//! key = "sha256:..."               # pin; default: the stream key held in `keys`
//!
//! [[tokens]]                       # `tenbrid token` makes one
//! sha256 = "sha256:..."            # SHA-256 of the bearer token; the token is never stored
//! principal = { kind = "agent", id = "support-assistant" }
//! streams = ["support"]            # default: every stream
//! ```
//!
//! Relative paths are relative to the file's directory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tenbri_core::Principal;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "listen")]
    pub listen: SocketAddr,
    #[serde(default = "grpc_listen")]
    pub grpc_listen: SocketAddr,
    pub keys: Option<PathBuf>,
    pub schema: Option<PathBuf>,
    #[serde(default = "queue")]
    pub queue: usize,
    #[serde(default = "deadline_ms")]
    pub deadline_ms: u64,
    #[serde(default)]
    pub streams: BTreeMap<String, StreamConfig>,
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    pub path: PathBuf,
    /// The genesis key's fingerprint (`sha256:…`) or public key (`ed25519:…`).
    pub key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub sha256: String,
    pub principal: Principal,
    pub streams: Option<Vec<String>>,
}

fn listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7070))
}
fn grpc_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7071))
}
fn queue() -> usize {
    10_000
}
fn deadline_ms() -> u64 {
    2_000
}

impl Config {
    /// Parses `text`, resolves relative paths against `base`, then applies `env` overrides.
    pub fn parse(
        text: &str,
        base: &Path,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Config, String> {
        let mut c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        let bad = |k: &str, v: &str| format!("{k}={v}: not a valid value");
        if let Some(v) = env("TENBRI_LISTEN") {
            c.listen = v.parse().map_err(|_| bad("TENBRI_LISTEN", &v))?;
        }
        if let Some(v) = env("TENBRI_GRPC_LISTEN") {
            c.grpc_listen = v.parse().map_err(|_| bad("TENBRI_GRPC_LISTEN", &v))?;
        }
        if let Some(v) = env("TENBRI_QUEUE") {
            c.queue = v.parse().map_err(|_| bad("TENBRI_QUEUE", &v))?;
        }
        if let Some(v) = env("TENBRI_DEADLINE_MS") {
            c.deadline_ms = v.parse().map_err(|_| bad("TENBRI_DEADLINE_MS", &v))?;
        }
        // Paths from the environment are relative to the working directory, as usual.
        c.keys = env("TENBRI_KEYS")
            .map(PathBuf::from)
            .or(c.keys.map(|p| base.join(p)));
        c.schema = env("TENBRI_SCHEMA")
            .map(PathBuf::from)
            .or(c.schema.map(|p| base.join(p)));
        for s in c.streams.values_mut() {
            s.path = base.join(&s.path);
        }
        if c.streams.is_empty() {
            return Err("no [streams.<name>] configured".into());
        }
        if c.tokens.is_empty() {
            return Err(
                "no [[tokens]] configured; tenbrid has no unauthenticated mode (make one with `tenbrid token`)"
                    .into(),
            );
        }
        if c.queue == 0 || c.queue > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(format!("queue = {}: out of range", c.queue));
        }
        for t in &c.tokens {
            if tenbri_core::encoding::prefixed::<32>(&t.sha256, "sha256:").is_none() {
                return Err(format!("tokens: {} is not sha256:<64 hex>", t.sha256));
            }
            if let Some(s) = t
                .streams
                .iter()
                .flatten()
                .find(|s| !c.streams.contains_key(*s))
            {
                return Err(format!("tokens: unknown stream `{s}`"));
            }
        }
        Ok(c)
    }

    /// Reads the file at `path`.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Config::parse(&text, base, |k| std::env::var(k).ok())
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
        keys = "keys"
        [streams.support]
        path = "audit/support"
        [[tokens]]
        sha256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        principal = { kind = "agent", id = "a" }
    "#;

    #[test]
    fn file_then_environment() {
        let c = Config::parse(FILE, Path::new("/etc/tenbri"), |_| None).unwrap();
        assert_eq!(c.listen, listen());
        assert_eq!(c.keys.unwrap(), Path::new("/etc/tenbri/keys"));
        assert_eq!(
            c.streams["support"].path,
            Path::new("/etc/tenbri/audit/support")
        );
        assert_eq!((c.queue, c.deadline_ms), (10_000, 2_000));

        let env = |k: &str| match k {
            "TENBRI_LISTEN" => Some("0.0.0.0:80".to_owned()),
            "TENBRI_KEYS" => Some("/k".to_owned()),
            "TENBRI_DEADLINE_MS" => Some("50".to_owned()),
            _ => None,
        };
        let c = Config::parse(FILE, Path::new("/etc/tenbri"), env).unwrap();
        assert_eq!(c.listen.port(), 80);
        assert_eq!(c.keys.unwrap(), Path::new("/k"));
        assert_eq!(c.deadline_ms, 50);
        assert!(Config::parse(FILE, Path::new("."), |_| Some("x".into())).is_err());
    }

    #[test]
    fn refuses_what_would_be_unsafe_or_a_typo() {
        let no_tokens = "[streams.s]\npath = \"s\"";
        assert!(Config::parse(no_tokens, Path::new("."), |_| None).is_err());
        for bad in [
            FILE.replace("keys =", "key ="),
            FILE.replace("sha256:00", "00"),
            format!("{FILE}streams = [\"other\"]"),
            FILE.replace("queue", "q") + "queue = 0",
        ] {
            assert!(
                Config::parse(&bad, Path::new("."), |_| None).is_err(),
                "{bad}"
            );
        }
    }
}
