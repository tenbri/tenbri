//! MCP proxy that records every tool call in a Tenbri stream.
//!
//! It sits between an MCP client and an MCP server on stdio (newline-delimited JSON-RPC) and passes
//! every message through, except that a `tools/call` is forwarded only once its intent is durable
//! in the stream, with `source: proxy` and the tool's name as the action type. The server's answer
//! closes it: `ok`, or `error` for a JSON-RPC error or a result with `isError`. A call the server
//! never answers is closed `unknown` when either side hangs up.
//!
//! The intent pins the call's `arguments` as an input, `mcp:<tool>/arguments` at
//! [`ARGUMENTS_VERSION`], by keyed digest. Through tenbrid that needs its digest route and a token
//! with `digest = true`; when the digest fails, the call is refused like one whose intent failed.
//!
//! The record comes from what crossed the wire, not from the agent's account of it. Opened on a
//! tenbrid (`https://host/<stream>`), the proxy holds a token and no signing key.
//!
//! Fail closed: when the intent can't be written, the client gets a JSON-RPC error and the server
//! never sees the call.

use std::collections::HashMap;
use std::sync::Arc;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tenbri_bindings::Stream;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The JSON-RPC error code of a call refused because it could not be recorded.
pub const NOT_RECORDED: i64 = -32001;

/// Who acts, as `{kind, id}`, from `agent:support` (`person:` and `service:` too).
pub fn principal(s: &str) -> Option<Value> {
    let (kind, id) = s.split_once(':')?;
    (matches!(kind, "agent" | "person" | "service") && !id.is_empty())
        .then(|| json!({ "kind": kind, "id": id }))
}

/// The `version` of a call's pinned arguments: the digest is of their JSON, compact, with object
/// keys sorted by their UTF-8 bytes, strings escaped as serde_json writes them (`"`, `\\` and
/// control characters only; `\u00xx` for the controls without a short form), and numbers exactly
/// as sent. A call whose `params` or `arguments` repeat a key is refused.
pub const ARGUMENTS_VERSION: &str = "json-sorted-keys";

/// How long the server may take to answer its last calls once the client has hung up.
pub const DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// The open intents, by the JSON-RPC id of their call (as JSON text, so `1` and `"1"` differ).
type Pending = Arc<Mutex<HashMap<String, String>>>;

/// Proxies until either side hangs up (after the client, the server gets [`DRAIN`] to answer what
/// it has), then closes the calls left open as `unknown`.
/// `principal` is who the entries name; through tenbrid, `None` lets the token's principal stand.
pub async fn run<CR, CW, SR, SW>(
    stream: Arc<Stream>,
    principal: Option<Value>,
    client_in: CR,
    client_out: CW,
    server_in: SW,
    server_out: SR,
) -> std::io::Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let pending: Pending = Arc::default();
    let client_out = Arc::new(Mutex::new(client_out));
    let mut up = tokio::spawn(upstream(
        stream.clone(),
        principal,
        pending.clone(),
        client_in,
        server_in,
        client_out.clone(),
    ));
    let mut down = tokio::spawn(downstream(
        stream.clone(),
        pending.clone(),
        server_out,
        client_out,
    ));
    let r = tokio::select! {
        // The client hung up, and the server's stdin closed with it: the server may still answer
        // the calls it has, then exits.
        r = &mut up => match tokio::time::timeout(DRAIN, &mut down).await {
            Ok(d) => r.and(d),
            Err(_) => {
                down.abort();
                r
            }
        },
        // The server hung up: nothing more can run.
        r = &mut down => {
            up.abort();
            r
        }
    };
    for (_, intent) in pending.lock().await.drain() {
        if let Err(e) = stream.outcome(intent.as_bytes(), "unknown", b"{}").await {
            eprintln!("tenbri-proxy: closing an unanswered call: {e}");
        }
    }
    stream.flush().await;
    r.map_err(std::io::Error::other)?
}

/// Client to server: records each `tools/call` before forwarding it.
async fn upstream<CR, SW, CW>(
    stream: Arc<Stream>,
    principal: Option<Value>,
    pending: Pending,
    client_in: CR,
    mut server_in: SW,
    client_out: Arc<Mutex<CW>>,
) -> std::io::Result<()>
where
    CR: AsyncRead + Unpin,
    SW: AsyncWrite + Unpin,
    CW: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(client_in).lines();
    while let Some(line) = lines.next_line().await? {
        let msg: Option<Value> = serde_json::from_str(&line).ok();
        match &msg {
            Some(m) if is_call(m) => {
                let id = m["id"].clone();
                match record(&stream, principal.as_ref(), m, &line).await {
                    Ok(intent) => {
                        pending.lock().await.insert(id.to_string(), intent);
                    }
                    Err(e) => {
                        let mut out = client_out.lock().await;
                        send(&mut *out, &refusal(&id, &e.to_string())).await?;
                        continue;
                    }
                }
            }
            // Batches went away in MCP 2025-06-18; one holding a call is refused whole, since
            // recording part of it would let the rest through unrecorded.
            Some(Value::Array(a)) if a.iter().any(is_call) => {
                let errors: Vec<Value> = a
                    .iter()
                    .filter(|m| m.get("method").is_some() && m.get("id").is_some())
                    .map(|m| refusal(&m["id"], "a batch holding tools/call is not recorded"))
                    .collect();
                let mut out = client_out.lock().await;
                send(&mut *out, &Value::Array(errors)).await?;
                continue;
            }
            _ => {}
        }
        server_in.write_all(line.as_bytes()).await?;
        server_in.write_all(b"\n").await?;
        server_in.flush().await?;
    }
    Ok(())
}

/// Server to client: closes each recorded call with the server's answer, then forwards it.
async fn downstream<SR, CW>(
    stream: Arc<Stream>,
    pending: Pending,
    server_out: SR,
    client_out: Arc<Mutex<CW>>,
) -> std::io::Result<()>
where
    SR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(server_out).lines();
    let mut gone = false;
    while let Some(line) = lines.next_line().await? {
        if let Ok(m) = serde_json::from_str::<Value>(&line) {
            // A response: an id and no method. A request the server makes has a method.
            let intent = match (m.get("id"), m.get("method")) {
                (Some(id), None) => pending.lock().await.remove(&id.to_string()),
                _ => None,
            };
            if let Some(intent) = intent {
                let failed =
                    m.get("error").is_some() || m["result"]["isError"].as_bool().unwrap_or(false);
                let status = if failed { "error" } else { "ok" };
                // The tool ran either way: the answer goes on, and the open intent shows the gap.
                if let Err(e) = stream.outcome(intent.as_bytes(), status, b"{}").await {
                    eprintln!("tenbri-proxy: recording an outcome: {e}");
                }
            }
        }
        // Once the client is gone, answers are still recorded, just not delivered.
        if !gone {
            let mut out = client_out.lock().await;
            let line = format!("{line}\n");
            gone = out.write_all(line.as_bytes()).await.is_err() || out.flush().await.is_err();
        }
    }
    Ok(())
}

fn is_call(m: &Value) -> bool {
    m.get("method").and_then(Value::as_str) == Some("tools/call") && m.get("id").is_some()
}

/// Writes the intent of a `tools/call` (`call`, parsed from `line`); returns it as stored.
async fn record(
    stream: &Stream,
    principal: Option<&Value>,
    call: &Value,
    line: &str,
) -> Result<String, tenbri_bindings::Error> {
    let tool = call["params"]["name"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            tenbri_bindings::Error::new(
                tenbri_bindings::INVALID_REQUEST,
                "tools/call names no tool",
            )
        })?;
    let mut d = json!({ "action": { "type": tool }, "source": "proxy" });
    // The arguments as sent, pinned by a keyed digest (the tenant's data key): a value guessed
    // later can be confirmed with the key, never read off the log.
    let args = pairs(line)
        .and_then(|m| member(&m, "params"))
        .and_then(|p| pairs(p.get()))
        .map(|m| member(&m, "arguments").map(|a| canonical(&a)));
    let args = match args {
        Some(None) => None,
        Some(Some(Some(a))) => Some(a),
        // Which duplicate the server reads is its choice, so no digest pins what it runs.
        _ => {
            return Err(tenbri_bindings::Error::new(
                tenbri_bindings::INVALID_REQUEST,
                "tools/call with a duplicate key in its params or arguments",
            ));
        }
    };
    if let Some(args) = args {
        let digest = stream.digest(None, args.as_bytes()).await?;
        d["inputs"] = json!([{
            "ref": format!("mcp:{tool}/arguments"),
            "version": ARGUMENTS_VERSION,
            "digest": digest,
        }]);
    }
    if let Some(p) = principal {
        d["principal"] = p.clone();
    }
    stream
        .intent(&serde_json::to_vec(&d).expect("JSON serializes"))
        .await
}

/// A JSON object's members in order, duplicates kept.
struct Pairs(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Pairs, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Pairs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Pairs, A::Error> {
                let mut v = Vec::new();
                while let Some(e) = m.next_entry()? {
                    v.push(e);
                }
                Ok(Pairs(v))
            }
        }
        d.deserialize_map(V)
    }
}

/// The members of the object `raw`, sorted by key; None if it is not an object or repeats a key.
fn pairs(raw: &str) -> Option<Vec<(String, Box<RawValue>)>> {
    let mut v = serde_json::from_str::<Pairs>(raw).ok()?.0;
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v.windows(2).all(|w| w[0].0 != w[1].0).then_some(v)
}

fn member(m: &[(String, Box<RawValue>)], key: &str) -> Option<Box<RawValue>> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// `v` as compact JSON, object keys sorted by their UTF-8 bytes, strings re-escaped as serde_json
/// writes them, and numbers exactly as sent: never through f64, so two different numbers never
/// share a digest. None if an object repeats a key. ([`ARGUMENTS_VERSION`])
fn canonical(v: &RawValue) -> Option<String> {
    let raw = v.get().trim();
    match raw.as_bytes().first()? {
        b'{' => {
            let mut out = Vec::new();
            for (k, v) in pairs(raw)? {
                out.push(format!(
                    "{}:{}",
                    serde_json::to_string(&k).ok()?,
                    canonical(&v)?
                ));
            }
            Some(format!("{{{}}}", out.join(",")))
        }
        b'[' => {
            let items: Vec<Box<RawValue>> = serde_json::from_str(raw).ok()?;
            let out: Option<Vec<String>> = items.iter().map(|i| canonical(i)).collect();
            Some(format!("[{}]", out?.join(",")))
        }
        b'"' => serde_json::to_string(&serde_json::from_str::<String>(raw).ok()?).ok(),
        // A number, true, false or null: as sent.
        _ => Some(raw.to_owned()),
    }
}

fn refusal(id: &Value, why: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": NOT_RECORDED, "message": format!("tenbri: not recorded, so not run: {why}") },
    })
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, m: &Value) -> std::io::Result<()> {
    w.write_all(m.to_string().as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_principals() {
        assert_eq!(
            principal("agent:support"),
            Some(json!({"kind": "agent", "id": "support"}))
        );
        assert_eq!(principal("robot:x"), None);
        assert_eq!(principal("agent:"), None);
    }
}
