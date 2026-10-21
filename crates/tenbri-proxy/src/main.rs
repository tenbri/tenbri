//! tenbri-proxy: runs an MCP server on stdio and records every tool call it is asked to make.
//!
//! ```text
//! tenbri-proxy [--stream LOCATION] [--agent KIND:ID] -- COMMAND [ARGS...]
//! ```
//!
//! `--stream` defaults to `$TENBRI_STREAM` and `--agent` to `$TENBRI_AGENT`. Point the stream at a
//! tenbrid (`https://host/<stream>`, token in `$TENBRI_TOKEN`) so neither the agent nor the proxy
//! holds a signing key. That tenbrid must serve the digest route (`POST /v1/streams/{stream}/digest`)
//! and its token have `digest = true`: the proxy pins every call's arguments by keyed digest, so
//! against an older tenbrid, or without the flag, it refuses every call that has arguments.

use std::process::{ExitCode, Stdio};
use std::sync::Arc;

use tenbri_bindings::{Options, Stream};

const USAGE: &str =
    "usage: tenbri-proxy [--stream LOCATION] [--agent KIND:ID] -- COMMAND [ARGS...]";

#[tokio::main]
async fn main() -> ExitCode {
    match proxy().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tenbri-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn proxy() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut location = std::env::var("TENBRI_STREAM").ok();
    let mut agent = std::env::var("TENBRI_AGENT").ok();
    let mut command = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--stream" => location = args.next(),
            "--agent" => agent = args.next(),
            "--version" => {
                println!("tenbri-proxy {}", tenbri_proxy::VERSION);
                return Ok(());
            }
            "--" => {
                command.extend(args.by_ref());
            }
            _ => return Err(format!("unexpected {a}\n{USAGE}")),
        }
    }
    let location = location.ok_or(format!("no stream: --stream or TENBRI_STREAM\n{USAGE}"))?;
    let (program, rest) = command.split_first().ok_or(USAGE.to_owned())?;
    let principal = agent
        .filter(|a| !a.is_empty())
        .map(|a| tenbri_proxy::principal(&a).ok_or(format!("--agent {a}: expected kind:id")))
        .transpose()?;
    let stream = Stream::open(&location, Options::default())
        .await
        .map_err(|e| format!("{location}: {e}"))?;
    if !stream.writable() {
        return Err(format!(
            "{location}: read-only here, so nothing could be recorded"
        ));
    }
    let mut child = tokio::process::Command::new(program)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let server_in = child.stdin.take().expect("piped");
    let server_out = child.stdout.take().expect("piped");
    tenbri_proxy::run(
        Arc::new(stream),
        principal,
        tokio::io::stdin(),
        tokio::io::stdout(),
        server_in,
        server_out,
    )
    .await
    .map_err(|e| e.to_string())
}
