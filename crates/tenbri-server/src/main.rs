//! `tenbrid`: the Tenbri REST and gRPC API.
//!
//! `tenbrid [--config FILE]` serves until SIGINT or SIGTERM, then stops accepting requests and
//! waits for the writes in flight. `tenbrid token` prints a new bearer token and the line that
//! configures it. Exit codes: 0 after a clean shutdown, 2 on a configuration or startup error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tenbri_server::{Config, Daemon, serve};

#[derive(Parser)]
#[command(name = "tenbrid", version, about = "The Tenbri REST and gRPC API.")]
struct Cli {
    /// The configuration file [default: $TENBRI_CONFIG, else tenbrid.toml].
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print a new bearer token, and the `[[tokens]]` entry that configures it (by its hash).
    Token,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tenbrid: {e}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if let Some(Command::Token) = cli.command {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| e.to_string())?;
        let token = format!("tnbt_{}", tenbri_core::encoding::hex(&secret));
        println!("token (give it to the client; it is not stored): {token}");
        println!();
        println!("[[tokens]]");
        println!(
            "sha256 = \"{}\"",
            tenbri_core::sign::sha256(token.as_bytes())
        );
        println!("principal = {{ kind = \"agent\", id = \"...\" }}");
        return Ok(());
    }
    let path = cli
        .config
        .or_else(|| std::env::var_os("TENBRI_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("tenbrid.toml"));
    let config = Config::load(&path)?;
    let daemon = Arc::new(Daemon::open(&config).await?);
    let bind = |a| async move {
        tokio::net::TcpListener::bind(a)
            .await
            .map_err(|e| format!("listen on {a}: {e}"))
    };
    let (rest, grpc) = (bind(config.listen).await?, bind(config.grpc_listen).await?);
    eprintln!(
        "tenbrid {}: REST on http://{}, gRPC on {}, {} streams",
        tenbri_server::VERSION,
        config.listen,
        config.grpc_listen,
        config.streams.len()
    );
    let anchoring = daemon.clone();
    let anchor = config.clone();
    tokio::spawn(async move { anchoring.anchor_every(&anchor).await });
    serve(daemon, rest, grpc, signal())
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("tenbrid: stopped; every acknowledged entry is durable");
    Ok(())
}

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
