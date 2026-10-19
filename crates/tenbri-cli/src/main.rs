//! The `tenbri` binary.
//!
//! Exit codes, stable from 0.1.0: 0 success; 1 the stream does not verify, or does not match the
//! `--checkpoint` given (truncated behind it, rewritten, or not signed by the stream); the first
//! broken sequence number is printed; 2 any other error, a malformed checkpoint file among them;
//! 3 `verify` without `--key`: the stream is consistent with its own genesis key, which proves
//! nothing about who wrote it.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tenbri_core::{Entry, Head, Role, canon, sign};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::{Hash, Note};
use tenbri_store::{LocalStore, Store};
use tenbri_writer::{
    RECONCILE_AFTER_MS, ReadError, Reader, Writer, draft_from_json, now_ms, verify,
};

#[derive(Parser)]
#[command(
    name = "tenbri",
    version,
    about = "Audit trail for AI agents: every decision signed, chained and provable."
)]
struct Cli {
    /// Keys directory [default: $TENBRI_KEYS, else ~/.config/tenbri/keys]. Never inside a stream.
    #[arg(long, global = true, value_name = "DIR")]
    keys: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a stream and its stream key; print the fingerprint to pin.
    Init {
        /// The stream's directory, <root>/<stream>; created, or empty.
        path: PathBuf,
        /// Keep the secret keys in the OS keychain instead of key files.
        #[cfg(feature = "keychain")]
        #[arg(long)]
        keychain: bool,
    },
    /// Append one entry, read as JSON on stdin; print it as stored.
    Append { path: PathBuf },
    /// Check canonical bytes, chain, signatures and keys against a pinned key.
    Verify {
        path: PathBuf,
        /// Fingerprint (sha256:…) or public key (ed25519:…) of the stream's genesis key.
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
        /// A checkpoint (C2SP signed note) seen before: the stream must still hold exactly the
        /// entries it covers, so truncation and rewrites behind it are caught.
        #[arg(long, value_name = "FILE")]
        checkpoint: Option<PathBuf>,
    },
    /// Print entries by input or action, each with its verification status, one JSON per line.
    Query {
        path: PathBuf,
        /// An input the entry used, as ref@version (policy:refund@14); repeat to require several.
        #[arg(long, value_name = "REF@VERSION")]
        input: Vec<String>,
        /// The action type (reply_ticket).
        #[arg(long, value_name = "TYPE")]
        action: Option<String>,
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
    },
    /// Print the last entries, then follow new ones as they are written.
    Tail {
        path: PathBuf,
        /// How many existing entries to print first.
        #[arg(short = 'n', default_value_t = 10)]
        lines: usize,
        /// Print and exit instead of following.
        #[arg(long)]
        no_follow: bool,
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
    },
}

/// A failure with its exit code.
struct Fail(u8, String);

impl<E: std::fmt::Display> From<E> for Fail {
    fn from(e: E) -> Self {
        Fail(2, e.to_string())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(Fail(code, msg)) => {
            eprintln!("tenbri: {msg}");
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> Result<u8, Fail> {
    let keys_dir = || {
        cli.keys
            .clone()
            .or_else(tenbri_keys::default_dir)
            .ok_or_else(|| {
                Fail(
                    2,
                    "no keys directory: pass --keys or set TENBRI_KEYS".into(),
                )
            })
    };
    match &cli.command {
        #[cfg(feature = "keychain")]
        Command::Init { path, keychain } => {
            init(
                path,
                &keys_dir()?,
                if *keychain {
                    Backend::Keychain
                } else {
                    Backend::File
                },
            )
            .await
        }
        #[cfg(not(feature = "keychain"))]
        Command::Init { path } => init(path, &keys_dir()?, Backend::File).await,
        Command::Append { path } => append(path, &keys_dir()?).await,
        Command::Verify {
            path,
            key,
            checkpoint,
        } => {
            let pin = key.as_deref().map(pin).transpose()?;
            let note = checkpoint
                .as_deref()
                .map(|f| {
                    std::fs::read(f)
                        .map_err(Fail::from)
                        .and_then(|b| Note::parse(&b).map_err(Fail::from))
                        .map_err(|Fail(_, e)| Fail(2, format!("{}: {e}", f.display())))
                })
                .transpose()?;
            let store = store(path)?;
            let r = verify(&store, pin.as_deref()).await?;
            let stream = r.stream.as_deref().unwrap_or("?");
            if let Some(b) = &r.broken {
                println!("broken at seq {}: {}", b.seq, b.error);
                println!("{} entries verified before it, stream {stream}", r.entries);
                return Ok(1);
            }
            if let Some(note) = &note {
                // ponytail: reads the stream a second time for its entry hashes; one pass once
                // tenbri-writer's verify returns them.
                let mut reader = Reader::new(&store, pin.as_deref());
                let hashes: Vec<Hash> = read(&mut reader)
                    .await?
                    .iter()
                    .map(|e| {
                        let h = sign::entry_hash(line(e).as_bytes());
                        tenbri_core::encoding::prefixed::<32>(&h, "sha256:").expect("a hash")
                    })
                    .collect();
                let cp = &note.checkpoint;
                match note.check(reader.chain(), &hashes) {
                    Ok(_) => println!("matches checkpoint {} at size {}", cp.origin, cp.size),
                    Err(b) => {
                        println!("broken at seq {}: {}", b.seq, b.error);
                        println!(
                            "against checkpoint {} at size {}; the stream has {} entries",
                            cp.origin,
                            cp.size,
                            hashes.len()
                        );
                        return Ok(1);
                    }
                }
            }
            if let Some(pin) = pin {
                println!(
                    "verified {} entries, stream {stream}, pinned to {pin}",
                    r.entries
                );
                return Ok(0);
            }
            println!("consistent: {} entries, stream {stream}", r.entries);
            println!(
                "NOT pinned: this only shows the stream agrees with its own genesis key; pass --key <fingerprint>"
            );
            Ok(3)
        }
        Command::Query {
            path,
            input,
            action,
            key,
        } => {
            let pin = key.as_deref().map(pin).transpose()?;
            let inputs: Vec<(&str, &str)> = input
                .iter()
                .map(|i| {
                    i.rsplit_once('@')
                        .ok_or_else(|| Fail(2, format!("--input {i}: expected ref@version")))
                })
                .collect::<Result<_, _>>()?;
            let store = store(path)?;
            let mut r = Reader::new(&store, pin.as_deref());
            let entries = read(&mut r).await?;
            if let Some(b) = r.chain().invalidated() {
                return Err(Fail(1, format!("the stream does not verify: {b}")));
            }
            let status = if pin.is_some() {
                "verified"
            } else {
                "unpinned"
            };
            let mut out = io::stdout().lock();
            for e in entries
                .iter()
                .filter(|e| matches(e, &inputs, action.as_deref()))
            {
                writeln!(
                    out,
                    "{{\"verification\":\"{status}\",\"entry\":{}}}",
                    line(e)
                )?;
            }
            Ok(0)
        }
        Command::Tail {
            path,
            lines,
            no_follow,
            key,
        } => {
            let pin = key.as_deref().map(pin).transpose()?;
            let store = store(path)?;
            let mut r = Reader::new(&store, pin.as_deref());
            let first = read(&mut r).await?;
            print_lines(&first[first.len().saturating_sub(*lines)..])?;
            if *no_follow {
                return Ok(0);
            }
            // ponytail: polls HEAD every 500 ms; a file watcher when latency matters.
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                print_lines(&read(&mut r).await?)?;
            }
        }
    }
}

fn store(path: &Path) -> Result<LocalStore, Fail> {
    LocalStore::open(path).map_err(|e| Fail(2, format!("{}: {e}", path.display())))
}

/// A `--key` value as a fingerprint: `sha256:…` as given, or the fingerprint of `ed25519:…`.
fn pin(s: &str) -> Result<String, Fail> {
    if tenbri_core::encoding::prefixed::<32>(s, "sha256:").is_some() {
        return Ok(s.to_owned());
    }
    sign::decode_key(s)
        .map(|k| sign::fingerprint(&k))
        .map_err(|_| {
            Fail(
                2,
                format!("--key {s}: expected sha256:<64 hex> or ed25519:<64 hex>"),
            )
        })
}

async fn read<S: Store>(r: &mut Reader<'_, S>) -> Result<Vec<Entry>, Fail> {
    r.poll().await.map_err(|e| match e {
        ReadError::Broken(b) => Fail(1, format!("the stream does not verify: {b}")),
        e => Fail(2, e.to_string()),
    })
}

fn line(e: &Entry) -> String {
    String::from_utf8(canon::to_vec(
        &canon::from_serialize(e).expect("a stored entry"),
    ))
    .expect("UTF-8")
}

fn print_lines(entries: &[Entry]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for e in entries {
        writeln!(out, "{}", line(e))?;
    }
    out.flush()
}

fn matches(e: &Entry, inputs: &[(&str, &str)], action: Option<&str>) -> bool {
    let has = |(r, v): &(&str, &str)| {
        e.inputs
            .iter()
            .flatten()
            .any(|i| i.r#ref == *r && i.version == *v)
    };
    inputs.iter().all(has)
        && action.is_none_or(|a| e.action.as_ref().is_some_and(|x| x.r#type == a))
}

async fn init(path: &Path, keys: &Path, backend: Backend) -> Result<u8, Fail> {
    if path.exists() && std::fs::read_dir(path)?.next().is_some() {
        return Err(Fail(2, format!("{} is not empty", path.display())));
    }
    std::fs::create_dir_all(path)?;
    let stream_key = Key::new_stream()?;
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS)?;
    let id = sign::stream_id(&stream_key.signing.verifying_key());
    let ks = KeyStore::open(keys, path, &id)?;
    ks.save(&stream_key, backend)?;
    ks.save(&session, backend)?;
    Writer::create(store(path)?, &stream_key, session).await?;
    println!("created stream {id} at {}", path.display());
    println!(
        "stream key fingerprint (pin it): {}",
        stream_key.fingerprint()
    );
    println!("keys: {}", ks.dir().display());
    println!(
        "verify with: tenbri verify {} --key {}",
        path.display(),
        stream_key.fingerprint()
    );
    Ok(0)
}

async fn append(path: &Path, keys: &Path) -> Result<u8, Fail> {
    let mut input = vec![];
    io::stdin().read_to_end(&mut input)?;
    let draft = draft_from_json(&input).map_err(|e| Fail(2, format!("stdin: {e}")))?;
    let store = store(path)?;
    let head = store
        .get("HEAD")
        .await?
        .ok_or_else(|| Fail(2, format!("no stream at {}", path.display())))?;
    let (head, _) = Head::parse(&head.bytes)?;
    let ks = KeyStore::open(keys, path, &head.stream)?;
    // The writer pins the stream to its genesis key as this machine holds it.
    let metas = ks.list()?;
    let genesis = metas
        .iter()
        .filter(|m| m.role == Role::Stream)
        .filter_map(|m| sign::decode_key(&m.public).ok())
        .find(|k| sign::stream_id(k) == head.stream)
        .ok_or_else(|| {
            Fail(
                2,
                format!(
                    "no stream key for {} in {}",
                    head.stream,
                    ks.dir().display()
                ),
            )
        })?;
    let mut w = Writer::open(store, Some(&sign::fingerprint(&genesis))).await?;

    // Sign with a stored session the stream certified, valid for at least another minute; else
    // certify a new one with the current stream key.
    let now = now_ms();
    let mut sessions: Vec<_> = metas.iter().filter(|m| m.role == Role::Session).collect();
    sessions.sort_by(|a, b| b.not_after.cmp(&a.not_after));
    let usable = sessions.iter().find_map(|m| {
        let k = ks.load(&m.id).ok()?;
        (k.valid_at(now + 60_000) && w.use_session(k).is_ok()).then_some(())
    });
    if usable.is_none() {
        let current = w
            .chain()
            .stream_key()
            .ok_or_else(|| Fail(2, "the stream has no stream key".into()))?
            .to_owned();
        let stream_key = ks.load(&current).map_err(|e| {
            Fail(
                2,
                format!("no usable session key, and the stream key {current} is not here: {e}"),
            )
        })?;
        let session = Key::new_session(now, SESSION_LIFETIME_MS)?;
        ks.save(
            &session,
            ks.list()?
                .iter()
                .find(|m| m.id == current)
                .map_or(Backend::File, |m| m.backend),
        )?;
        w.certify_session(&stream_key, session).await?;
    }
    w.reconcile_stale(now, RECONCILE_AFTER_MS, draft.intent.as_deref())
        .await?;
    let e = w.append(draft).await?;
    println!("{}", line(&e));
    Ok(0)
}
