//! The `tenbri` binary.
//!
//! Exit codes, stable from 0.1.0: 0 success; 1 the stream does not verify, or does not match the
//! `--checkpoint` given (truncated behind it, rewritten, or not signed by the stream); the first
//! broken sequence number is printed; 2 any other error, a malformed checkpoint file among them;
//! 3 `verify` without `--key`: the stream is consistent with its own genesis key, which proves
//! nothing about who wrote it; `schema check` exits 1 when an entry breaks its action's schema.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tenbri_core::{Entry, Head, Principal, PrincipalKind, Role, canon, encoding, sign};
use tenbri_crypt::{DataKeys, epoch_note, erasure_note};
use tenbri_index::{Filter, State};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::Note;
use tenbri_schema::{Schemas, Unknown};
use tenbri_store::{AnyStore, Store};
use tenbri_writer::{
    CHECKPOINT_FILE, Checkpoints, RECONCILE_AFTER_MS, ReadError, Reader, Writer, draft_from_json,
    now_ms, verify,
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

// Parsed once per run: the size of the largest variant (query's filters) does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Create a stream and its stream key; print the fingerprint to pin.
    Init {
        /// The stream: a directory, <root>/<stream>, created or empty; or an object-store prefix,
        /// s3://bucket/<root>/<stream> or r2://bucket/<root>/<stream>, empty.
        path: String,
        /// Keep the secret keys in the OS keychain instead of key files.
        #[cfg(feature = "keychain")]
        #[arg(long)]
        keychain: bool,
    },
    /// Append one entry, read as JSON on stdin; print it as stored.
    Append { path: String },
    /// Check canonical bytes, chain, signatures and keys against a pinned key.
    Verify {
        path: String,
        /// Fingerprint (sha256:…) or public key (ed25519:…) of the stream's genesis key.
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
        /// A checkpoint (C2SP signed note) seen before: the stream must still hold exactly the
        /// entries it covers, so truncation and rewrites behind it are caught.
        #[arg(long, value_name = "FILE")]
        checkpoint: Option<PathBuf>,
    },
    /// Print the entries matching every filter given, in sequence order, one JSON per line, each
    /// with its verification status, seq, entry hash and what the answer is current to.
    ///
    /// Uses the stream's index when there is one (`tenbri index rebuild`), bringing it up to HEAD
    /// first; its answers are "indexed" until `--verify` checks them against the stream. Without
    /// an index, reads and verifies the whole stream.
    Query {
        path: String,
        /// An input the entry used, as ref@version (policy:refund@14), or ref for any version;
        /// repeat to require several.
        #[arg(long, value_name = "REF@VERSION")]
        input: Vec<String>,
        /// The action type (reply_ticket).
        #[arg(long, value_name = "TYPE")]
        action: Option<String>,
        /// The principal, as kind:id (agent:support-assistant).
        #[arg(long, value_name = "KIND:ID")]
        principal: Option<String>,
        /// The action target, exactly.
        #[arg(long)]
        target: Option<String>,
        /// The subject handle.
        #[arg(long)]
        subject: Option<String>,
        /// The rule, as ref@version, or ref for any version.
        #[arg(long, value_name = "REF@VERSION")]
        rule: Option<String>,
        /// Entries at or after this time: 2026-10-20T09:00:00Z, 2026-10-20, or 1h, 30m, 7d ago.
        #[arg(long, value_name = "TIME")]
        since: Option<String>,
        /// Entries before this time.
        #[arg(long, value_name = "TIME")]
        until: Option<String>,
        /// The OpenTelemetry trace id.
        #[arg(long, value_name = "TRACE_ID")]
        trace: Option<String>,
        /// An outcome's status: ok, error, refused or unknown.
        #[arg(long)]
        status: Option<String>,
        /// Only entries after this sequence number (the cursor of the previous page).
        #[arg(long, value_name = "SEQ", default_value_t = 0)]
        after: u64,
        /// At most this many entries; the next page's --after is printed on stderr.
        #[arg(long)]
        limit: Option<usize>,
        /// Check the index's answers against the stream, read and verified in full.
        #[arg(long)]
        verify: bool,
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
    },
    /// The stream's index: a derived view `query` uses, kept in $TENBRI_INDEX_DIR or the user's
    /// cache directory; deleting it loses nothing.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Print the last entries, then follow new ones as they are written.
    Tail {
        path: String,
        /// How many existing entries to print first.
        #[arg(short = 'n', default_value_t = 10)]
        lines: usize,
        /// Print and exit instead of following.
        #[arg(long)]
        no_follow: bool,
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
    },
    /// Action schemas (tenbri.toml).
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
    /// Delete a subject's data keys, so its bodies and input digests can no longer be read or
    /// confirmed, and record the erasure in the stream. The chain, checkpoints and receipts still
    /// verify.
    Erase {
        path: String,
        #[command(flatten)]
        who: Who,
        /// Why: a reference such as the request id (dsr:2026-1042), recorded in the erasure note.
        #[arg(long)]
        reason: String,
        /// Who asked for it, recorded as the note's principal (a person id).
        #[arg(long, value_name = "ID")]
        by: Option<String>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// The stream's signing keys and data keys.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

/// Whose data keys: a subject's, or the tenant's (entries without a subject).
#[derive(Args)]
#[group(required = true, multiple = false)]
struct Who {
    /// The subject handle.
    #[arg(long, value_name = "HANDLE")]
    subject: Option<String>,
    /// The tenant's keys, used by entries without a subject.
    #[arg(long)]
    tenant: bool,
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List the signing keys and the data keys (subjects and key epochs); never a secret.
    List { path: String },
    /// Print a subject's data keys as JSON, for a backup kept apart from the log.
    Export {
        path: String,
        #[command(flatten)]
        who: Who,
        /// Only the digest keys: enough to confirm input digests, never to open a body.
        #[arg(long)]
        digest: bool,
    },
    /// Start a new data key epoch for a subject and record it in the stream; older epochs keep
    /// opening older data until erased.
    Rotate {
        path: String,
        #[command(flatten)]
        who: Who,
        /// Who rotated, recorded as the note's principal (a person id).
        #[arg(long, value_name = "ID")]
        by: Option<String>,
    },
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Validate tenbri.toml, then every entry of the given streams against it. Exit 1 if an
    /// entry breaks its action's schema.
    Check {
        /// Streams to check: directories, <root>/<stream>, or s3:// / r2:// URLs.
        paths: Vec<String>,
        /// The schema file.
        #[arg(long, default_value = "tenbri.toml", value_name = "FILE")]
        schema: PathBuf,
    },
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Delete the stream's index and build it again from every batch.
    Rebuild {
        path: String,
        /// The backend: sqlite (one file) or parquet (files any Arrow tool reads).
        #[arg(long, default_value = "sqlite")]
        backend: tenbri_index::Kind,
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
            let store = store(path).await?;
            let r = verify(&store, pin.as_deref()).await?;
            let stream = r.stream.as_deref().unwrap_or("?");
            if let Some(b) = &r.broken {
                println!("broken at seq {}: {}", b.seq, b.error);
                println!("{} entries verified before it, stream {stream}", r.entries);
                return Ok(1);
            }
            if let Some(note) = &note {
                // ponytail: reads the stream a second time for its entry hashes; one pass once
                // tenbri-writer's verify takes a checkpoint.
                let mut reader = Reader::new(&store, pin.as_deref());
                read(&mut reader).await?;
                let hashes = reader.hashes();
                let cp = &note.checkpoint;
                match note.check(reader.chain(), hashes) {
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
            if let Some(size) = r.checkpoint {
                println!("matches its latest checkpoint, at size {size}");
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
            principal,
            target,
            subject,
            rule,
            since,
            until,
            trace,
            status,
            after,
            limit,
            verify,
            key,
        } => {
            let pin = key.as_deref().map(pin).transpose()?;
            let now = now_ms();
            let time = |t: &Option<String>, flag: &str| {
                t.as_deref()
                    .map(|t| {
                        tenbri_index::parse_time(t, now).ok_or_else(|| {
                            Fail(2, format!("--{flag} {t}: expected a time (2026-10-20T09:00:00Z, 2026-10-20) or a duration (1h)"))
                        })
                    })
                    .transpose()
            };
            let filter = Filter {
                inputs: input.iter().map(|i| tenbri_index::ref_version(i)).collect(),
                action: action.clone(),
                principal: principal.clone(),
                target: target.clone(),
                subject: subject.clone(),
                rule: rule.as_deref().map(tenbri_index::ref_version),
                since: time(since, "since")?,
                until: time(until, "until")?,
                trace_id: trace.clone(),
                status: status.clone(),
                after: *after,
            };
            let limit = limit.unwrap_or(usize::MAX);
            let store = store(path).await?;
            query(&store, &filter, limit, *verify, pin.as_deref()).await
        }
        Command::Index {
            command: IndexCommand::Rebuild { path, backend },
        } => {
            let store = store(path).await?;
            let dir = index_dir(&store).await?;
            tenbri_index::remove(&dir)?;
            let mut ix = tenbri_index::open(*backend, &dir)?;
            let st = tenbri_index::rebuild(ix.as_mut(), &store).await?;
            println!(
                "indexed {} entries of {} ({backend}) at {}",
                st.seq,
                st.stream,
                dir.display()
            );
            if let Some(c) = st.checkpoint {
                println!("latest checkpoint: size {c}");
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
            let store = store(path).await?;
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
        Command::Schema {
            command: SchemaCommand::Check { paths, schema },
        } => schema_check(schema, paths).await,
        Command::Erase {
            path,
            who,
            reason,
            by,
            yes,
        } => erase(path, &keys_dir()?, who.subject.as_deref(), reason, by, *yes).await,
        Command::Keys { command } => match command {
            KeysCommand::List { path } => keys_list(path, &keys_dir()?).await,
            KeysCommand::Export { path, who, digest } => {
                let (_, ks) = open_stream(path, &keys_dir()?).await?;
                let json = DataKeys::open(&ks)?.export(who.subject.as_deref(), *digest)?;
                println!("{}", *json);
                Ok(0)
            }
            KeysCommand::Rotate { path, who, by } => {
                let (store, ks) = open_stream(path, &keys_dir()?).await?;
                let data = DataKeys::open(&ks)?;
                let mut w = open_writer(store, ks).await?;
                let subject = who.subject.as_deref();
                let n = data.rotate(subject)?;
                let e = w.append(epoch_note(subject, n, person(by))).await?;
                println!(
                    "{}: new data key epoch {n}, recorded at seq {}",
                    whose(subject),
                    e.seq
                );
                Ok(0)
            }
        },
    }
}

fn whose(subject: Option<&str>) -> String {
    subject.map_or("tenant".into(), |s| format!("subject {s}"))
}

fn person(by: &Option<String>) -> Option<Principal> {
    by.as_ref().map(|id| Principal {
        kind: PrincipalKind::Person,
        id: id.clone(),
    })
}

async fn erase(
    path: &str,
    keys: &Path,
    subject: Option<&str>,
    reason: &str,
    by: &Option<String>,
    yes: bool,
) -> Result<u8, Fail> {
    let (store, ks) = open_stream(path, keys).await?;
    let data = DataKeys::open(&ks)?;
    // Open the writer first: a stream that does not verify, or no key to sign with, stops here,
    // before anything is deleted.
    let mut w = open_writer(store, ks).await?;
    if !yes {
        let answer = subject.unwrap_or("tenant");
        eprint!(
            "This deletes the data keys of {} in {}: its bodies and input digests can never be read \
             or confirmed again. Type {answer} to confirm: ",
            whose(subject),
            data.dir().display()
        );
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim_end_matches(['\r', '\n']) != answer {
            return Err(Fail(2, "not confirmed; nothing was erased".into()));
        }
    }
    let n = data.erase(subject)?;
    let e = w
        .append(erasure_note(subject, reason, person(by)))
        .await
        .map_err(|e| {
            Fail(
                2,
                format!(
                    "deleted {n} data key epochs of {}, but the erasure note was not written: {e}; \
                     run tenbri erase again to record it",
                    whose(subject)
                ),
            )
        })?;
    println!(
        "erased {}: {n} data key epochs deleted; erasure recorded at seq {}",
        whose(subject),
        e.seq
    );
    Ok(0)
}

async fn keys_list(path: &str, keys: &Path) -> Result<u8, Fail> {
    let (_, ks) = open_stream(path, keys).await?;
    println!("signing keys of {} ({}):", ks.stream(), ks.dir().display());
    for m in ks.list()? {
        let role = match m.role {
            Role::Stream => "stream",
            Role::Session => "session",
        };
        let until = m
            .not_after
            .map(|t| format!(" until {t}"))
            .unwrap_or_default();
        println!("  {} {role} {}{until}", m.id, m.public);
    }
    let data = DataKeys::open(&ks)?;
    println!("data keys ({}):", data.dir().display());
    for h in data.list()? {
        let (first, last) = (&h.epochs[0], &h.epochs[h.epochs.len() - 1]);
        println!(
            "  {}: epochs {}..{}, newest made {}",
            whose(h.subject.as_deref()),
            first.epoch,
            last.epoch,
            last.created
        );
    }
    Ok(0)
}

/// Where the index of the stream in `store` lives.
async fn index_dir<S: Store>(store: &S) -> Result<PathBuf, Fail> {
    let head = store
        .get("HEAD")
        .await?
        .ok_or_else(|| Fail(2, "no stream here (no HEAD)".into()))?;
    let (head, _) = Head::parse(&head.bytes)?;
    let root = tenbri_index::default_root()
        .ok_or_else(|| Fail(2, "no index directory: set TENBRI_INDEX_DIR".into()))?;
    Ok(tenbri_index::dir_for(&root, &head.stream))
}

/// `tenbri query`: through the index if the stream has one, else a verified scan.
async fn query<S: Store>(
    store: &S,
    filter: &Filter,
    limit: usize,
    check: bool,
    pin: Option<&str>,
) -> Result<u8, Fail> {
    let verified = if pin.is_some() {
        "verified"
    } else {
        "unpinned"
    };
    let ix = tenbri_index::find(&index_dir(store).await?)?;
    let (hits, next, state, status) = match ix {
        Some(mut ix) => {
            tenbri_index::update(ix.as_mut(), store).await?;
            let page = tenbri_index::search(ix.as_ref(), filter, limit)?;
            let state = page.state.expect("an index brought up to HEAD has a state");
            let mut status = "indexed";
            if check {
                // ponytail: re-reads the whole stream; check each hit's inclusion proof against
                // a checkpoint once receipts land.
                let mut r = Reader::new(store, pin);
                read(&mut r).await?;
                if let Some(b) = r.chain().invalidated() {
                    return Err(Fail(1, format!("the stream does not verify: {b}")));
                }
                for h in &page.hits {
                    let want = r.hashes().get(h.seq as usize - 1).map(|x| encoding::hex(x));
                    if want.as_deref() != h.hash.strip_prefix("sha256:") {
                        return Err(Fail(
                            1,
                            format!(
                                "the index disagrees with the stream at seq {}: run `tenbri index rebuild`",
                                h.seq
                            ),
                        ));
                    }
                }
                status = verified;
            }
            (page.hits, page.next, state, status)
        }
        None => {
            let mut r = Reader::new(store, pin);
            let entries = read(&mut r).await?;
            if let Some(b) = r.chain().invalidated() {
                return Err(Fail(1, format!("the stream does not verify: {b}")));
            }
            let mut hits = vec![];
            let mut next = None;
            for (e, h) in entries.iter().zip(r.hashes()) {
                let l = line(e);
                if !filter.matches_entry(e, &l) {
                    continue;
                }
                if hits.len() == limit {
                    next = hits.last().map(|h: &tenbri_index::Hit| h.seq);
                    break;
                }
                hits.push(tenbri_index::Hit {
                    seq: e.seq,
                    hash: format!("sha256:{}", encoding::hex(h)),
                    line: l,
                });
            }
            let head = r.head().expect("a stream read to its HEAD");
            let state = State {
                stream: head.stream.clone(),
                seq: head.seq,
                hash: head.hash.clone(),
                checkpoint: None,
            };
            (hits, next, state, verified)
        }
    };
    let as_of = serde_json::to_string(&state)?;
    let mut out = io::stdout().lock();
    for h in hits {
        writeln!(
            out,
            "{{\"verification\":\"{status}\",\"entry\":{},\"seq\":{},\"hash\":\"{}\",\"as_of\":{as_of}}}",
            h.line, h.seq, h.hash
        )?;
    }
    out.flush()?;
    if let Some(n) = next {
        eprintln!("tenbri: more entries match; next page: --after {n}");
    }
    Ok(0)
}

async fn schema_check(file: &Path, paths: &[String]) -> Result<u8, Fail> {
    let schemas = Schemas::load(file).map_err(|e| Fail(2, e))?;
    println!(
        "{}: {} action schemas, unknown actions {}",
        file.display(),
        schemas.actions.len(),
        match schemas.unknown_actions {
            Unknown::Reject => "rejected",
            Unknown::Warn => "warned about",
        }
    );
    let mut code = 0;
    for path in paths {
        let store = store(path).await?;
        let mut r = Reader::new(&store, None);
        let (mut checked, mut bad) = (0, 0);
        for e in read(&mut r).await? {
            let c = schemas.check(&e);
            for w in &c.warnings {
                println!("{} seq {}: warning: {w}", path, e.seq);
            }
            for v in &c.violations {
                println!("{} seq {}: {v}", path, e.seq);
            }
            checked += 1;
            bad += usize::from(!c.violations.is_empty());
        }
        println!("{}: {checked} entries, {bad} break their schema", path);
        if bad > 0 {
            code = 1;
        }
    }
    Ok(code)
}

/// The store at `location`: a local directory, or an object store (credentials from `AWS_*`;
/// `CLOUDFLARE_ACCOUNT_ID` for R2).
async fn store(location: &str) -> Result<AnyStore, Fail> {
    tenbri_store::open(location)
        .await
        .map_err(|e| Fail(2, e.to_string()))
}

/// The key directory of `stream`, kept apart from it when it is a local directory.
fn key_store(keys: &Path, location: &str, stream: &str) -> io::Result<KeyStore> {
    if tenbri_store::is_url(location) {
        KeyStore::open_for_object_store(keys, stream)
    } else {
        KeyStore::open(keys, Path::new(location), stream)
    }
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

async fn init(path: &str, keys: &Path, backend: Backend) -> Result<u8, Fail> {
    if !tenbri_store::is_url(path) {
        let dir = Path::new(path);
        if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
            return Err(Fail(2, format!("{path} is not empty")));
        }
        std::fs::create_dir_all(dir)?;
    }
    let store = store(path).await?;
    if store.get("HEAD").await?.is_some() {
        return Err(Fail(2, format!("{path} already holds a stream")));
    }
    let stream_key = Key::new_stream()?;
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS)?;
    let id = sign::stream_id(&stream_key.signing.verifying_key());
    let ks = key_store(keys, path, &id)?;
    ks.save(&stream_key, backend)?;
    ks.save(&session, backend)?;
    Writer::create(store, &stream_key, session).await?;
    println!("created stream {id} at {path}");
    println!(
        "stream key fingerprint (pin it): {}",
        stream_key.fingerprint()
    );
    println!("keys: {}", ks.dir().display());
    println!(
        "verify with: tenbri verify {} --key {}",
        path,
        stream_key.fingerprint()
    );
    Ok(0)
}

/// The store at `path` and its key store, found from its HEAD.
async fn open_stream(path: &str, keys: &Path) -> Result<(AnyStore, KeyStore), Fail> {
    let store = store(path).await?;
    let head = store
        .get("HEAD")
        .await?
        .ok_or_else(|| Fail(2, format!("no stream at {path}")))?;
    let (head, _) = Head::parse(&head.bytes)?;
    let ks = key_store(keys, path, &head.stream)?;
    Ok((store, ks))
}

/// A writer for the stream, pinned to its genesis key as this machine holds it, with the latest
/// checkpoint kept with the keys as the HEAD floor, and a session key it may sign with.
async fn open_writer(store: AnyStore, ks: KeyStore) -> Result<Writer<AnyStore, Checkpoints>, Fail> {
    let genesis = ks
        .list()?
        .iter()
        .filter(|m| m.role == Role::Stream)
        .filter_map(|m| sign::decode_key(&m.public).ok())
        .find(|k| sign::stream_id(k) == ks.stream())
        .ok_or_else(|| {
            Fail(
                2,
                format!(
                    "no stream key for {} in {}",
                    ks.stream(),
                    ks.dir().display()
                ),
            )
        })?;
    let mut w = Writer::open(store, Some(&sign::fingerprint(&genesis)))
        .await?
        .with_checkpoints(Some(ks.dir().join(CHECKPOINT_FILE)))
        .await?;
    // A stored session the stream certified, valid for at least another minute; else a new one
    // certified with the current stream key.
    w.use_keys(ks).await?;
    Ok(w)
}

async fn append(path: &str, keys: &Path) -> Result<u8, Fail> {
    let mut input = vec![];
    io::stdin().read_to_end(&mut input)?;
    let draft = draft_from_json(&input).map_err(|e| Fail(2, format!("stdin: {e}")))?;
    let (store, ks) = open_stream(path, keys).await?;
    let mut w = open_writer(store, ks).await?;
    let now = now_ms();
    w.reconcile_stale(now, RECONCILE_AFTER_MS, draft.intent.as_deref())
        .await?;
    let e = w.append(draft).await?;
    println!("{}", line(&e));
    Ok(0)
}
