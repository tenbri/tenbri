//! The `tenbri` binary.
//!
//! Exit codes, stable from 0.1.0: 0 success; 1 the stream does not verify, or does not match the
//! `--checkpoint` given (truncated behind it, rewritten, or not signed by the stream); the first
//! broken sequence number is printed; 2 any other error, a malformed checkpoint file among them;
//! 3 `verify` without `--key` or a pin recorded when the stream was created here (`init`, or an
//! SDK's `init()`): the stream is consistent with its own
//! genesis key, which proves nothing about who wrote it; `schema check` exits 1 when an entry
//! breaks its action's schema; `receipt verify` exits 1 when the receipt does not verify, with the
//! reason.

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tenbri_core::{Entry, Head, Principal, PrincipalKind, Role, canon, encoding, sign};
use tenbri_crypt::{DataKeys, epoch_note, erasure_note};
use tenbri_index::{Filter, State};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::{Note, checkpoint};
use tenbri_schema::{Schemas, Unknown};
use tenbri_store::{AnyStore, Store};
use tenbri_writer::{
    CHECKPOINT_FILE, Checkpoints, RECONCILE_AFTER_MS, ReadError, Reader, ReceiptError, Writer,
    draft_from_json, now_ms, verify,
};

#[derive(Parser)]
#[command(
    name = "tenbri",
    version,
    about = "The open-source Agent Decision Record: every decision signed, chained and provable."
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
        #[arg(env = "TENBRI_STREAM")]
        path: String,
        /// Keep the secret keys in the OS keychain instead of key files.
        #[cfg(feature = "keychain")]
        #[arg(long)]
        keychain: bool,
    },
    /// Append one entry, read as JSON on stdin; print it as stored.
    #[command(after_help = format!("{APPEND_EXAMPLE}\n\n{ALLOWED}"))]
    Append {
        #[arg(env = "TENBRI_STREAM")]
        path: String,
    },
    /// Check canonical bytes, chain, signatures and keys against a pinned key.
    Verify {
        #[arg(env = "TENBRI_STREAM")]
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
    /// first and checking each answer against the batch in storage that holds it, so an edited
    /// batch fails the query (exit 1). Its answers are "indexed", not signature-checked, until
    /// `--verify` checks them against the whole stream. Without an index, reads and verifies the
    /// whole stream.
    Query {
        #[arg(env = "TENBRI_STREAM")]
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
        #[command(flatten)]
        format: Format,
    },
    /// Print one entry, by sequence number or id, with the intent, approval, outcome or reconcile
    /// it is linked to, and whether the stream verifies.
    Show {
        /// [STREAM] SEQ|ID: the stream may come from TENBRI_STREAM instead.
        #[arg(required = true, num_args = 1..=2, value_name = "STREAM] [SEQ|ID")]
        args: Vec<String>,
        /// Fingerprint of the stream's genesis key [default: the pin `tenbri init` or an SDK's init() recorded].
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
        /// One JSON object per entry of the chain, as when stdout is not a terminal.
        #[arg(long, conflicts_with = "pretty")]
        json: bool,
        /// Fields and chain, as when stdout is a terminal.
        #[arg(long)]
        pretty: bool,
    },
    /// The stream's index: a derived view `query` uses, kept in $TENBRI_INDEX_DIR or the user's
    /// cache directory; deleting it loses nothing.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Print the last entries, then follow new ones as they are written.
    Tail {
        #[arg(env = "TENBRI_STREAM")]
        path: String,
        /// How many existing entries to print first.
        #[arg(short = 'n', default_value_t = 10)]
        lines: usize,
        /// Print and exit instead of following.
        #[arg(long)]
        no_follow: bool,
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
        #[command(flatten)]
        format: Format,
    },
    /// Seal and sign a checkpoint of the whole stream now; with --tsa, timestamp it (RFC 3161).
    Checkpoint {
        #[arg(env = "TENBRI_STREAM")]
        path: String,
        /// The URL of an RFC 3161 timestamp authority: its token is stored next to the
        /// checkpoint (anchors/<size>.tsr) and goes into receipts.
        #[arg(long, value_name = "URL")]
        tsa: Option<String>,
    },
    /// Receipts: a self-contained proof that entries are in a stream.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
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
        #[arg(env = "TENBRI_STREAM")]
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

/// How `query` and `tail` print: one line per entry on a terminal, JSON otherwise.
#[derive(Args)]
struct Format {
    /// One JSON object per line, as when stdout is not a terminal.
    #[arg(long, conflicts_with = "pretty")]
    json: bool,
    /// One line per entry, as when stdout is a terminal.
    #[arg(long)]
    pretty: bool,
    /// One-line output: key entries too.
    #[arg(long)]
    all: bool,
}

impl Format {
    fn human(&self) -> bool {
        !self.json && (self.pretty || io::stdout().is_terminal())
    }
    /// Whether `e` is printed: every entry as JSON, key entries on lines only with --all.
    fn keeps(&self, e: &Entry) -> bool {
        !self.human() || self.all || e.kind != tenbri_core::Kind::Key
    }
}

const APPEND_EXAMPLE: &str = r#"The writer fills v, stream, seq, prev, signer and sig; id and ts are optional. A decision intent
needs kind, phase, source, principal and action:

  echo '{"kind":"decision","phase":"intent","source":"sdk",
         "principal":{"kind":"agent","id":"support-bot"},
         "action":{"type":"reply_ticket","target":"zendesk:ticket/1042"}}' | tenbri append ./audit/support

Its outcome names the intent's id and adds a status:

  {"kind":"decision","phase":"outcome","source":"sdk","intent":"<id>","status":"ok",
   "principal":{"kind":"agent","id":"support-bot"},"action":{"type":"reply_ticket"}}

Every field and rule: spec/format-v1.md, section 4."#;

/// The values of the entry's enumerated fields, printed with `append --help` and on its
/// `invalid_field` errors; `allowed_values_match_the_format` keeps them in step with tenbri-core.
const ALLOWED: &str = "\
allowed values:
  kind            decision, approval, key, reconcile, note
  phase           intent, outcome (decision entries only)
  source          sdk, proxy, ingest
  status          ok, error, refused, unknown (outcomes and reconciles)
  principal.kind  agent, person, service
  durability      local, replicated, postgres
  links[].rel     cause, handoff, approval";

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
    List {
        #[arg(env = "TENBRI_STREAM")]
        path: String,
    },
    /// Print a subject's data keys as JSON, for a backup kept apart from the log.
    Export {
        #[arg(env = "TENBRI_STREAM")]
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
        #[arg(env = "TENBRI_STREAM")]
        path: String,
        #[command(flatten)]
        who: Who,
        /// Who rotated, recorded as the note's principal (a person id).
        #[arg(long, value_name = "ID")]
        by: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReceiptCommand {
    /// Write a receipt for entries of a stream: the entries, the stream's key history, a signed
    /// checkpoint covering them and their inclusion proofs, and its RFC 3161 token if it has one.
    Create {
        #[arg(env = "TENBRI_STREAM")]
        path: String,
        /// An entry's sequence number or id; repeat for a receipt proving several.
        #[arg(long, required = true, value_name = "SEQ|ID")]
        entry: Vec<String>,
        /// Where to write it [default: stdout].
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Check the stream against this fingerprint while reading it.
        #[arg(long, value_name = "FINGERPRINT")]
        key: Option<String>,
    },
    /// Check a receipt offline against a pinned stream key: no network, no access to the stream.
    Verify {
        file: PathBuf,
        /// Fingerprint (sha256:…) or public key (ed25519:…) of the stream's genesis key.
        #[arg(long, value_name = "FINGERPRINT")]
        key: String,
        /// The timestamp authorities' root certificates you trust (PEM); without it, RFC 3161
        /// tokens in the receipt are not checked.
        #[arg(long, value_name = "PEM")]
        tsa_roots: Option<PathBuf>,
        /// A witness you trust, by its verifier key (name+id+base64); repeat for several.
        /// Experimental: needs the `witness` feature.
        #[arg(long, value_name = "VKEY")]
        witness: Vec<String>,
        /// How many of the --witness keys must have cosigned the checkpoint [default: all].
        #[arg(long, value_name = "N", requires = "witness")]
        witnesses: Option<usize>,
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
        #[arg(env = "TENBRI_STREAM")]
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
            let (pin, pins) = resolve_pin(key.as_deref(), path, cli.keys.as_deref())?;
            let recorded = pins
                .map(|f| format!(" (the pin recorded in {})", f.display()))
                .unwrap_or_default();
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
                println!(
                    "{} entries verified before it, stream {stream}{recorded}",
                    r.entries
                );
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
                    "verified {} entries, stream {stream}, pinned to {pin}{recorded}",
                    r.entries
                );
                return Ok(0);
            }
            println!("consistent: {} entries, stream {stream}", r.entries);
            println!(
                "NOT pinned: this only shows the stream agrees with its own genesis key; pass --key <fingerprint>"
            );
            // ponytail: a second read for the genesis key; verify's report could carry it.
            let mut reader = Reader::new(&store, None);
            if let Some(fp) = read(&mut reader).await?.first().and_then(genesis) {
                println!(
                    "its genesis key is {fp}; if the stream's owner gave you that fingerprint, pin it:"
                );
                println!("  tenbri verify {path} --key {fp}");
            }
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
            format,
        } => {
            let pin = lines_pin(key.as_deref(), path, cli.keys.as_deref(), format)?;
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
            query(&store, &filter, limit, *verify, pin.as_deref(), format).await
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
            format,
        } => {
            let pin = lines_pin(key.as_deref(), path, cli.keys.as_deref(), format)?;
            let mark = if pin.is_some() {
                "verified"
            } else {
                "unpinned"
            };
            let store = store(path).await?;
            let mut r = Reader::new(&store, pin.as_deref());
            let first: Vec<Entry> = read(&mut r)
                .await?
                .into_iter()
                .filter(|e| format.keeps(e))
                .collect();
            print_entries(&first[first.len().saturating_sub(*lines)..], format, mark)?;
            if *no_follow {
                return Ok(0);
            }
            // ponytail: polls HEAD every 500 ms; a file watcher when latency matters.
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let new: Vec<Entry> = read(&mut r)
                    .await?
                    .into_iter()
                    .filter(|e| format.keeps(e))
                    .collect();
                print_entries(&new, format, mark)?;
            }
        }
        Command::Show {
            args,
            key,
            json,
            pretty,
        } => {
            let (path, want) = match &args[..] {
                [path, want] => (path.clone(), want),
                [want] => (
                    std::env::var("TENBRI_STREAM")
                        .ok()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            Fail(2, "no stream: pass one, or set TENBRI_STREAM".into())
                        })?,
                    want,
                ),
                _ => unreachable!("clap takes one or two"),
            };
            let json = *json || !(*pretty || io::stdout().is_terminal());
            show(&path, want, key.as_deref(), cli.keys.as_deref(), json).await
        }
        Command::Checkpoint { path, tsa } => checkpoint(path, &keys_dir()?, tsa.as_deref()).await,
        Command::Receipt {
            command:
                ReceiptCommand::Create {
                    path,
                    entry,
                    out,
                    key,
                },
        } => {
            let pin = key.as_deref().map(pin).transpose()?;
            let store = store(path).await?;
            let wanted = |e: &Entry| entry.iter().any(|w| *w == e.id || w.parse() == Ok(e.seq));
            let r = tenbri_writer::receipt(&store, pin.as_deref(), wanted)
                .await
                .map_err(|e| match e {
                    ReceiptError::Read(ReadError::Broken(b)) => {
                        Fail(1, format!("the stream does not verify: {b}"))
                    }
                    e => Fail(2, e.to_string()),
                })?;
            match out {
                Some(f) => {
                    std::fs::write(f, &r).map_err(|e| Fail(2, format!("{}: {e}", f.display())))?
                }
                None => io::stdout().write_all(&r)?,
            }
            Ok(0)
        }
        Command::Receipt {
            command:
                ReceiptCommand::Verify {
                    file,
                    key,
                    tsa_roots,
                    witness,
                    witnesses,
                },
        } => receipt_verify(
            file,
            &pin(key)?,
            tsa_roots.as_deref(),
            witness,
            witnesses.unwrap_or(witness.len()),
        ),
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

fn receipt_verify(
    file: &Path,
    pin: &str,
    tsa_roots: Option<&Path>,
    witness: &[String],
    need: usize,
) -> Result<u8, Fail> {
    let at = |p: &Path, e: &dyn std::fmt::Display| Fail(2, format!("{}: {e}", p.display()));
    let bytes = std::fs::read(file).map_err(|e| at(file, &e))?;
    let roots = tsa_roots
        .map(|p| {
            std::fs::read(p)
                .map_err(|e| at(p, &e))
                .and_then(|b| tenbri_anchor::parse_roots(&b).map_err(|e| at(p, &e)))
        })
        .transpose()?;
    let v = match tenbri_anchor::verify_receipt(&bytes, pin, roots.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            println!("receipt does not verify: {e}");
            return Ok(1);
        }
    };
    let cosigned = match cosignatures(&v.receipt, witness, need)? {
        Ok(c) => c,
        Err(e) => {
            println!("receipt does not verify: {e}");
            return Ok(1);
        }
    };
    let r = &v.receipt;
    let cp = &r.checkpoint;
    for e in r.proved() {
        println!(
            "proves seq {} ({}), id {}, ts {} (claimed by the writer)",
            e.seq,
            kind(e),
            e.id,
            e.ts
        );
    }
    println!(
        "in stream {}, checkpoint at size {}, pinned to {pin}; key history: {} key entries",
        cp.origin,
        cp.size,
        r.entries
            .iter()
            .filter(|e| e.kind == tenbri_core::Kind::Key)
            .count()
    );
    match &v.timestamps {
        Some(ts) => {
            for t in ts {
                println!(
                    "timestamped by {} at {} (RFC 3161): the checkpoint existed then",
                    t.tsa,
                    tenbri_anchor::rfc3339(t.unix)
                );
            }
        }
        None if !r.rfc3161.is_empty() => println!(
            "{} RFC 3161 token(s) NOT checked: pass --tsa-roots <pem> to trust a timestamp authority",
            r.rfc3161.len()
        ),
        None => {}
    }
    for (name, time) in cosigned {
        println!(
            "cosigned by witness {name} at {} (its time): it saw no other history up to this checkpoint",
            tenbri_anchor::rfc3339(time)
        );
    }
    Ok(0)
}

/// The witnesses pinned by `vkeys` that cosigned the receipt's checkpoint, with their time; at
/// least `need` of them, or why not (spec/checkpoints.md, section 6).
#[cfg(feature = "witness")]
fn cosignatures(
    r: &tenbri_merkle::receipt::Verified,
    vkeys: &[String],
    need: usize,
) -> Result<Result<Vec<(String, u64)>, tenbri_core::Error>, Fail> {
    use tenbri_merkle::witness::{self, Witness};
    let ws = vkeys
        .iter()
        .map(|k| Witness::parse(k).map_err(|e| Fail(2, e.detail)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(witness::verify(r, &ws, need).map(|c| c.into_iter().map(|c| (c.name, c.time)).collect()))
}

#[cfg(not(feature = "witness"))]
fn cosignatures(
    _: &tenbri_merkle::receipt::Verified,
    vkeys: &[String],
    _: usize,
) -> Result<Result<Vec<(String, u64)>, tenbri_core::Error>, Fail> {
    if vkeys.is_empty() {
        return Ok(Ok(vec![]));
    }
    Err(Fail(
        2,
        "--witness needs tenbri built with the `witness` feature (Experimental)".into(),
    ))
}

/// An entry's kind, and its phase if it has one: `decision intent`.
fn kind(e: &Entry) -> String {
    let k = name(&e.kind);
    match &e.phase {
        Some(p) => format!("{k} {}", name(p)),
        None => k,
    }
}

async fn checkpoint(path: &str, keys: &Path, tsa: Option<&str>) -> Result<u8, Fail> {
    let (store, ks) = open_stream(path, keys).await?;
    let mut w = open_writer(store, ks).await?;
    let size = w.checkpoint().await?;
    println!("checkpoint at size {size}: {}", checkpoint::key(size));
    let Some(url) = tsa else { return Ok(0) };
    let anchor = checkpoint::anchor_key(size);
    if w.store().get(&anchor).await?.is_some() {
        println!("already timestamped: {anchor}");
        return Ok(0);
    }
    let note = w
        .store()
        .get(&checkpoint::key(size))
        .await?
        .ok_or_else(|| Fail(2, format!("{} vanished", checkpoint::key(size))))?;
    let text = Note::parse(&note.bytes)?.text().to_owned();
    let tsr = tenbri_anchor::timestamp(url, text.as_bytes()).await?;
    w.store().put_if_absent(&anchor, &tsr).await?;
    println!("timestamped by {url}: {anchor}");
    Ok(0)
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
    // No index directory: no index to erase from.
    let ixdir = index_dir(&store).await.ok();
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
    // The index holds the subject's refs and targets in plaintext: its rows go too. Rebuilds keep
    // them out by the note just written.
    if let (Some(s), Some(dir)) = (subject, &ixdir) {
        if let Some(mut ix) = tenbri_index::find(dir)? {
            ix.erase(s).map_err(|err| {
                Fail(
                    2,
                    format!(
                        "erasure recorded at seq {}, but the index at {} still holds subject {s}: \
                         {err}; run tenbri index rebuild",
                        e.seq,
                        dir.display()
                    ),
                )
            })?;
        }
    }
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
    format: &Format,
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
            } else {
                tenbri_index::confirm(store, &page.hits)
                    .await
                    .map_err(|e| match e.kind() {
                        io::ErrorKind::InvalidData => Fail(1, e.to_string()),
                        _ => e.into(),
                    })?;
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
        if format.human() {
            let e: Entry = serde_json::from_str(&h.line)?;
            if format.keeps(&e) {
                writeln!(out, "{}", summary(&e, status))?;
            }
            continue;
        }
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

fn print_entries(entries: &[Entry], format: &Format, mark: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for e in entries {
        if format.human() {
            writeln!(out, "{}", summary(e, mark))?;
        } else {
            writeln!(out, "{}", line(e))?;
        }
    }
    out.flush()
}

/// An enum member as the format spells it: `decision`.
fn name<T: serde::Serialize>(v: &T) -> String {
    match canon::from_serialize(v) {
        Ok(canon::Value::Str(s)) => s,
        _ => "?".into(),
    }
}

fn principal(p: &Principal) -> String {
    format!("{}:{}", name(&p.kind), p.id)
}

fn action(a: &tenbri_core::Action) -> String {
    match &a.target {
        Some(t) => format!("{} {t}", a.r#type),
        None => a.r#type.clone(),
    }
}

/// One line for an entry: seq, ts, kind and phase, principal, action, status, verification.
fn summary(e: &Entry, mark: &str) -> String {
    let or_dash = |s: Option<String>| s.unwrap_or_else(|| "-".into());
    format!(
        "{:>6}  {}  {:<17} {:<24} {:<32} {:<8} {mark}",
        e.seq,
        e.ts,
        kind(e),
        or_dash(e.principal.as_ref().map(principal)),
        or_dash(e.action.as_ref().map(action)),
        or_dash(e.status.as_ref().map(name)),
    )
}

/// The fingerprint of the genesis key a stream's first entry certifies.
fn genesis(first: &Entry) -> Option<String> {
    match &first.key {
        Some(tenbri_core::KeyEvent::Certify { public, .. }) => {
            sign::decode_key(public).ok().map(|k| sign::fingerprint(&k))
        }
        _ => None,
    }
}

/// The fingerprint to check `path` against: `--key`, else the pin recorded when the stream was
/// created here, with the pins file it came from.
fn resolve_pin(
    key: Option<&str>,
    path: &str,
    keys: Option<&Path>,
) -> Result<(Option<String>, Option<PathBuf>), Fail> {
    if let Some(k) = key {
        return Ok((Some(pin(k)?), None));
    }
    let found = keys
        .map(Path::to_owned)
        .or_else(tenbri_keys::default_dir)
        .and_then(|d| tenbri_keys::recorded_pin(&d, path));
    match found {
        Some((fp, file)) => Ok((Some(pin(&fp)?), Some(file))),
        None => Ok((None, None)),
    }
}

/// The pin of `query` and `tail`: `--key`; on one-line output, else the recorded pin. JSON output
/// stays as it was without `--key`, for scripts.
fn lines_pin(
    key: Option<&str>,
    path: &str,
    keys: Option<&Path>,
    format: &Format,
) -> Result<Option<String>, Fail> {
    match key {
        None if format.human() => Ok(resolve_pin(None, path, keys)?.0),
        k => k.map(pin).transpose(),
    }
}

/// `tenbri show`: the entry `want` (a seq or an id), its chain, and whether the stream verifies.
async fn show(
    path: &str,
    want: &str,
    key: Option<&str>,
    keys: Option<&Path>,
    json: bool,
) -> Result<u8, Fail> {
    let (pin, pins) = resolve_pin(key, path, keys)?;
    let store = store(path).await?;
    let mut r = Reader::new(&store, pin.as_deref());
    let entries = read(&mut r).await?;
    if let Some(b) = r.chain().invalidated() {
        return Err(Fail(1, format!("the stream does not verify: {b}")));
    }
    let hash = |e: &Entry| format!("sha256:{}", encoding::hex(&r.hashes()[e.seq as usize - 1]));
    let e = entries
        .iter()
        .find(|e| e.id == want || want.parse() == Ok(e.seq))
        .ok_or_else(|| Fail(2, format!("no entry {want} in {path}")))?;
    // The intent the entry belongs to: itself, or the one its outcome or reconcile names.
    let root = match e.phase {
        Some(tenbri_core::Phase::Intent) => Some(e.id.as_str()),
        _ => e.intent.as_deref(),
    };
    let own = hash(e);
    let linked = |x: &Entry| {
        x.seq == e.seq
            || root.is_some_and(|i| x.id == i || x.intent.as_deref() == Some(i))
            || x.approval.as_ref().is_some_and(|a| a.entry == own)
    };
    // And the approvals those cite.
    let cited: Vec<&str> = entries
        .iter()
        .filter(|x| linked(x))
        .filter_map(|x| x.approval.as_ref().map(|a| a.entry.as_str()))
        .collect();
    let chain: Vec<&Entry> = entries
        .iter()
        .filter(|x| linked(x) || cited.contains(&hash(x).as_str()))
        .collect();
    let status = if pin.is_some() {
        "verified"
    } else {
        "unpinned"
    };
    let mut out = io::stdout().lock();
    if json {
        for x in chain {
            writeln!(
                out,
                "{{\"verification\":\"{status}\",\"entry\":{},\"seq\":{},\"hash\":\"{}\"}}",
                line(x),
                x.seq,
                hash(x)
            )?;
        }
        return Ok(0);
    }
    writeln!(out, "seq {}  {}  {}", e.seq, kind(e), e.id)?;
    let field = |out: &mut io::StdoutLock, k: &str, v: String| writeln!(out, "  {k:<12} {v}");
    field(&mut out, "ts", e.ts.clone())?;
    field(&mut out, "hash", own.clone())?;
    let canon::Value::Obj(members) = canon::from_serialize(e)? else {
        unreachable!("an entry is an object")
    };
    for (k, v) in members {
        let v = match (k.as_str(), v) {
            ("v" | "id" | "stream" | "seq" | "ts" | "kind" | "phase" | "prev" | "sig", _) => {
                continue;
            }
            ("principal", _) => e.principal.as_ref().map(principal).unwrap_or_default(),
            ("action", _) => e.action.as_ref().map(action).unwrap_or_default(),
            (_, canon::Value::Str(s)) => s,
            (_, v) => String::from_utf8(canon::to_vec(&v)).expect("UTF-8"),
        };
        field(&mut out, &k, v)?;
    }
    let verdict = match (&pin, &pins) {
        (Some(p), None) => format!("verified, pinned to {p}"),
        (Some(p), Some(f)) => format!("verified, pinned to {p} (recorded in {})", f.display()),
        (None, _) => format!(
            "unpinned: consistent with its own genesis key only; `tenbri verify {path}` prints the --key to pin"
        ),
    };
    field(&mut out, "verification", verdict)?;
    if chain.len() > 1 {
        writeln!(out, "\nchain:")?;
        for x in chain {
            let at = if x.seq == e.seq { ">" } else { " " };
            writeln!(out, "{at}{}", summary(x, status))?;
        }
    }
    Ok(0)
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
    let pins = tenbri_keys::record_pin(keys, path, &stream_key.fingerprint())
        .map_err(|e| Fail(2, e.to_string()))?;
    println!("created stream {id} at {path}");
    println!(
        "stream key fingerprint (pin it): {}",
        stream_key.fingerprint()
    );
    println!("keys: {}", ks.dir().display());
    println!("pinned in {}: tenbri verify {path} uses it", pins.display());
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
    w.use_keys(ks).await?;
    // A stream whose checkpoint key tenbrid certified: checkpoints made here are signed for
    // witnesses too. The CLI never certifies one.
    #[cfg(feature = "witness")]
    w.use_checkpoint_key(false).await?;
    Ok(w)
}

/// An append error, with the allowed values when a field had the wrong one.
fn invalid(msg: String) -> Fail {
    if msg.contains("invalid_field") {
        return Fail(
            2,
            format!("{msg}\n{ALLOWED}\nan example: tenbri append --help"),
        );
    }
    Fail(2, msg)
}

async fn append(path: &str, keys: &Path) -> Result<u8, Fail> {
    let mut input = vec![];
    io::stdin().read_to_end(&mut input)?;
    let draft = draft_from_json(&input).map_err(|mut e| {
        // serde's position is in the canonicalised bytes, not in what was typed.
        if let Some(i) = e.detail.find(" at line ") {
            e.detail.truncate(i);
        }
        invalid(format!("stdin: {e}"))
    })?;
    let (store, ks) = open_stream(path, keys).await?;
    let mut w = open_writer(store, ks).await?;
    let now = now_ms();
    w.reconcile_stale(now, RECONCILE_AFTER_MS, draft.intent.as_deref())
        .await?;
    let e = w.append(draft).await.map_err(|e| invalid(e.to_string()))?;
    println!("{}", line(&e));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::ALLOWED;
    use tenbri_core::{Durability, Kind, Phase, PrincipalKind, Rel, Source, Status};

    /// Each line of ALLOWED lists exactly the variants tenbri-core accepts, in its order.
    #[test]
    fn allowed_values_match_the_format() {
        fn expected<T: serde::de::DeserializeOwned>() -> String {
            let e = serde_json::from_str::<T>("\"?\"")
                .err()
                .unwrap()
                .to_string();
            let list = e.split("expected ").nth(1).unwrap();
            list.split('`')
                .skip(1)
                .step_by(2)
                .collect::<Vec<_>>()
                .join(", ")
        }
        let want = [
            ("kind", expected::<Kind>()),
            ("phase", expected::<Phase>()),
            ("source", expected::<Source>()),
            ("status", expected::<Status>()),
            ("principal.kind", expected::<PrincipalKind>()),
            ("durability", expected::<Durability>()),
            ("links[].rel", expected::<Rel>()),
        ];
        let lines: Vec<&str> = ALLOWED.lines().skip(1).collect();
        assert_eq!(lines.len(), want.len());
        for (l, (field, values)) in lines.iter().zip(want) {
            let (f, v) = l.trim().split_once(' ').unwrap();
            assert_eq!(f, field);
            assert!(v.trim().starts_with(&values), "{field}: {v} vs {values}");
        }
    }
}
