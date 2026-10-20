//! Tenbri's derived index: a view of one stream that can be deleted and rebuilt from its batches
//! at any time, and is never the source of truth.
//!
//! Two backends behind one trait, [`Backend`]: SQLite (the default, one file) and Parquet (a
//! directory of files any Arrow tool reads). Both hold one row per entry with the fields queries
//! filter on, the entry's canonical line, its sequence number and its entry hash, and record the
//! sequence number, entry hash and latest checkpoint they are current to ([`State`]).
//!
//! - [`update`] brings an index up to the stream's HEAD, reading only the batches it lacks; it
//!   refuses a stream that no longer extends what the index holds (a rewrite, a truncation, a
//!   different stream) instead of mixing the two.
//! - [`rebuild`] empties the index and reads the stream again from seq 1.
//! - [`Backend::erase`] removes a subject's rows (`tenbri erase`); [`append`], which both of the
//!   above write through, keeps them out once the stream records the erasure.
//! - [`search`] answers a [`Filter`] a page at a time; every [`Hit`] carries the seq and entry
//!   hash it can be checked by against the chain, and the [`Page`] says what the index is current
//!   to.
//!
//! The index reads the stream without checking signatures: its answers are "indexed", not
//! "verified", until a caller checks them against a verified read of the stream.

mod parquet;
mod sqlite;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;
use tenbri_core::{Entry, Head, encoding, sign};
use tenbri_store::Store;
use tenbri_writer::{batch_key, split_batch};

pub use crate::parquet::ParquetIndex;
pub use crate::sqlite::SqliteIndex;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Rows written per call to [`Backend::append`] while catching up, to bound memory.
const CHUNK: usize = 50_000;

/// What an index is current to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct State {
    /// The stream id (tnb1:…).
    pub stream: String,
    /// The last sequence number indexed.
    pub seq: u64,
    /// The entry hash at `seq`.
    pub hash: String,
    /// The size of the stream's latest checkpoint at or below `seq`, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<u64>,
}

/// One entry as the index holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub seq: u64,
    pub hash: String,
    pub id: String,
    pub ts: String,
    pub kind: String,
    pub phase: Option<String>,
    pub status: Option<String>,
    pub principal_kind: Option<String>,
    pub principal_id: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub subject: Option<String>,
    pub rule_ref: Option<String>,
    pub rule_version: Option<String>,
    pub rule_result: Option<String>,
    pub trace_id: Option<String>,
    /// (ref, version) of each input.
    pub inputs: Vec<(String, String)>,
    /// The entry's canonical JSON.
    pub line: String,
}

/// The lowercase name serde gives a unit variant.
fn name<T: Serialize>(t: &T) -> String {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => s,
        _ => unreachable!("a unit variant"),
    }
}

impl Row {
    /// The row of `e`, stored as `line`.
    pub fn new(e: &Entry, line: &str) -> Row {
        Row {
            seq: e.seq,
            hash: sign::entry_hash(line.as_bytes()),
            id: e.id.clone(),
            ts: e.ts.clone(),
            kind: name(&e.kind),
            phase: e.phase.as_ref().map(name),
            status: e.status.as_ref().map(name),
            principal_kind: e.principal.as_ref().map(|p| name(&p.kind)),
            principal_id: e.principal.as_ref().map(|p| p.id.clone()),
            action: e.action.as_ref().map(|a| a.r#type.clone()),
            target: e.action.as_ref().and_then(|a| a.target.clone()),
            subject: e.subject.clone(),
            rule_ref: e.rule.as_ref().map(|r| r.r#ref.clone()),
            rule_version: e.rule.as_ref().map(|r| r.version.clone()),
            rule_result: e.rule.as_ref().map(|r| r.result.clone()),
            trace_id: e.trace.as_ref().map(|t| t.trace_id.clone()),
            inputs: e
                .inputs
                .iter()
                .flatten()
                .map(|i| (i.r#ref.clone(), i.version.clone()))
                .collect(),
            line: line.to_owned(),
        }
    }
}

/// What to look for; empty fields match everything, and an entry must match all the others.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Inputs the entry used: ref, and version if given (`policy:refund@14`). All must match.
    pub inputs: Vec<(String, Option<String>)>,
    /// The action type.
    pub action: Option<String>,
    /// `kind:id` (`agent:support-assistant`).
    pub principal: Option<String>,
    /// The action target, exactly.
    pub target: Option<String>,
    pub subject: Option<String>,
    /// The rule's ref, and version if given.
    pub rule: Option<(String, Option<String>)>,
    /// `ts` at or after this (`YYYY-MM-DDTHH:MM:SS.mmmZ`, see [`parse_time`]).
    pub since: Option<String>,
    /// `ts` before this.
    pub until: Option<String>,
    /// The OpenTelemetry trace id.
    pub trace_id: Option<String>,
    /// An outcome's status: ok, error, refused or unknown.
    pub status: Option<String>,
    /// Only entries with a greater sequence number: the cursor of the previous page.
    pub after: u64,
}

/// Splits `ref@version`; without `@`, any version.
pub fn ref_version(s: &str) -> (String, Option<String>) {
    match s.rsplit_once('@') {
        Some((r, v)) => (r.to_owned(), Some(v.to_owned())),
        None => (s.to_owned(), None),
    }
}

impl Filter {
    /// Whether `row` matches. The scan and the Parquet backend use this; SQLite says the same in
    /// SQL, and the tests hold them to the same answers.
    pub fn matches(&self, row: &Row) -> bool {
        let eq = |want: &Option<String>, have: &Option<String>| {
            want.as_ref().is_none_or(|w| have.as_ref() == Some(w))
        };
        let version = |want: &Option<String>, have: &str| want.as_ref().is_none_or(|w| w == have);
        row.seq > self.after
            && self
                .inputs
                .iter()
                .all(|(r, v)| row.inputs.iter().any(|(rr, vv)| rr == r && version(v, vv)))
            && eq(&self.action, &row.action)
            && self.principal.as_ref().is_none_or(|p| {
                matches!((&row.principal_kind, &row.principal_id), (Some(k), Some(id))
                    if p.split_once(':') == Some((k.as_str(), id.as_str())))
            })
            && eq(&self.target, &row.target)
            && eq(&self.subject, &row.subject)
            && self.rule.as_ref().is_none_or(|(r, v)| {
                row.rule_ref.as_ref() == Some(r)
                    && row.rule_version.as_deref().is_some_and(|rv| version(v, rv))
            })
            && self.since.as_ref().is_none_or(|s| row.ts >= *s)
            && self.until.as_ref().is_none_or(|u| row.ts < *u)
            && eq(&self.trace_id, &row.trace_id)
            && eq(&self.status, &row.status)
    }

    /// Whether entry `e` matches.
    pub fn matches_entry(&self, e: &Entry, line: &str) -> bool {
        self.matches(&Row::new(e, line))
    }
}

/// A matching entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub seq: u64,
    /// Its entry hash, to check against the chain.
    pub hash: String,
    /// Its canonical JSON.
    pub line: String,
}

/// One page of answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub hits: Vec<Hit>,
    /// When more entries match: the `after` of the next page.
    pub next: Option<u64>,
    /// What the index was current to when it answered.
    pub state: Option<State>,
}

/// An index backend. Implementations keep the rows and the state together: a crash leaves the
/// state of the last complete [`Backend::append`].
pub trait Backend: Send {
    /// What the index is current to; `None` when it is empty.
    fn state(&self) -> io::Result<Option<State>>;
    /// Adds `rows` (in sequence order, after the current state) and moves the state to `state`.
    /// Callers that index a stream go through [`append`], which applies its erasure notes.
    fn append(&mut self, rows: &[Row], state: &State) -> io::Result<()>;
    /// Deletes every row of `subject`, leaving the state as it is.
    fn erase(&mut self, subject: &str) -> io::Result<()>;
    /// Up to `limit` matching hits, in sequence order.
    fn query(&self, f: &Filter, limit: usize) -> io::Result<Vec<Hit>>;
    /// Removes every row and the state.
    fn clear(&mut self) -> io::Result<()>;
    /// Which backend this is.
    fn kind(&self) -> Kind;
}

/// The action type of the note `tenbri erase` writes (`tenbri_crypt::erasure_note`).
const ERASE: &str = "tenbri.erase";

/// [`Backend::append`], after applying the erasure notes among `rows`: each erases its subject's
/// rows before it, here and already in `ix`, and is kept itself without a subject, so that
/// `--action tenbri.erase` lists erasures and `--subject` finds nothing. A subject's rows after
/// its erasure are indexed again.
pub fn append(ix: &mut dyn Backend, rows: Vec<Row>, state: &State) -> io::Result<()> {
    let mut out: Vec<Row> = Vec::with_capacity(rows.len());
    let mut erased = vec![];
    for mut row in rows {
        if row.kind == "note" && row.action.as_deref() == Some(ERASE) {
            if let Some(s) = row.subject.take() {
                // ponytail: rescans the batch per note; notes are rare.
                out.retain(|r| r.subject.as_ref() != Some(&s));
                erased.push(s);
            }
        }
        out.push(row);
    }
    // Before the append, so that rows after the note survive. A crash in between leaves the old
    // state, and the next update erases again.
    for s in &erased {
        ix.erase(s)?;
    }
    ix.append(&out, state)
}

/// A page of at most `limit` hits.
pub fn search(ix: &dyn Backend, f: &Filter, limit: usize) -> io::Result<Page> {
    let mut hits = ix.query(f, limit.saturating_add(1))?;
    let next = (hits.len() > limit).then(|| {
        hits.truncate(limit);
        hits.last().map_or(f.after, |h| h.seq)
    });
    Ok(Page {
        hits,
        next,
        state: ix.state()?,
    })
}

/// The index backends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Sqlite,
    Parquet,
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Kind, String> {
        match s {
            "sqlite" => Ok(Kind::Sqlite),
            "parquet" => Ok(Kind::Parquet),
            "iceberg" => Err("the Iceberg index is not built yet; use sqlite or parquet".into()),
            _ => Err(format!("{s}: expected sqlite or parquet")),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&name(self))
    }
}

const SQLITE_FILE: &str = "index.sqlite";
const PARQUET_DIR: &str = "parquet";

/// Opens the index of `kind` in `dir`, creating it if needed.
pub fn open(kind: Kind, dir: &Path) -> io::Result<Box<dyn Backend>> {
    std::fs::create_dir_all(dir)?;
    Ok(match kind {
        Kind::Sqlite => Box::new(SqliteIndex::open(&dir.join(SQLITE_FILE))?),
        Kind::Parquet => Box::new(ParquetIndex::open(&dir.join(PARQUET_DIR))?),
    })
}

/// The index already in `dir`, if there is one (SQLite first).
pub fn find(dir: &Path) -> io::Result<Option<Box<dyn Backend>>> {
    for kind in [Kind::Sqlite, Kind::Parquet] {
        if dir.join(path_of(kind)).exists() {
            return open(kind, dir).map(Some);
        }
    }
    Ok(None)
}

/// Deletes every index in `dir`.
pub fn remove(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn path_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Sqlite => SQLITE_FILE,
        Kind::Parquet => PARQUET_DIR,
    }
}

/// The directory of `stream`'s index under `root`.
pub fn dir_for(root: &Path, stream: &str) -> PathBuf {
    root.join(stream.replace(':', "-"))
}

/// Where indexes live by default: `$TENBRI_INDEX_DIR`, else the user's cache directory
/// (`~/Library/Caches/tenbri/index`, `$XDG_CACHE_HOME/tenbri/index` or `~/.cache/…`,
/// `%LOCALAPPDATA%\tenbri\index`).
pub fn default_root() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(d) = env("TENBRI_INDEX_DIR") {
        return Some(d);
    }
    let cache = if cfg!(windows) {
        env("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Caches"))
    } else {
        env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|h| h.join(".cache")))
    };
    cache.map(|c| c.join("tenbri").join("index"))
}

/// A time for [`Filter::since`] and [`Filter::until`]: `YYYY-MM-DDTHH:MM:SS.mmmZ`, the same
/// without milliseconds, a date (`YYYY-MM-DD`, midnight UTC), or a duration before `now_ms`
/// (`90s`, `15m`, `1h`, `7d`).
pub fn parse_time(s: &str, now_ms: i64) -> Option<String> {
    if let Some(unit) = s.chars().last().filter(|c| "smhd".contains(*c)) {
        if let Ok(n) = s[..s.len() - 1].parse::<i64>() {
            let ms = match unit {
                's' => 1_000,
                'm' => 60_000,
                'h' => 3_600_000,
                _ => 86_400_000,
            };
            return Some(encoding::format_ts(now_ms.checked_sub(n.checked_mul(ms)?)?));
        }
    }
    let full = match s.len() {
        10 => format!("{s}T00:00:00.000Z"),
        20 => format!("{}.000Z", s.strip_suffix('Z')?),
        _ => s.to_owned(),
    };
    encoding::parse_ts(&full).map(encoding::format_ts)
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Brings `ix` up to the stream's HEAD in `store`, reading only the batches after its state.
///
/// Refuses, without changing the index, a stream that does not extend what the index holds: a
/// HEAD behind it or a different entry at its seq (a rewrite or a truncation, which `tenbri
/// verify` reports), or another stream. Lines are parsed and chained by `prev`, not
/// signature-checked: that is `verify`'s job.
pub async fn update<S: Store>(ix: &mut dyn Backend, store: &S) -> io::Result<State> {
    let head = store
        .get("HEAD")
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no stream here (no HEAD)"))?;
    let (head, _) = Head::parse(&head.bytes).map_err(|e| invalid(e.to_string()))?;
    let mut state = ix.state()?;
    if let Some(s) = &state {
        let stale = |why: &str| {
            Err(invalid(format!(
                "the index does not match the stream: {why}; run `tenbri verify`, then `tenbri index rebuild`"
            )))
        };
        if s.stream != head.stream {
            return stale(&format!("it indexes {}, not {}", s.stream, head.stream));
        }
        if head.seq < s.seq {
            return stale(&format!("HEAD is at {}, the index at {}", head.seq, s.seq));
        }
        if head.seq == s.seq && head.hash != s.hash {
            return stale(&format!("another entry at seq {}", s.seq));
        }
    }
    let (mut seq, mut prev) = state
        .as_ref()
        .map_or((0, None), |s| (s.seq, Some(s.hash.clone())));
    let mut rows = vec![];
    while seq < head.seq {
        let first = seq + 1;
        let batch = store
            .get(&batch_key(first))
            .await?
            .ok_or_else(|| invalid(format!("{} is missing", batch_key(first))))?;
        for line in split_batch(&batch.bytes).map_err(|e| invalid(e.to_string()))? {
            let at = seq + 1;
            let bad = |why: &str| invalid(format!("seq {at}: {why}"));
            let e: Entry = serde_json::from_slice(line).map_err(|e| bad(&e.to_string()))?;
            if e.seq != at || e.stream != head.stream {
                return Err(bad("not the next entry of this stream"));
            }
            if e.prev != prev {
                return Err(bad(
                    "its prev is not the entry before it; run `tenbri verify`",
                ));
            }
            let line = std::str::from_utf8(line).map_err(|_| bad("not UTF-8"))?;
            let row = Row::new(&e, line);
            prev = Some(row.hash.clone());
            seq = at;
            rows.push(row);
            if rows.len() >= CHUNK {
                state = Some(flush(ix, &mut rows, &head.stream, None)?);
            }
        }
    }
    if seq > 0 && prev.as_deref() != Some(head.hash.as_str()) {
        return Err(invalid(format!(
            "HEAD's hash is not the entry hash at seq {seq}"
        )));
    }
    let checkpoint = latest_checkpoint(store, seq).await?;
    if !rows.is_empty() || state.as_ref().is_some_and(|s| s.checkpoint != checkpoint) {
        state = Some(flush(ix, &mut rows, &head.stream, checkpoint)?);
    }
    state.ok_or_else(|| invalid("an empty stream"))
}

fn flush(
    ix: &mut dyn Backend,
    rows: &mut Vec<Row>,
    stream: &str,
    checkpoint: Option<u64>,
) -> io::Result<State> {
    let old = ix.state()?;
    let last = rows.last();
    let state = State {
        stream: stream.to_owned(),
        seq: last.map_or_else(|| old.as_ref().map_or(0, |s| s.seq), |r| r.seq),
        hash: last.map_or_else(
            || old.as_ref().map(|s| s.hash.clone()).unwrap_or_default(),
            |r| r.hash.clone(),
        ),
        checkpoint: checkpoint.or(old.and_then(|s| s.checkpoint)),
    };
    append(ix, std::mem::take(rows), &state)?;
    Ok(state)
}

/// Empties `ix` and indexes the whole stream again.
pub async fn rebuild<S: Store>(ix: &mut dyn Backend, store: &S) -> io::Result<State> {
    ix.clear()?;
    update(ix, store).await
}

/// Checks each of `hits` against the batch in `store` that holds it, so that a batch edited on
/// disk after it was indexed fails the query instead of answering from the index's copy. Reads
/// only the batches the hits are in; the rest of the stream, and signatures, are `verify`'s job.
pub async fn confirm<S: Store>(store: &S, hits: &[Hit]) -> io::Result<()> {
    if hits.is_empty() {
        return Ok(());
    }
    // ponytail: lists every batch key per query; keep each row's batch in the index if that
    // listing gets slow. Put-if-absent keeps names up to HEAD on the chain, so the listing agrees
    // with what a reader following HEAD finds.
    let mut firsts: Vec<u64> = store
        .list("batches/")
        .await?
        .iter()
        .filter_map(|l| tenbri_writer::batch_seq(&l.key))
        .collect();
    firsts.sort_unstable();
    let mut held: Option<(u64, Vec<u8>)> = None;
    for h in hits {
        let changed = || {
            invalid(format!(
                "the stream changed under the index at seq {}: run `tenbri verify`",
                h.seq
            ))
        };
        let first = match firsts.partition_point(|&f| f <= h.seq) {
            0 => return Err(changed()),
            i => firsts[i - 1],
        };
        if held.as_ref().is_none_or(|(f, _)| *f != first) {
            let b = store.get(&batch_key(first)).await?.ok_or_else(changed)?;
            held = Some((first, b.bytes));
        }
        let (_, bytes) = held.as_ref().expect("fetched above");
        let lines = split_batch(bytes).map_err(|_| changed())?;
        let line = lines.get((h.seq - first) as usize).ok_or_else(changed)?;
        if sign::entry_hash(line) != h.hash || line != &h.line.as_bytes() {
            return Err(changed());
        }
    }
    Ok(())
}

/// The size of the latest checkpoint in `store` at or below `seq`.
pub async fn latest_checkpoint<S: Store>(store: &S, seq: u64) -> io::Result<Option<u64>> {
    Ok(store
        .list("checkpoints/")
        .await?
        .iter()
        .filter_map(|l| {
            let n: u64 = l
                .key
                .strip_prefix("checkpoints/")?
                .strip_suffix(".note")?
                .parse()
                .ok()?;
            (tenbri_merkle::checkpoint::key(n) == l.key).then_some(n)
        })
        .filter(|&n| n <= seq)
        .max())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let now = encoding::parse_ts("2026-10-20T12:00:00.000Z").unwrap();
        assert_eq!(parse_time("1h", now).unwrap(), "2026-10-20T11:00:00.000Z");
        assert_eq!(parse_time("2d", now).unwrap(), "2026-10-18T12:00:00.000Z");
        assert_eq!(
            parse_time("2026-10-19", now).unwrap(),
            "2026-10-19T00:00:00.000Z"
        );
        assert_eq!(
            parse_time("2026-10-19T01:02:03Z", now).unwrap(),
            "2026-10-19T01:02:03.000Z"
        );
        assert_eq!(
            parse_time("2026-10-19T01:02:03.004Z", now).unwrap(),
            "2026-10-19T01:02:03.004Z"
        );
        for bad in ["", "h", "yesterday", "2026-13-01", "-1x"] {
            assert_eq!(parse_time(bad, now), None, "{bad}");
        }
    }

    #[test]
    fn kinds() {
        assert_eq!("parquet".parse::<Kind>().unwrap(), Kind::Parquet);
        assert!("iceberg".parse::<Kind>().is_err());
        assert_eq!(Kind::Sqlite.to_string(), "sqlite");
    }
}
