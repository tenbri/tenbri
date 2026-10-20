//! The SQLite backend: one file, readable by any SQLite client.

use std::io;
use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

use crate::{Backend, Filter, Hit, Kind, Row, State};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    id TEXT NOT NULL,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    phase TEXT,
    status TEXT,
    principal_kind TEXT,
    principal_id TEXT,
    action TEXT,
    target TEXT,
    subject TEXT,
    rule_ref TEXT,
    rule_version TEXT,
    rule_result TEXT,
    trace_id TEXT
);
-- Apart, so that scans of entries read narrow rows.
CREATE TABLE IF NOT EXISTS lines (
    seq INTEGER PRIMARY KEY REFERENCES entries(seq),
    line TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inputs (
    seq INTEGER NOT NULL REFERENCES entries(seq),
    ref TEXT NOT NULL,
    version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS inputs_ref ON inputs(ref, version, seq);
CREATE INDEX IF NOT EXISTS entries_action ON entries(action, seq);
CREATE INDEX IF NOT EXISTS entries_principal ON entries(principal_id, principal_kind, seq);
CREATE INDEX IF NOT EXISTS entries_target ON entries(target, seq);
CREATE INDEX IF NOT EXISTS entries_subject ON entries(subject, seq);
CREATE INDEX IF NOT EXISTS entries_rule ON entries(rule_ref, rule_version, seq);
CREATE INDEX IF NOT EXISTS entries_ts ON entries(ts);
CREATE INDEX IF NOT EXISTS entries_trace ON entries(trace_id, seq);
CREATE INDEX IF NOT EXISTS entries_status ON entries(status, seq);
CREATE TABLE IF NOT EXISTS state (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    stream TEXT NOT NULL,
    seq INTEGER NOT NULL,
    hash TEXT NOT NULL,
    checkpoint INTEGER
);
";

/// The SQLite index.
pub struct SqliteIndex(Connection);

fn err(e: rusqlite::Error) -> io::Error {
    io::Error::other(e)
}

fn int(n: u64) -> io::Result<i64> {
    i64::try_from(n).map_err(|_| io::Error::other("a sequence number above 2^63"))
}

impl SqliteIndex {
    /// Opens or creates the index file at `path`.
    pub fn open(path: &Path) -> io::Result<SqliteIndex> {
        let c = Connection::open(path).map_err(err)?;
        // WAL: tenbri query can read while tenbrid writes.
        c.pragma_update(None, "journal_mode", "WAL").map_err(err)?;
        c.pragma_update(None, "synchronous", "NORMAL")
            .map_err(err)?;
        c.pragma_update(None, "cache_size", -65_536).map_err(err)?;
        c.execute_batch(SCHEMA).map_err(err)?;
        Ok(SqliteIndex(c))
    }
}

impl Backend for SqliteIndex {
    fn kind(&self) -> Kind {
        Kind::Sqlite
    }

    fn state(&self) -> io::Result<Option<State>> {
        self.0
            .query_row("SELECT stream, seq, hash, checkpoint FROM state", [], |r| {
                Ok(State {
                    stream: r.get(0)?,
                    seq: r.get::<_, i64>(1)? as u64,
                    hash: r.get(2)?,
                    checkpoint: r.get::<_, Option<i64>>(3)?.map(|n| n as u64),
                })
            })
            .optional()
            .map_err(err)
    }

    fn append(&mut self, rows: &[Row], state: &State) -> io::Result<()> {
        let tx = self.0.transaction().map_err(err)?;
        {
            let mut entry = tx
                .prepare_cached(
                    "INSERT INTO entries VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                )
                .map_err(err)?;
            let mut line = tx
                .prepare_cached("INSERT INTO lines VALUES (?1, ?2)")
                .map_err(err)?;
            let mut input = tx
                .prepare_cached("INSERT INTO inputs VALUES (?1, ?2, ?3)")
                .map_err(err)?;
            for r in rows {
                let seq = int(r.seq)?;
                entry
                    .execute(params![
                        seq,
                        r.hash,
                        r.id,
                        r.ts,
                        r.kind,
                        r.phase,
                        r.status,
                        r.principal_kind,
                        r.principal_id,
                        r.action,
                        r.target,
                        r.subject,
                        r.rule_ref,
                        r.rule_version,
                        r.rule_result,
                        r.trace_id
                    ])
                    .map_err(err)?;
                line.execute(params![seq, r.line]).map_err(err)?;
                for (rf, v) in &r.inputs {
                    input.execute(params![seq, rf, v]).map_err(err)?;
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO state VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    state.stream,
                    int(state.seq)?,
                    state.hash,
                    state.checkpoint.map(int).transpose()?
                ],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }

    fn query(&self, f: &Filter, limit: usize) -> io::Result<Vec<Hit>> {
        let mut sql = String::from(
            "SELECT seq, hash, (SELECT line FROM lines WHERE lines.seq = entries.seq) FROM entries WHERE seq > ",
        );
        let mut args = vec![Value::Integer(int(f.after)?)];
        // ts is claimed by the writer and may step back, so it is not ordered by seq; but the
        // first and last seq in the time range, found through the ts index, bound the scan.
        match &f.since {
            Some(s) => {
                sql.push_str(
                    "max(?, (SELECT coalesce(min(seq) - 1, 9223372036854775806) FROM entries INDEXED BY entries_ts WHERE ts >= ?)) AND ts >= ?",
                );
                args.extend([Value::Text(s.clone()), Value::Text(s.clone())]);
            }
            None => sql.push('?'),
        }
        if let Some(u) = &f.until {
            sql.push_str(
                " AND seq <= (SELECT coalesce(max(seq), 0) FROM entries INDEXED BY entries_ts WHERE ts < ?) AND ts < ?",
            );
            args.extend([Value::Text(u.clone()), Value::Text(u.clone())]);
        }
        // Each equality filter: its columns and values, all held by one index ending in seq.
        let text = |v: &str| Value::Text(v.to_owned());
        let mut filters: Vec<(&str, Vec<&str>, Vec<Value>)> = vec![];
        for (col, v) in [
            ("action", &f.action),
            ("target", &f.target),
            ("subject", &f.subject),
            ("trace_id", &f.trace_id),
            ("status", &f.status),
        ] {
            if let Some(v) = v {
                filters.push(("entries", vec![col], vec![text(v)]));
            }
        }
        if let Some(p) = &f.principal {
            // A principal without a kind matches nothing, as in Filter::matches.
            let (k, id) = p.split_once(':').unwrap_or(("", p));
            filters.push((
                "entries",
                vec!["principal_id", "principal_kind"],
                vec![text(id), text(k)],
            ));
        }
        if let Some((r, v)) = &f.rule {
            let mut f = ("entries", vec!["rule_ref"], vec![text(r)]);
            if let Some(v) = v {
                f.1.push("rule_version");
                f.2.push(text(v));
            }
            filters.push(f);
        }
        for (r, v) in &f.inputs {
            let mut f = ("inputs", vec!["ref"], vec![text(r)]);
            if let Some(v) = v {
                f.1.push("version");
                f.2.push(text(v));
            }
            filters.push(f);
        }
        let cond = |cols: &[&str]| {
            cols.iter()
                .map(|c| format!("{c} = ?"))
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        if filters.len() >= 2 {
            // Intersected from the indexes alone: only the page's rows are read from the table.
            let sets: Vec<String> = filters
                .iter()
                .map(|(table, cols, _)| {
                    format!("SELECT seq FROM {table} WHERE {} AND seq > ?", cond(cols))
                })
                .collect();
            sql.push_str(&format!(" AND seq IN ({})", sets.join(" INTERSECT ")));
            for (_, _, vals) in filters {
                args.extend(vals);
                args.push(Value::Integer(int(f.after)?));
            }
        } else {
            // One filter: walk its index in seq order and stop at the page's end.
            for (table, cols, vals) in filters {
                match table {
                    "entries" => sql.push_str(&format!(" AND {}", cond(&cols))),
                    _ => sql.push_str(&format!(
                        " AND seq IN (SELECT seq FROM {table} WHERE {})",
                        cond(&cols)
                    )),
                }
                args.extend(vals);
            }
        }
        sql.push_str(" ORDER BY seq LIMIT ?");
        args.push(Value::Integer(int(limit.min(i64::MAX as usize) as u64)?));
        let mut stmt = self.0.prepare_cached(&sql).map_err(err)?;
        let rows = stmt
            .query_map(params_from_iter(args), |r| {
                Ok(Hit {
                    seq: r.get::<_, i64>(0)? as u64,
                    hash: r.get(1)?,
                    line: r.get(2)?,
                })
            })
            .map_err(err)?;
        rows.collect::<Result<_, _>>().map_err(err)
    }

    fn erase(&mut self, subject: &str) -> io::Result<()> {
        // Freed pages are zeroed, and the WAL is emptied after, so the rows do not linger in the
        // file; copies on copy-on-write disks, snapshots or backups may survive.
        self.0
            .pragma_update(None, "secure_delete", true)
            .map_err(err)?;
        let tx = self.0.transaction().map_err(err)?;
        for table in ["inputs", "lines"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE seq IN (SELECT seq FROM entries WHERE subject = ?1)"
                ),
                [subject],
            )
            .map_err(err)?;
        }
        tx.execute("DELETE FROM entries WHERE subject = ?1", [subject])
            .map_err(err)?;
        tx.commit().map_err(err)?;
        // A reader holding the WAL leaves it in place; the next checkpoint overwrites it.
        self.0
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .map_err(err)
    }

    fn clear(&mut self) -> io::Result<()> {
        self.0
            .execute_batch(
                "DELETE FROM inputs; DELETE FROM lines; DELETE FROM entries; DELETE FROM state;",
            )
            .map_err(err)
    }
}
