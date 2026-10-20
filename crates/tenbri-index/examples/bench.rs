//! Query latency of the SQLite and Parquet indexes on a generated stream.
//!
//! ```text
//! cargo run --release -p tenbri-index --example bench -- [entries, default 1000000] [dir]
//! ```
//!
//! Builds both indexes from the same rows (as `tenbri index rebuild` would, in chunks of 50,000),
//! then runs each query 20 times for a first page of 100 and prints the first run (that query's
//! pages not yet cached by SQLite), the median and the slowest.

use std::time::{Duration, Instant};

use tenbri_index::{Backend, Filter, Kind, Row, State, open, search};

fn row(seq: u64) -> Row {
    let n = seq as usize;
    // ~1,000 entries per minute from 2026-10-01: 1M entries span about 17 hours.
    let ms = 1_790_812_800_000 + seq as i64 * 60;
    let outcome = n % 2 == 0;
    Row {
        seq,
        hash: format!("sha256:{seq:064x}"),
        id: format!("01J{seq:023}"),
        ts: tenbri_core::encoding::format_ts(ms),
        kind: "decision".into(),
        phase: Some(if outcome { "outcome" } else { "intent" }.into()),
        status: outcome.then(|| ["ok", "ok", "ok", "error", "refused"][n / 2 % 5].into()),
        principal_kind: Some("agent".into()),
        principal_id: Some(format!("agent-{}", n % 50)),
        action: Some(format!("action_{}", n / 2 % 20)),
        target: Some(format!("zendesk:ticket/{}", n / 2 % 100_000)),
        subject: Some(format!("subj-{}", n / 2 % 10_000)),
        rule_ref: Some(format!("rule:{}", n / 2 % 10)),
        rule_version: Some(format!("{}", n / 2 % 7)),
        rule_result: Some("allow".into()),
        trace_id: Some(format!("{:032x}", n / 2)),
        inputs: vec![
            ("policy:refund".into(), format!("{}", 10 + n / 2 % 5)),
            (format!("doc:{}", n / 2 % 1_000), "1".into()),
        ],
        line: format!("{{\"seq\":{seq},\"padding\":\"{}\"}}", "x".repeat(400)),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: u64 = args.next().map_or(1_000_000, |a| a.parse().unwrap());
    let dir = args.next().map_or_else(
        || std::env::temp_dir().join(format!("tenbri-index-bench-{}", std::process::id())),
        Into::into,
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("{n} entries, first page of 100, 20 runs per query");

    let mid = n / 2;
    let f = Filter::default;
    let queries: Vec<(&str, Filter)> = vec![
        (
            "input policy:refund@14",
            Filter {
                inputs: vec![("policy:refund".into(), Some("14".into()))],
                ..f()
            },
        ),
        (
            "input doc:7 (rare)",
            Filter {
                inputs: vec![("doc:7".into(), None)],
                ..f()
            },
        ),
        (
            "action + status",
            Filter {
                action: Some("action_3".into()),
                status: Some("refused".into()),
                ..f()
            },
        ),
        (
            "principal",
            Filter {
                principal: Some("agent:agent-7".into()),
                ..f()
            },
        ),
        (
            "subject (rare)",
            Filter {
                subject: Some("subj-42".into()),
                ..f()
            },
        ),
        (
            "rule ref@version",
            Filter {
                rule: Some(("rule:3".into(), Some("2".into()))),
                ..f()
            },
        ),
        (
            "trace id (2 hits)",
            Filter {
                trace_id: Some(format!("{:032x}", mid / 2)),
                ..f()
            },
        ),
        (
            "last 10 minutes",
            Filter {
                since: Some(row(n - 10_000).ts),
                ..f()
            },
        ),
        (
            "input + status, last hr",
            Filter {
                inputs: vec![("policy:refund".into(), Some("12".into()))],
                status: Some("refused".into()),
                since: Some(row(n.saturating_sub(60_000).max(1)).ts),
                ..f()
            },
        ),
        (
            "page after mid-stream",
            Filter {
                action: Some("action_3".into()),
                after: mid,
                ..f()
            },
        ),
        (
            "no match",
            Filter {
                target: Some("nowhere".into()),
                ..f()
            },
        ),
    ];

    for kind in [Kind::Sqlite, Kind::Parquet] {
        let mut ix = open(kind, &dir.join(kind.to_string())).unwrap();
        let t = Instant::now();
        let mut seq = 0;
        while seq < n {
            let rows: Vec<Row> = (seq + 1..=(seq + 50_000).min(n)).map(row).collect();
            seq = rows.last().unwrap().seq;
            let st = State {
                stream: "tnb1:00000000000000000000000000000000".into(),
                seq,
                hash: rows.last().unwrap().hash.clone(),
                checkpoint: None,
            };
            ix.append(&rows, &st).unwrap();
        }
        println!("\n{kind}: built in {:.1?}", t.elapsed());
        println!(
            "{:<24} {:>6} {:>10} {:>10} {:>10}",
            "query", "hits", "first", "p50", "max"
        );
        for (name, q) in &queries {
            let (hits, first, p50, max) = time(ix.as_ref(), q);
            println!("{name:<24} {hits:>6} {first:>10.2?} {p50:>10.2?} {max:>10.2?}");
        }
    }
    if std::env::args().nth(2).is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn time(ix: &dyn Backend, q: &Filter) -> (usize, Duration, Duration, Duration) {
    let mut runs = vec![];
    let mut hits = 0;
    for _ in 0..20 {
        let t = Instant::now();
        hits = search(ix, q, 100).unwrap().hits.len();
        runs.push(t.elapsed());
    }
    let first = runs[0];
    runs.sort();
    (hits, first, runs[runs.len() / 2], runs[runs.len() - 1])
}
