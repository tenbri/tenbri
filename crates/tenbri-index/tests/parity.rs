//! The index answers what a scan answers: on generated rows and filters, SQLite, Parquet and
//! `Filter::matches` over every row agree, page by page.

use std::path::PathBuf;

use proptest::prelude::*;
use tenbri_index::{Backend, Filter, Kind, Row, State, open, search};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-index-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn pick(pool: &'static [&'static str]) -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::sample::select(pool).prop_map(str::to_owned))
}

const ACTIONS: &[&str] = &["reply_ticket", "issue_refund", "close"];
const IDS: &[&str] = &["agent:a", "agent:b", "person:a", "service:x"];
const TARGETS: &[&str] = &["t:1", "t:2"];
const SUBJECTS: &[&str] = &["s1", "s2"];
const REFS: &[&str] = &["policy:refund", "doc:faq", "ticket:1"];
const VERSIONS: &[&str] = &["13", "14"];
const STATUS: &[&str] = &["ok", "error", "refused", "unknown"];
const TRACES: &[&str] = &[
    "0af7651916cd43dd8448eb211c80319c",
    "4bf92f3577b34da6a3ce929d0e0e4736",
];
const DAYS: &[&str] = &["2026-10-18", "2026-10-19", "2026-10-20"];

/// A row without its seq, hash and line, which follow from its place in the stream.
fn row() -> impl Strategy<Value = Row> {
    (
        (pick(ACTIONS), pick(IDS), pick(TARGETS), pick(SUBJECTS)),
        (pick(STATUS), pick(TRACES), pick(REFS), pick(VERSIONS)),
        prop::collection::vec(
            (prop::sample::select(REFS), prop::sample::select(VERSIONS)),
            0..3,
        ),
        (0usize..3, 0u32..86_400),
    )
        .prop_map(
            |(
                (action, principal, target, subject),
                (status, trace, rule_ref, rule_v),
                inputs,
                (day, s),
            )| {
                let (pk, pid) = principal
                    .map(|p| {
                        let (k, i) = p.split_once(':').unwrap();
                        (Some(k.to_owned()), Some(i.to_owned()))
                    })
                    .unwrap_or_default();
                Row {
                    ts: format!(
                        "{}T{:02}:{:02}:{:02}.000Z",
                        DAYS[day],
                        s / 3600,
                        s / 60 % 60,
                        s % 60
                    ),
                    kind: "decision".into(),
                    phase: Some("intent".into()),
                    status,
                    principal_kind: pk,
                    principal_id: pid,
                    action,
                    target,
                    subject,
                    rule_version: rule_ref.as_ref().map(|_| rule_v.unwrap_or("1".into())),
                    rule_ref,
                    rule_result: Some("allow".into()),
                    trace_id: trace,
                    inputs: inputs
                        .into_iter()
                        .map(|(r, v)| (r.to_owned(), v.to_owned()))
                        .collect(),
                    ..Row::default()
                }
            },
        )
}

type Ref = (String, Option<String>);
type FilterParts = (
    (Vec<Ref>, Option<String>, Option<String>, Option<String>),
    (Option<String>, Option<Ref>, Option<String>, Option<String>),
    (Option<String>, Option<String>, u64),
);

fn make_filter(parts: FilterParts) -> Filter {
    let (
        (inputs, action, principal, target),
        (subject, rule, trace_id, status),
        (since, until, after),
    ) = parts;
    Filter {
        inputs,
        action,
        principal,
        target,
        subject,
        rule,
        since: since.map(|d| format!("{d}T06:00:00.000Z")),
        until: until.map(|d| format!("{d}T18:00:00.000Z")),
        trace_id,
        status,
        after,
    }
}

fn filter() -> impl Strategy<Value = Filter> {
    let rv = || (prop::sample::select(REFS), pick(VERSIONS)).prop_map(|(r, v)| (r.to_owned(), v));
    (
        (
            prop::collection::vec(rv(), 0..2),
            pick(ACTIONS),
            pick(IDS),
            pick(TARGETS),
        ),
        (
            pick(SUBJECTS),
            prop::option::of(rv()),
            pick(TRACES),
            pick(STATUS),
        ),
        (pick(DAYS), pick(DAYS), 0u64..40),
    )
        .prop_map(make_filter)
}

/// Every hit of `f`, following `next` a page of `page` at a time.
fn all(ix: &dyn Backend, f: &Filter, page: usize) -> Vec<u64> {
    let mut f = f.clone();
    let mut out = vec![];
    loop {
        let p = search(ix, &f, page).unwrap();
        out.extend(p.hits.iter().map(|h| h.seq));
        assert!(p.hits.len() <= page);
        match p.next {
            Some(n) => f.after = n,
            None => return out,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn index_matches_a_scan(
        rows in prop::collection::vec(row(), 1..60),
        filters in prop::collection::vec(filter(), 1..16),
        split in 0usize..60,
        page in 1usize..8,
    ) {
        let rows: Vec<Row> = rows
            .into_iter()
            .enumerate()
            .map(|(i, r)| Row {
                seq: i as u64 + 1,
                hash: format!("sha256:{:064x}", i + 1),
                id: format!("id{i}"),
                line: format!("{{\"seq\":{}}}", i + 1),
                ..r
            })
            .collect();
        let state = |n: usize| State {
            stream: "tnb1:00000000000000000000000000000000".into(),
            seq: n as u64,
            hash: rows[n - 1].hash.clone(),
            checkpoint: None,
        };
        let dir = tmp("parity");
        let mut ixs = vec![];
        for kind in [Kind::Sqlite, Kind::Parquet] {
            let mut ix = open(kind, &dir.join(kind.to_string())).unwrap();
            ix.clear().unwrap();
            // Two appends, as incremental updates make them.
            let split = split.clamp(1, rows.len());
            ix.append(&rows[..split], &state(split)).unwrap();
            ix.append(&rows[split..], &state(rows.len())).unwrap();
            prop_assert_eq!(ix.state().unwrap(), Some(state(rows.len())));
            ixs.push(ix);
        }
        for f in &filters {
            let scan: Vec<u64> = rows.iter().filter(|r| f.matches(r)).map(|r| r.seq).collect();
            for ix in &ixs {
                prop_assert_eq!(&all(ix.as_ref(), f, page), &scan, "{} {:?}", ix.kind(), f);
            }
            // Hits carry the row's hash and line.
            for h in search(ixs[0].as_ref(), f, 1000).unwrap().hits {
                let r = &rows[h.seq as usize - 1];
                prop_assert_eq!((&h.hash, &h.line), (&r.hash, &r.line));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Many small appends to a Parquet index get merged, and the answers stay the same.
#[test]
fn parquet_compacts_small_files() {
    let dir = tmp("compact");
    let mut ix = open(Kind::Parquet, &dir).unwrap();
    for seq in 1..=40u64 {
        let r = Row {
            seq,
            hash: format!("h{seq}"),
            id: format!("id{seq}"),
            ts: "2026-10-20T00:00:00.000Z".into(),
            kind: "note".into(),
            action: Some(if seq % 2 == 0 { "even" } else { "odd" }.into()),
            line: format!("l{seq}"),
            ..Row::default()
        };
        let st = State {
            stream: "s".into(),
            seq,
            hash: r.hash.clone(),
            checkpoint: None,
        };
        ix.append(&[r], &st).unwrap();
    }
    let files = std::fs::read_dir(dir.join("parquet"))
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().extension().unwrap() == "parquet")
        .count();
    assert!(files <= 17, "{files} files");
    let f = Filter {
        action: Some("even".into()),
        ..Filter::default()
    };
    assert_eq!(
        all(ix.as_ref(), &f, 7),
        (2..=40).step_by(2).collect::<Vec<_>>()
    );
    // Reopened from its manifest.
    drop(ix);
    let ix = tenbri_index::find(&dir).unwrap().unwrap();
    assert_eq!(ix.kind(), Kind::Parquet);
    assert_eq!(ix.state().unwrap().unwrap().seq, 40);
    assert_eq!(all(ix.as_ref(), &f, 100).len(), 20);
    let _ = std::fs::remove_dir_all(&dir);
}
