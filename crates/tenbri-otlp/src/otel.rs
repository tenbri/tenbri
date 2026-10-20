//! The active span's ids, and Tenbri's own spans and metrics, through the `opentelemetry` API.

use std::fmt::Display;
use std::time::Instant;

use opentelemetry::trace::{Span, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};
use tenbri_core::{Broken, Entry, Kind, Trace};

/// The instrumentation scope of Tenbri's spans and metrics.
const SCOPE: &str = "tenbri";

/// The ids of the span active in `cx`, if it has a valid one.
///
/// With `tracing-opentelemetry`, the active `tracing` span is not OpenTelemetry's current context:
/// pass `tracing::Span::current().context()`.
pub fn from_context(cx: &Context) -> Option<Trace> {
    let span = cx.span();
    let sc = span.span_context();
    sc.is_valid().then(|| Trace {
        trace_id: sc.trace_id().to_string(),
        span_id: sc.span_id().to_string(),
    })
}

/// The ids of the span active now ([`Context::current`]), if there is one.
///
/// ```
/// use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
/// use opentelemetry::Context;
///
/// assert!(tenbri_otlp::current().is_none());
/// let sc = SpanContext::new(
///     TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
///     SpanId::from_hex("00f067aa0ba902b7").unwrap(),
///     TraceFlags::SAMPLED,
///     true,
///     TraceState::default(),
/// );
/// let _active = Context::current().with_remote_span_context(sc).attach();
/// let t = tenbri_otlp::current().unwrap();
/// assert_eq!((t.trace_id.as_str(), t.span_id.as_str()), ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"));
/// ```
pub fn current() -> Option<Trace> {
    from_context(&Context::current())
}

fn kind(k: Kind) -> &'static str {
    match k {
        Kind::Decision => "decision",
        Kind::Approval => "approval",
        Kind::Key => "key",
        Kind::Reconcile => "reconcile",
        Kind::Note => "note",
    }
}

// ponytail: instruments are looked up on every append and verify, so a meter provider installed
// after the first one still sees them; cache them if that lookup ever shows in a profile.

/// A `tenbri.append` span, a child of the active span, around one append of a batch. When it ends
/// it records one `tenbri.entry` event per entry written (its id, seq, kind and `tenbri.verification`:
/// `verified`, as the writer checks every entry against the stream before it signs it), or
/// `tenbri.entry.rejected` with the reason, and the metrics `tenbri.entries` (by
/// `tenbri.result`: `written` or `failed`) and `tenbri.append.duration` (seconds).
pub struct Append {
    span: global::BoxedSpan,
    start: Instant,
}

impl Append {
    pub fn start(entries: usize) -> Append {
        let mut span = global::tracer(SCOPE).start("tenbri.append");
        span.set_attribute(KeyValue::new("tenbri.entries", entries as i64));
        Append {
            span,
            start: Instant::now(),
        }
    }

    pub fn end<E: Display>(mut self, results: &[Result<Entry, E>]) {
        let (mut written, mut failed) = (0u64, 0u64);
        for r in results {
            match r {
                Ok(e) => {
                    written += 1;
                    self.span.add_event(
                        "tenbri.entry",
                        vec![
                            KeyValue::new("tenbri.entry.id", e.id.clone()),
                            KeyValue::new("tenbri.entry.seq", e.seq as i64),
                            KeyValue::new("tenbri.entry.kind", kind(e.kind)),
                            KeyValue::new("tenbri.stream", e.stream.clone()),
                            KeyValue::new("tenbri.verification", "verified"),
                        ],
                    );
                }
                Err(err) => {
                    failed += 1;
                    self.span.add_event(
                        "tenbri.entry.rejected",
                        vec![KeyValue::new("tenbri.error", err.to_string())],
                    );
                }
            }
        }
        if failed > 0 {
            self.span
                .set_status(Status::error(format!("{failed} entries not written")));
        }
        self.span.end();
        let meter = global::meter(SCOPE);
        let entries = meter
            .u64_counter("tenbri.entries")
            .with_unit("{entry}")
            .with_description("Entries appended, by result")
            .build();
        entries.add(written, &[KeyValue::new("tenbri.result", "written")]);
        entries.add(failed, &[KeyValue::new("tenbri.result", "failed")]);
        meter
            .f64_histogram("tenbri.append.duration")
            .with_unit("s")
            .with_description("Time to make a batch durable")
            .build()
            .record(self.start.elapsed().as_secs_f64(), &[]);
    }
}

/// A `tenbri.verify` span, a child of the active span, around one verification of a stream, and
/// the metric `tenbri.verify.duration` (seconds, by `tenbri.verification`: `verified` or
/// `broken`).
pub struct Verify {
    span: global::BoxedSpan,
    start: Instant,
}

impl Verify {
    pub fn start() -> Verify {
        Verify {
            span: global::tracer(SCOPE).start("tenbri.verify"),
            start: Instant::now(),
        }
    }

    pub fn end(mut self, stream: Option<&str>, entries: u64, broken: Option<&Broken>) {
        if let Some(s) = stream {
            self.span
                .set_attribute(KeyValue::new("tenbri.stream", s.to_owned()));
        }
        self.span
            .set_attribute(KeyValue::new("tenbri.entries", entries as i64));
        let verification = if let Some(b) = broken {
            self.span
                .set_attribute(KeyValue::new("tenbri.broken.seq", b.seq as i64));
            self.span
                .set_attribute(KeyValue::new("tenbri.broken.code", b.error.code.as_str()));
            self.span.set_status(Status::error(b.to_string()));
            "broken"
        } else {
            "verified"
        };
        self.span
            .set_attribute(KeyValue::new("tenbri.verification", verification));
        self.span.end();
        global::meter(SCOPE)
            .f64_histogram("tenbri.verify.duration")
            .with_unit("s")
            .with_description("Time to verify a stream")
            .build()
            .record(
                self.start.elapsed().as_secs_f64(),
                &[KeyValue::new("tenbri.verification", verification)],
            );
    }
}
