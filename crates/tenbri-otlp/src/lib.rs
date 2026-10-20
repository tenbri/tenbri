//! OpenTelemetry correlation for Tenbri: an entry's `trace` names the span that was active when it
//! was written, so a trace links to the signed decision and the decision back to the trace.
//!
//! - [`traceparent`]: the ids from a W3C `traceparent` header (tenbrid takes it on every append).
//! - With the `otel` feature: `current` and `from_context`, the active span's ids through the
//!   `opentelemetry` API, which `tenbri-writer`'s `otel` feature puts on every entry it appends
//!   without one; `Append` and `Verify`, Tenbri's own spans and metrics.
//!
//! Nothing here sends telemetry. The `opentelemetry` API is a no-op until the application installs
//! an SDK with an exporter (`opentelemetry::global::set_tracer_provider`), and Tenbri installs
//! none.
//!
//! Turning OpenTelemetry GenAI spans into entries (`tenbri ingest otlp`) is Experimental and not
//! here yet.

#[cfg(feature = "otel")]
mod otel;
#[cfg(feature = "otel")]
pub use otel::{Append, Verify, current, from_context};

pub use tenbri_core::Trace;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The W3C Trace Context `traceparent` header (<https://www.w3.org/TR/trace-context/>).
pub mod traceparent {
    use tenbri_core::Trace;
    use tenbri_core::encoding::unhex;

    /// The trace and parent span ids of a `traceparent` header, or `None` if it is not one: a
    /// receiver ignores an invalid header (W3C Trace Context, section 3.2).
    ///
    /// ```
    /// let t = tenbri_otlp::traceparent::parse(
    ///     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    /// )
    /// .unwrap();
    /// assert_eq!(t.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    /// assert_eq!(t.span_id, "00f067aa0ba902b7");
    /// assert!(tenbri_otlp::traceparent::parse("00-0000-00f067aa0ba902b7-01").is_none());
    /// ```
    pub fn parse(header: &str) -> Option<Trace> {
        let mut parts = header.trim().split('-');
        let (version, trace_id, span_id, flags) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        let version = unhex::<1>(version)?[0];
        // Version 00 has exactly four fields; a later version may add more after them.
        if version == 0xff || (version == 0 && parts.next().is_some()) {
            return None;
        }
        unhex::<1>(flags)?;
        let t = unhex::<16>(trace_id)?;
        let s = unhex::<8>(span_id)?;
        (t != [0; 16] && s != [0; 8]).then(|| Trace {
            trace_id: trace_id.to_owned(),
            span_id: span_id.to_owned(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::parse;

        #[test]
        fn takes_valid_headers_and_ignores_the_rest() {
            let ok = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
            assert!(parse(ok).is_some());
            assert!(parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-x").is_some());
            for bad in [
                "",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
                "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            ] {
                assert!(parse(bad).is_none(), "{bad}");
            }
        }
    }
}
