//! OpenTelemetry correlation (tenbri-writer's `otel` feature): trace ids go from the active span
//! into the entry and back out through a query, and appends and verifies emit spans.

use opentelemetry::context::FutureExt;
use opentelemetry::trace::{TraceContextExt, Tracer};
use opentelemetry::{Context, Value, global};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tenbri_core::{Action, Entry, Kind, Principal, PrincipalKind, Status, Trace};
use tenbri_testkit::{Match, TestStream};
use tenbri_writer::{Lane, LaneConfig};

fn reply(ticket: &str) -> Entry {
    Entry {
        principal: Some(Principal {
            kind: PrincipalKind::Agent,
            id: "support".into(),
        }),
        action: Some(Action {
            r#type: "reply_ticket".into(),
            target: Some(ticket.into()),
        }),
        ..Entry::new(Kind::Decision)
    }
}

fn attr<'a>(s: &'a SpanData, key: &str) -> Option<&'a Value> {
    s.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| &kv.value)
}

// One test: the tracer provider is global to the process.
#[tokio::test]
async fn trace_ids_round_trip_and_tenbri_emits_spans() {
    let kit = TestStream::new().await;
    let mut log = kit.writer().await;

    // Without an active span, an entry has no trace, and nothing is exported anywhere.
    let none = log.intent(reply("ticket:0")).await.unwrap();
    assert_eq!(none.trace, None);

    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    global::set_tracer_provider(provider.clone());

    // The agent's span: Writer and Lane put its ids on what they append inside it.
    let cx = Context::current_with_span(global::tracer("agent").start("handle_ticket"));
    let sc = cx.span().span_context().clone();
    let want = Trace {
        trace_id: sc.trace_id().to_string(),
        span_id: sc.span_id().to_string(),
    };
    let intent = log
        .intent(reply("ticket:1"))
        .with_context(cx.clone())
        .await
        .unwrap();
    assert_eq!(intent.trace.as_ref(), Some(&want));
    log.outcome(&none, Status::Ok).await.unwrap();
    drop(log);

    let lane = Lane::spawn(kit.writer().await, LaneConfig::default());
    let outcome = lane
        .outcome(&intent, Status::Ok)
        .with_context(cx.clone())
        .await
        .unwrap();
    assert_eq!(outcome.trace.as_ref(), Some(&want));

    // A trace the caller set is kept.
    let other = Trace {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
    };
    let own = lane
        .intent(Entry {
            trace: Some(other.clone()),
            ..reply("ticket:2")
        })
        .with_context(cx.clone())
        .await
        .unwrap();
    assert_eq!(own.trace, Some(other));
    lane.outcome(&own, Status::Error).await.unwrap();
    lane.flush().await;

    // Back out: the decision by its trace id, intent and outcome, signed and verified.
    let d = kit.assert_decision(Match::default().trace_id(&want.trace_id));
    assert_eq!(d.intent.unwrap().id, intent.id);
    assert_eq!(d.outcome.unwrap().trace, Some(want.clone()));
    kit.assert_every_intent_has_outcome();
    async { kit.assert_verifies().await }
        .with_context(cx.clone())
        .await;

    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let appends: Vec<&SpanData> = spans.iter().filter(|s| s.name == "tenbri.append").collect();
    // Five appends after the provider was installed, three of them inside the agent's span.
    assert_eq!(appends.len(), 5, "{spans:#?}");
    let traced: Vec<&&SpanData> = appends
        .iter()
        .filter(|s| s.parent_span_id == sc.span_id())
        .collect();
    assert_eq!(traced.len(), 3);
    for s in &traced {
        assert_eq!(s.span_context.trace_id(), sc.trace_id());
        let e = s.events.iter().find(|e| e.name == "tenbri.entry").unwrap();
        let get = |k: &str| {
            e.attributes
                .iter()
                .find(|kv| kv.key.as_str() == k)
                .map(|kv| kv.value.to_string())
        };
        assert!(
            [&intent.id, &outcome.id, &own.id]
                .map(|i| Some(i.clone()))
                .contains(&get("tenbri.entry.id"))
        );
        assert_eq!(get("tenbri.verification").as_deref(), Some("verified"));
    }
    let verify = spans.iter().find(|s| s.name == "tenbri.verify").unwrap();
    assert_eq!(verify.parent_span_id, sc.span_id());
    assert_eq!(
        attr(verify, "tenbri.verification")
            .map(Value::to_string)
            .as_deref(),
        Some("verified")
    );
    assert_eq!(attr(verify, "tenbri.entries"), Some(&Value::I64(8)));
}
