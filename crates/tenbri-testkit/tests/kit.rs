//! The test kit catches what it promises to: a missing outcome, a missing decision, tampering.

use tenbri_core::{Action, Entry, Kind, Principal, PrincipalKind, Rule, Status};
use tenbri_testkit::{Match, TestStream, check, input};

fn refund(order: &str) -> Entry {
    Entry {
        principal: Some(Principal {
            kind: PrincipalKind::Agent,
            id: "support".into(),
        }),
        action: Some(Action {
            r#type: "issue_refund".into(),
            target: Some(order.into()),
        }),
        inputs: Some(vec![input("policy:refund", "14")]),
        rule: Some(Rule {
            r#ref: "refund-limit".into(),
            version: "3".into(),
            result: "deny".into(),
        }),
        ..Entry::new(Kind::Decision)
    }
}

/// An agent that refuses one refund and leaves another one open.
async fn record(kit: &TestStream) {
    let mut log = kit.writer().await;
    let a = log.intent(refund("order:1")).await.unwrap();
    log.outcome(&a, Status::Refused).await.unwrap();
    log.intent(refund("order:2")).await.unwrap();
}

#[tokio::test]
async fn finds_decisions_by_action_input_rule_principal_and_status() {
    let kit = TestStream::new().await;
    record(&kit).await;
    let d = kit.assert_decision(
        Match::default()
            .action("issue_refund")
            .input("policy:refund@14")
            .rule("refund-limit@3")
            .principal("agent:support")
            .status(Status::Refused),
    );
    assert_eq!(d.intent.unwrap().action.unwrap().target.unwrap(), "order:1");
    kit.assert_decision(Match::default().input("policy:refund").target("order:2"));

    let entries = kit.entries();
    for m in [
        Match::default().action("reply_ticket"),
        Match::default().input("policy:refund@13"),
        Match::default().target("order:2").status(Status::Ok),
        Match::default().principal("person:support"),
    ] {
        let f = check::decision(&entries, &m).unwrap_err();
        assert!(f.0.contains("issue_refund (refused"), "{f}");
        assert!(f.0.contains("issue_refund (no outcome"), "{f}");
    }
}

#[tokio::test]
async fn catches_an_intent_without_an_outcome() {
    let kit = TestStream::new().await;
    record(&kit).await;
    let f = check::every_intent_has_outcome(&kit.entries()).unwrap_err();
    assert!(f.0.starts_with("1 intent(s) without an outcome"), "{f}");

    // A reconcile entry closes the intent in the stream, but the outcome never came.
    let mut log = kit.writer().await;
    kit.clock().advance(2 * 3_600_000);
    let r = log
        .reconcile_stale(kit.clock().now_ms(), 3_600_000, None)
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert!(check::every_intent_has_outcome(&kit.entries()).is_err());

    let open = kit.assert_decision(Match::default().target("order:2"));
    log.outcome(open.intent.as_ref().unwrap(), Status::Ok)
        .await
        .unwrap();
    kit.assert_every_intent_has_outcome();
    kit.assert_verifies().await;
}

#[tokio::test]
#[should_panic(expected = "without an outcome")]
async fn assert_every_intent_has_outcome_panics() {
    let kit = TestStream::new().await;
    record(&kit).await;
    kit.assert_every_intent_has_outcome();
}

#[tokio::test]
async fn catches_tampering() {
    let kit = TestStream::new().await;
    record(&kit).await;
    assert_eq!(kit.assert_verifies().await.entries, 5);

    // The refusal becomes an approval of the refund.
    kit.tamper(4, |e| e["status"] = "ok".into());
    assert_eq!(
        kit.assert_decision(Match::default().target("order:1"))
            .outcome
            .unwrap()
            .status,
        Some(Status::Ok)
    );
    let f = check::verifies(kit.store(), &kit.pin()).await.unwrap_err();
    assert!(f.0.contains("after 3 entries"), "{f}");
    assert!(f.0.contains("bad_signature"), "{f}");
}

#[tokio::test]
async fn the_same_test_writes_the_same_bytes() {
    let (a, b) = (TestStream::new().await, TestStream::new().await);
    record(&a).await;
    record(&b).await;
    for k in a.store().keys() {
        assert_eq!(a.store().bytes(&k), b.store().bytes(&k), "{k}");
    }
    assert_eq!(a.store().keys(), b.store().keys());
    assert_eq!(a.snapshot(), b.snapshot());
    a.assert_snapshot(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snapshots/record.jsonl"
    ));
}
