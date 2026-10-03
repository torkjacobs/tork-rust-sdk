//! S01: every declared PII type has a working pattern with a positive and a
//! negative example, and the optional agent telemetry fields pass through.

use tork_governance::*;

fn detects(text: &str, t: PIIType) -> bool {
    detect_pii(text).types.contains(&t)
}

// (type, positive example, negative example)
fn cases() -> Vec<(PIIType, &'static str, &'static str)> {
    vec![
        (
            PIIType::Ssn,
            "SSN 123-45-6789 on file",
            "ref 123-456-789 only",
        ),
        (
            PIIType::CreditCard,
            "card 4111-1111-1111-1111",
            "card 4111-1111-111",
        ),
        (
            PIIType::Email,
            "mail john@example.com now",
            "mail john at example dot com",
        ),
        (PIIType::Phone, "call 555-123-4567", "call 55-12"),
        (
            PIIType::Address,
            "lives at 123 Main Street",
            "lives on Main Street",
        ),
        (
            PIIType::IpAddress,
            "host 192.168.1.1 up",
            "host 999.999.999.999 up",
        ),
        (PIIType::DateOfBirth, "born 01/15/1990", "born 13/45/1990"),
        (PIIType::Passport, "passport AB1234567", "passport 1234567"),
        (
            PIIType::DriversLicense,
            "licence D1234567",
            "licence 1234567",
        ),
        (PIIType::BankAccount, "acct 12345678901234", "acct 1234567"),
    ]
}

#[test]
fn every_declared_type_has_positive_and_negative_example() {
    let cases = cases();
    for t in PIIType::all() {
        assert!(
            cases.iter().any(|(ct, _, _)| *ct == t),
            "no test case for {t:?}"
        );
    }
    for (t, pos, neg) in cases {
        assert!(detects(pos, t), "{t:?} should detect: {pos}");
        assert!(!detects(neg, t), "{t:?} should NOT detect: {neg}");
    }
}

fn ctx() -> SessionContext {
    SessionContext {
        agent_id: Some("agent-1".into()),
        agent_role: Some("planner".into()),
        session_id: Some("sess-9".into()),
        session_turn: Some(3),
    }
}

#[test]
fn session_fields_pass_through_when_set() {
    let mut tork = Tork::new();
    let r = tork.govern_with_options(
        "hello",
        GovernOptions {
            session_context: Some(ctx()),
            ..Default::default()
        },
    );
    let sc = r.session_context.clone().unwrap();
    assert_eq!(sc.agent_id.as_deref(), Some("agent-1"));
    assert_eq!(sc.agent_role.as_deref(), Some("planner"));
    assert_eq!(sc.session_id.as_deref(), Some("sess-9"));
    assert_eq!(sc.session_turn, Some(3));
    let v = serde_json::to_value(&r.receipt).unwrap();
    assert_eq!(v["session_context"]["agent_id"], "agent-1");
    assert_eq!(v["session_context"]["session_turn"], 3);
    assert!(v["session_context"]["session_turn"].is_u64());
}

#[test]
fn session_fields_omitted_when_unset() {
    let mut tork = Tork::new();
    let r = tork.govern("hello");
    let v = serde_json::to_value(&r).unwrap();
    assert!(v.get("session_context").is_none());
    assert!(serde_json::to_value(&r.receipt)
        .unwrap()
        .get("session_context")
        .is_none());

    let partial = SessionContext {
        session_id: Some("s".into()),
        ..Default::default()
    };
    let v = serde_json::to_value(&partial).unwrap();
    assert_eq!(v["session_id"], "s");
    assert!(v.get("agent_id").is_none());
    assert!(v.get("agent_role").is_none());
    assert!(v.get("session_turn").is_none());
}
