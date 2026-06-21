use browser_isolation::{BrowserIsolationEngine, IsolationMode, IsolationPolicy};
use uuid::Uuid;

#[test]
fn policy_overrides_default_mode() {
    let engine = BrowserIsolationEngine::new(IsolationMode::Remote);
    let mut policy = IsolationPolicy::new("readonly-unknown", IsolationMode::ReadOnly);
    policy.target_domains.push("unknown.test".into());
    engine.add_policy(policy);

    assert_eq!(
        engine.resolve_mode("https://unknown.test/page"),
        IsolationMode::ReadOnly
    );
}

#[test]
fn terminate_session_sets_end_time() {
    let engine = BrowserIsolationEngine::new(IsolationMode::Containerized);
    let session = engine
        .start_session(Uuid::new_v4(), "https://app.test")
        .unwrap();
    let terminated = engine.terminate_session(session.id).unwrap();
    assert!(terminated.ended_at.is_some());
}
