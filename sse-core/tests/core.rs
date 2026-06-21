use sse_core::{RiskLevel, SseSecurityPolicy, WebAccessAction};

#[test]
fn risk_level_score_floor() {
    assert_eq!(RiskLevel::High.score_floor(), 75);
}

#[test]
fn security_policy_defaults() {
    let policy = SseSecurityPolicy::new("default");
    assert!(policy.enabled);
    assert_eq!(policy.min_risk_level, RiskLevel::Medium);
}

#[test]
fn web_access_action_variants_exist() {
    let _ = WebAccessAction::Allow;
    let _ = WebAccessAction::Block;
}
