use dlp::{detect_patterns, luhn_valid, DlpAction, DlpEngine, DlpPatternKind, DlpPolicy};

#[test]
fn luhn_rejects_invalid() {
    assert!(!luhn_valid("4111111111111112"));
}

#[test]
fn engine_blocks_credit_card() {
    let engine = DlpEngine::new();
    let mut policy = DlpPolicy::new("pci");
    policy.patterns = vec![DlpPatternKind::CreditCard];
    policy.action = DlpAction::Block;
    engine.add_policy(policy);

    let incidents = engine
        .scan("card: 4111 1111 1111 1111", "web", None)
        .unwrap();
    assert!(!incidents.is_empty());
}

#[test]
fn detect_patterns_finds_email() {
    let matches = detect_patterns("contact user@example.com today");
    assert!(matches.iter().any(|m| m.kind == DlpPatternKind::Email));
}
