use threat_protection::{ThreatFeed, ThreatProtectionEngine};
use uuid::Uuid;

#[test]
fn registers_feeds() {
    let engine = ThreatProtectionEngine::new();
    engine.register_feed(ThreatFeed {
        id: Uuid::new_v4(),
        name: "test-feed".into(),
        provider: "mock".into(),
        enabled: true,
        last_sync_at: None,
        indicator_count: 0,
    });
    assert_eq!(engine.feeds().len(), 1);
}

#[test]
fn no_match_for_unknown() {
    let engine = ThreatProtectionEngine::new();
    assert!(engine.check("safe.test", false).unwrap().is_none());
}
