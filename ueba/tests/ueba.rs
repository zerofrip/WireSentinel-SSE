use ueba::UebaEngine;
use uuid::Uuid;

#[test]
fn establishes_baseline_on_first_observation() {
    let engine = UebaEngine::new();
    let subject = Uuid::new_v4();
    assert!(engine
        .observe_session(subject, 12, "app.example.com")
        .unwrap()
        .is_none());
    assert!(engine.baseline(subject).is_some());
}
