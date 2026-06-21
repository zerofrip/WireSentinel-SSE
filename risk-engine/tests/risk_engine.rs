use risk_engine::{ContinuousRiskEngine, RiskLevel};
use uuid::Uuid;

#[test]
fn threshold_detection() {
    let engine = ContinuousRiskEngine::new(80);
    let score = engine.compute(Uuid::new_v4(), 90, 90, 90, 90).unwrap();
    assert!(engine.exceeds_threshold(&score));
}

#[test]
fn minimal_score_for_clean_subject() {
    let engine = ContinuousRiskEngine::new(75);
    let score = engine.compute(Uuid::new_v4(), 0, 0, 0, 0).unwrap();
    assert_eq!(score.level, RiskLevel::Minimal);
}
