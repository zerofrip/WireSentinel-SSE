use std::collections::HashMap;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{BehaviorAnomaly, CasbFinding, DlpIncident, RiskLevel, RiskScore, ThreatMatch};
use sse_core::SseResult;

/// Synthesizes continuous risk scores from UEBA, threat, DLP, and CASB inputs.
pub struct ContinuousRiskEngine {
    scores: RwLock<HashMap<Uuid, RiskScore>>,
    threshold: u8,
}

impl ContinuousRiskEngine {
    pub fn new(threshold: u8) -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
            threshold,
        }
    }

    pub fn compute(
        &self,
        subject_id: Uuid,
        ueba: u8,
        threat: u8,
        dlp: u8,
        casb: u8,
    ) -> SseResult<RiskScore> {
        let score = ((ueba as u16 + threat as u16 + dlp as u16 + casb as u16) / 4) as u8;
        let level = level_for_score(score);
        let risk = RiskScore {
            subject_id,
            score,
            level,
            ueba_contribution: ueba,
            threat_contribution: threat,
            dlp_contribution: dlp,
            casb_contribution: casb,
            computed_at: Utc::now(),
        };
        self.scores.write().insert(subject_id, risk.clone());
        Ok(risk)
    }

    pub fn synthesize_from_signals(
        &self,
        subject_id: Uuid,
        anomalies: &[BehaviorAnomaly],
        threats: &[ThreatMatch],
        dlp_incidents: &[DlpIncident],
        casb_findings: &[CasbFinding],
    ) -> SseResult<RiskScore> {
        let ueba = anomalies
            .iter()
            .filter(|a| a.subject_id == subject_id)
            .map(|a| severity_to_score(a.severity))
            .max()
            .unwrap_or(0);
        let threat = threats
            .iter()
            .map(|t| severity_to_score(t.indicator.severity))
            .max()
            .unwrap_or(0);
        let dlp = if dlp_incidents.is_empty() { 0 } else { 70 };
        let casb = if casb_findings.is_empty() { 0 } else { 50 };
        self.compute(subject_id, ueba, threat, dlp, casb)
    }

    pub fn get(&self, subject_id: Uuid) -> Option<RiskScore> {
        self.scores.read().get(&subject_id).cloned()
    }

    pub fn exceeds_threshold(&self, score: &RiskScore) -> bool {
        score.score >= self.threshold
    }

    pub fn elevated(&self, subject_id: Uuid, previous: RiskLevel) -> bool {
        self.get(subject_id)
            .map(|s| s.level > previous)
            .unwrap_or(false)
    }
}

impl Default for ContinuousRiskEngine {
    fn default() -> Self {
        Self::new(75)
    }
}

fn level_for_score(score: u8) -> RiskLevel {
    match score {
        0..=24 => RiskLevel::Minimal,
        25..=49 => RiskLevel::Low,
        50..=74 => RiskLevel::Medium,
        75..=89 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

fn severity_to_score(level: RiskLevel) -> u8 {
    level.score_floor()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_weighted_score() {
        let engine = ContinuousRiskEngine::new(75);
        let score = engine
            .compute(Uuid::new_v4(), 80, 90, 70, 60)
            .unwrap();
        assert_eq!(score.score, 75);
        assert_eq!(score.level, RiskLevel::High);
    }
}
