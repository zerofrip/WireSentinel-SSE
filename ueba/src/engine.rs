use std::collections::HashMap;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{BehaviorAnomaly, BehaviorBaseline, RiskLevel};
use sse_core::SseResult;

/// UEBA engine maintaining baselines and detecting anomalies.
pub struct UebaEngine {
    baselines: RwLock<HashMap<Uuid, BehaviorBaseline>>,
    anomalies: RwLock<Vec<BehaviorAnomaly>>,
}

impl UebaEngine {
    pub fn new() -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            anomalies: RwLock::new(Vec::new()),
        }
    }

    pub fn establish_baseline(&self, baseline: BehaviorBaseline) {
        self.baselines.write().insert(baseline.subject_id, baseline);
    }

    pub fn baseline(&self, subject_id: Uuid) -> Option<BehaviorBaseline> {
        self.baselines.read().get(&subject_id).cloned()
    }

    pub fn observe_session(
        &self,
        subject_id: Uuid,
        hour: u8,
        destination: &str,
    ) -> SseResult<Option<BehaviorAnomaly>> {
        let baseline = match self.baseline(subject_id) {
            Some(b) => b,
            None => {
                self.establish_baseline(BehaviorBaseline {
                    subject_id,
                    avg_daily_sessions: 1.0,
                    typical_hours: vec![hour],
                    typical_destinations: vec![destination.into()],
                    established_at: Utc::now(),
                });
                return Ok(None);
            }
        };

        let hour_anomaly = !baseline.typical_hours.contains(&hour);
        let dest_anomaly = !baseline
            .typical_destinations
            .iter()
            .any(|d| destination.contains(d.as_str()));

        if !hour_anomaly && !dest_anomaly {
            return Ok(None);
        }

        let anomaly = BehaviorAnomaly {
            id: Uuid::new_v4(),
            subject_id,
            anomaly_type: if hour_anomaly {
                "unusual_hour".into()
            } else {
                "unusual_destination".into()
            },
            severity: if hour_anomaly && dest_anomaly {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            },
            detail: format!("observed {destination} at hour {hour}"),
            detected_at: Utc::now(),
        };
        self.anomalies.write().push(anomaly.clone());
        Ok(Some(anomaly))
    }

    pub fn recent_anomalies(&self, limit: usize) -> Vec<BehaviorAnomaly> {
        self.anomalies
            .read()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for UebaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unusual_hour() {
        let engine = UebaEngine::new();
        let subject = Uuid::new_v4();
        engine.establish_baseline(BehaviorBaseline {
            subject_id: subject,
            avg_daily_sessions: 5.0,
            typical_hours: vec![9, 10, 11],
            typical_destinations: vec!["corp.internal".into()],
            established_at: Utc::now(),
        });

        let anomaly = engine
            .observe_session(subject, 3, "corp.internal")
            .unwrap()
            .unwrap();
        assert_eq!(anomaly.anomaly_type, "unusual_hour");
    }
}
