use std::collections::VecDeque;

use chrono::Utc;
use parking_lot::Mutex;
use uuid::Uuid;

use shared_types::{DlpIncident, DlpPolicy};
use sse_core::SseResult;

use crate::detection::detect_patterns;

const DEFAULT_CAPACITY: usize = 5_000;

/// DLP engine applying policies and recording incidents.
pub struct DlpEngine {
    policies: Mutex<Vec<DlpPolicy>>,
    incidents: Mutex<VecDeque<DlpIncident>>,
    capacity: usize,
}

impl DlpEngine {
    pub fn new() -> Self {
        Self {
            policies: Mutex::new(Vec::new()),
            incidents: Mutex::new(VecDeque::new()),
            capacity: DEFAULT_CAPACITY,
        }
    }

    pub fn add_policy(&self, policy: DlpPolicy) {
        self.policies.lock().push(policy);
    }

    pub fn scan(
        &self,
        content: &str,
        channel: &str,
        user_id: Option<Uuid>,
    ) -> SseResult<Vec<DlpIncident>> {
        let patterns = detect_patterns(content);
        let policies = self.policies.lock().clone();
        let mut incidents = Vec::new();

        for pm in patterns {
            for policy in policies
                .iter()
                .filter(|p| p.enabled && policy_covers_channel(p, channel))
            {
                if policy.patterns.contains(&pm.kind) || policy.patterns.is_empty() {
                    let incident = DlpIncident {
                        id: Uuid::new_v4(),
                        policy_id: policy.id,
                        pattern: pm.kind,
                        action: policy.action,
                        channel: channel.into(),
                        user_id,
                        matched_snippet: pm.matched.clone(),
                        detected_at: Utc::now(),
                    };
                    self.record_incident(incident.clone());
                    incidents.push(incident);
                }
            }
        }

        Ok(incidents)
    }

    fn record_incident(&self, incident: DlpIncident) {
        let mut store = self.incidents.lock();
        if store.len() >= self.capacity {
            store.pop_front();
        }
        store.push_back(incident);
    }

    pub fn recent_incidents(&self, limit: usize) -> Vec<DlpIncident> {
        self.incidents
            .lock()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn policy_covers_channel(policy: &DlpPolicy, channel: &str) -> bool {
    policy.channels.is_empty() || policy.channels.iter().any(|c| c == channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::{DlpAction, DlpPatternKind};

    #[test]
    fn scan_creates_incident_for_ssn() {
        let engine = DlpEngine::new();
        let mut policy = DlpPolicy::new("pii");
        policy.patterns = vec![DlpPatternKind::Ssn];
        policy.action = DlpAction::Block;
        engine.add_policy(policy);

        let incidents = engine.scan("SSN: 123-45-6789", "email", None).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].action, DlpAction::Block);
    }
}
