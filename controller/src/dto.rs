use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{SseIncidentBundle, SseTelemetryPayload};
use uuid::Uuid;

/// Incident bundle DTO pushed from agents to WireSentinel-Controller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SseIncidentBundleDto {
    pub bundle: SseIncidentBundle,
    pub agent_id: Uuid,
    pub received_at: DateTime<Utc>,
}

impl SseIncidentBundleDto {
    pub fn from_bundle(bundle: SseIncidentBundle, agent_id: Uuid) -> Self {
        Self {
            bundle,
            agent_id,
            received_at: Utc::now(),
        }
    }

    pub fn incident_count(&self) -> usize {
        self.bundle.dlp_incidents.len()
            + self.bundle.casb_findings.len()
            + self.bundle.threat_matches.len()
            + self.bundle.anomalies.len()
    }
}

pub fn empty_telemetry(agent_id: Uuid) -> SseTelemetryPayload {
    SseTelemetryPayload::empty(agent_id)
}

pub fn sample_incident_bundle(tenant_id: Uuid) -> SseIncidentBundle {
    SseIncidentBundle {
        bundle_id: Uuid::new_v4(),
        tenant_id,
        dlp_incidents: Vec::new(),
        casb_findings: Vec::new(),
        threat_matches: Vec::new(),
        anomalies: Vec::new(),
        risk_scores: Vec::new(),
        issued_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_telemetry_defaults() {
        let id = Uuid::new_v4();
        let payload = empty_telemetry(id);
        assert_eq!(payload.agent_id, id);
        assert!(!payload.swg_active);
    }

    #[test]
    fn incident_bundle_dto_counts() {
        let dto = SseIncidentBundleDto::from_bundle(
            sample_incident_bundle(Uuid::new_v4()),
            Uuid::new_v4(),
        );
        assert_eq!(dto.incident_count(), 0);
    }
}
