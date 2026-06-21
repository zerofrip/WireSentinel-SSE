use controller::{empty_telemetry, sample_incident_bundle, SseIncidentBundleDto};
use uuid::Uuid;

#[test]
fn telemetry_payload_roundtrip() {
    let agent = Uuid::new_v4();
    let payload = empty_telemetry(agent);
    assert_eq!(payload.agent_id, agent);
}

#[test]
fn bundle_dto_from_sample() {
    let dto =
        SseIncidentBundleDto::from_bundle(sample_incident_bundle(Uuid::new_v4()), Uuid::new_v4());
    assert!(dto.received_at <= chrono::Utc::now());
}
