//! Agent telemetry and incident bundle DTOs for WireSentinel-Controller integration.

mod dto;

pub use dto::{empty_telemetry, sample_incident_bundle, SseIncidentBundleDto};
pub use shared_types::{SseIncidentBundle, SseTelemetryPayload};
