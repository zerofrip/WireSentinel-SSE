use std::sync::Arc;

use shared_types::SecurityEventRecord;
use siem::{format_event, SiemExportFormat, SiemIntegrationManager, SyslogExporter};
use uuid::Uuid;

#[test]
fn formats_json_export() {
    let record = SecurityEventRecord {
        id: Uuid::new_v4(),
        event_kind: "test".into(),
        payload: serde_json::json!({"a": 1}),
        tenant_id: Uuid::new_v4(),
        ingested_at: chrono::Utc::now(),
    };
    let formatted = format_event(&record, SiemExportFormat::Json).unwrap();
    assert!(formatted.contains("test"));
}

#[test]
fn export_via_syslog() {
    let manager = SiemIntegrationManager::new();
    let exporter = Arc::new(SyslogExporter::new("udp://127.0.0.1:514"));
    manager.register(exporter.clone());

    let events = vec![SecurityEventRecord {
        id: Uuid::new_v4(),
        event_kind: "alert".into(),
        payload: serde_json::json!({}),
        tenant_id: Uuid::new_v4(),
        ingested_at: chrono::Utc::now(),
    }];

    let job = manager
        .export_events(
            shared_types::SiemExporterKind::Syslog,
            SiemExportFormat::Syslog,
            &events,
        )
        .unwrap();
    assert!(job.success);
    assert!(exporter.last_payload.lock().is_some());
}
