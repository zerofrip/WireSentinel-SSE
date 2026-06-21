use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{SecurityEventRecord, SiemExportFormat, SiemExportJob, SiemExporterKind};
use sse_core::SseResult;

use crate::exporter::{format_event, SiemExporter};

/// Manages SIEM exporters and export jobs.
pub struct SiemIntegrationManager {
    exporters: RwLock<HashMap<SiemExporterKind, Arc<dyn SiemExporter>>>,
    jobs: RwLock<Vec<SiemExportJob>>,
}

impl SiemIntegrationManager {
    pub fn new() -> Self {
        Self {
            exporters: RwLock::new(HashMap::new()),
            jobs: RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, exporter: Arc<dyn SiemExporter>) {
        self.exporters.write().insert(exporter.kind(), exporter);
    }

    pub fn export_events(
        &self,
        kind: SiemExporterKind,
        format: SiemExportFormat,
        events: &[SecurityEventRecord],
    ) -> SseResult<SiemExportJob> {
        let exporter =
            self.exporters.read().get(&kind).cloned().ok_or_else(|| {
                sse_core::SseError::Siem(format!("exporter {kind:?} not registered"))
            })?;

        let mut job = SiemExportJob {
            id: Uuid::new_v4(),
            exporter: kind,
            format,
            endpoint: exporter.endpoint().into(),
            event_count: events.len() as u64,
            started_at: Utc::now(),
            completed_at: None,
            success: false,
            error: None,
        };

        for event in events {
            let payload = format_event(event, format)?;
            exporter.export(&payload)?;
        }

        job.completed_at = Some(Utc::now());
        job.success = true;
        self.jobs.write().push(job.clone());
        Ok(job)
    }

    pub fn jobs(&self) -> Vec<SiemExportJob> {
        self.jobs.read().clone()
    }
}

impl Default for SiemIntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}
