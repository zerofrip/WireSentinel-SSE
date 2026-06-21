use chrono::Utc;
use shared_types::{SecurityEventRecord, SiemExportFormat};
use sse_core::SseResult;

/// Format a security event for SIEM export.
pub fn format_event(record: &SecurityEventRecord, format: SiemExportFormat) -> SseResult<String> {
    match format {
        SiemExportFormat::Json => Ok(serde_json::to_string(record).map_err(|e| {
            sse_core::SseError::Siem(e.to_string())
        })?),
        SiemExportFormat::Cef => Ok(format!(
            "CEF:0|WireSentinel|SSE|0.1|{}|{}|5|msg={}",
            record.event_kind,
            record.id,
            record.payload
        )),
        SiemExportFormat::Leef => Ok(format!(
            "LEEF:2.0|WireSentinel|SSE|0.1|{}|id={}|kind={}",
            record.event_kind, record.id, record.event_kind
        )),
        SiemExportFormat::Syslog => Ok(format!(
            "<134>{} WireSentinel-SSE: {} tenant={} id={}",
            Utc::now().format("%b %d %H:%M:%S"),
            record.event_kind,
            record.tenant_id,
            record.id
        )),
    }
}

/// Trait for SIEM destination exporters.
pub trait SiemExporter: Send + Sync {
    fn kind(&self) -> shared_types::SiemExporterKind;

    fn endpoint(&self) -> &str;

    fn export(&self, payload: &str) -> SseResult<()>;
}

/// Mock syslog exporter for tests.
pub struct SyslogExporter {
    endpoint: String,
    pub last_payload: parking_lot::Mutex<Option<String>>,
}

impl SyslogExporter {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            last_payload: parking_lot::Mutex::new(None),
        }
    }
}

impl SiemExporter for SyslogExporter {
    fn kind(&self) -> shared_types::SiemExporterKind {
        shared_types::SiemExporterKind::Syslog
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn export(&self, payload: &str) -> SseResult<()> {
        *self.last_payload.lock() = Some(payload.into());
        Ok(())
    }
}

macro_rules! stub_exporter {
    ($name:ident, $kind:expr) => {
        pub struct $name {
            endpoint: String,
        }

        impl $name {
            pub fn new(endpoint: impl Into<String>) -> Self {
                Self {
                    endpoint: endpoint.into(),
                }
            }
        }

        impl SiemExporter for $name {
            fn kind(&self) -> shared_types::SiemExporterKind {
                $kind
            }

            fn endpoint(&self) -> &str {
                &self.endpoint
            }

            fn export(&self, _payload: &str) -> SseResult<()> {
                Ok(())
            }
        }
    };
}

stub_exporter!(SplunkExporter, shared_types::SiemExporterKind::Splunk);
stub_exporter!(SentinelExporter, shared_types::SiemExporterKind::Sentinel);
stub_exporter!(ElasticExporter, shared_types::SiemExporterKind::Elastic);
stub_exporter!(OpenSearchExporter, shared_types::SiemExporterKind::OpenSearch);
stub_exporter!(QRadarExporter, shared_types::SiemExporterKind::QRadar);
