use std::collections::VecDeque;

use chrono::{Duration, Utc};
use parking_lot::Mutex;
use uuid::Uuid;

use shared_types::{RetentionPolicy, SecurityEventRecord};
use sse_core::SseResult;

/// In-memory security data lake with configurable retention.
pub struct SecurityDataLake {
    events: Mutex<VecDeque<SecurityEventRecord>>,
    retention: RetentionPolicy,
}

impl SecurityDataLake {
    pub fn new(retention: RetentionPolicy) -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            retention,
        }
    }

    pub fn retention(&self) -> &RetentionPolicy {
        &self.retention
    }

    pub fn ingest(
        &self,
        tenant_id: Uuid,
        event_kind: impl Into<String>,
        payload: serde_json::Value,
    ) -> SecurityEventRecord {
        let record = SecurityEventRecord {
            id: Uuid::new_v4(),
            event_kind: event_kind.into(),
            payload,
            tenant_id,
            ingested_at: Utc::now(),
        };
        self.events.lock().push_back(record.clone());
        self.purge_expired();
        record
    }

    pub fn purge_expired(&self) {
        let cutoff = Utc::now() - Duration::days(self.retention.days() as i64);
        let mut events = self.events.lock();
        while events
            .front()
            .is_some_and(|e| e.ingested_at < cutoff)
        {
            events.pop_front();
        }
    }

    pub fn count(&self) -> usize {
        self.events.lock().len()
    }

    pub fn all(&self) -> Vec<SecurityEventRecord> {
        self.events.lock().iter().cloned().collect()
    }

    pub fn set_retention(&mut self, retention: RetentionPolicy) -> SseResult<()> {
        self.retention = retention;
        self.purge_expired();
        Ok(())
    }
}

impl Default for SecurityDataLake {
    fn default() -> Self {
        Self::new(RetentionPolicy::Days90)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_events() {
        let lake = SecurityDataLake::new(RetentionPolicy::Days30);
        lake.ingest(Uuid::new_v4(), "test", serde_json::json!({}));
        assert_eq!(lake.count(), 1);
    }
}
