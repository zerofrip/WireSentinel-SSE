use std::collections::HashMap;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{RiskLevel, ThreatFeed, ThreatIndicator, ThreatMatch};
use sse_core::SseResult;

/// Threat protection engine matching indicators against traffic/content.
pub struct ThreatProtectionEngine {
    feeds: RwLock<Vec<ThreatFeed>>,
    indicators: RwLock<HashMap<String, ThreatIndicator>>,
}

impl ThreatProtectionEngine {
    pub fn new() -> Self {
        Self {
            feeds: RwLock::new(Vec::new()),
            indicators: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_feed(&self, feed: ThreatFeed) {
        self.feeds.write().push(feed);
    }

    pub fn add_indicator(&self, indicator: ThreatIndicator) {
        self.indicators
            .write()
            .insert(indicator.value.clone(), indicator);
    }

    pub fn feeds(&self) -> Vec<ThreatFeed> {
        self.feeds.read().clone()
    }

    pub fn check(&self, value: &str, block: bool) -> SseResult<Option<ThreatMatch>> {
        let indicators = self.indicators.read();
        let indicator = match indicators.get(value) {
            Some(i) => i.clone(),
            None => return Ok(None),
        };

        Ok(Some(ThreatMatch {
            id: Uuid::new_v4(),
            indicator,
            matched_value: value.into(),
            blocked: block,
            detected_at: Utc::now(),
        }))
    }

    pub fn ingest_ioc_list(&self, feed_id: Uuid, values: &[(&str, RiskLevel)]) {
        for (value, severity) in values {
            self.add_indicator(ThreatIndicator {
                id: Uuid::new_v4(),
                indicator_type: "ioc".into(),
                value: (*value).into(),
                severity: *severity,
                source_feed_id: feed_id,
                expires_at: None,
            });
        }
    }
}

impl Default for ThreatProtectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_indicator() {
        let engine = ThreatProtectionEngine::new();
        let feed_id = Uuid::new_v4();
        engine.ingest_ioc_list(feed_id, &[("evil.test", RiskLevel::Critical)]);

        let m = engine.check("evil.test", true).unwrap().unwrap();
        assert!(m.blocked);
    }
}
