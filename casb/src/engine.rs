use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{CasbFinding, CasbProviderKind, ShadowItRecord};
use sse_core::SseResult;

use crate::provider::CasbProvider;

/// CASB engine orchestrating SaaS providers and shadow IT detection.
pub struct CasbEngine {
    providers: RwLock<HashMap<CasbProviderKind, Arc<dyn CasbProvider>>>,
    sanctioned: RwLock<HashSet<Uuid>>,
    shadow_records: RwLock<Vec<ShadowItRecord>>,
}

impl CasbEngine {
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            sanctioned: RwLock::new(HashSet::new()),
            shadow_records: RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, provider: Arc<dyn CasbProvider>) {
        self.providers.write().insert(provider.kind(), provider);
    }

    pub fn sanction(&self, app_id: Uuid) {
        self.sanctioned.write().insert(app_id);
    }

    pub async fn scan_all(&self, user_id: Uuid) -> SseResult<Vec<CasbFinding>> {
        let providers: Vec<_> = self.providers.read().values().cloned().collect();
        let mut findings = Vec::new();
        for provider in providers {
            findings.extend(provider.scan_activity(user_id).await?);
        }
        Ok(findings)
    }

    pub async fn detect_shadow_it(&self, user_id: Uuid) -> SseResult<Vec<ShadowItRecord>> {
        let providers: Vec<_> = self.providers.read().values().cloned().collect();
        let sanctioned = self.sanctioned.read().clone();
        let mut detected = Vec::new();

        for provider in providers {
            for app in provider.list_applications().await? {
                if !sanctioned.contains(&app.id) && !app.sanctioned {
                    let record = ShadowItRecord {
                        id: Uuid::new_v4(),
                        application: app,
                        user_id,
                        first_seen_at: Utc::now(),
                        last_seen_at: Utc::now(),
                        session_count: 1,
                    };
                    detected.push(record);
                }
            }
        }

        self.shadow_records.write().extend(detected.clone());
        Ok(detected)
    }

    pub fn shadow_records(&self) -> Vec<ShadowItRecord> {
        self.shadow_records.read().clone()
    }
}

impl Default for CasbEngine {
    fn default() -> Self {
        Self::new()
    }
}
