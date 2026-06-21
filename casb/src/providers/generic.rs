use async_trait::async_trait;
use uuid::Uuid;

use shared_types::{CasbFinding, CasbProviderKind, SaasApplication};
use sse_core::SseResult;

use crate::provider::CasbProvider;

/// Generic mock CASB provider for tests and development.
pub struct GenericMockProvider;

#[async_trait]
impl CasbProvider for GenericMockProvider {
    fn kind(&self) -> CasbProviderKind {
        CasbProviderKind::GenericMock
    }

    fn display_name(&self) -> &str {
        "Generic Mock"
    }

    async fn list_applications(&self) -> SseResult<Vec<SaasApplication>> {
        Ok(vec![SaasApplication {
            id: Uuid::new_v4(),
            name: "Unknown SaaS".into(),
            provider: self.kind(),
            domain: "unknown-saas.test".into(),
            sanctioned: false,
            risk_score: 60,
        }])
    }

    async fn scan_activity(&self, user_id: Uuid) -> SseResult<Vec<CasbFinding>> {
        Ok(vec![CasbFinding {
            id: Uuid::new_v4(),
            provider: self.kind(),
            application_id: Uuid::new_v4(),
            user_id,
            violation_type: "unsanctioned_app".into(),
            detail: "Generic mock violation".into(),
            detected_at: chrono::Utc::now(),
        }])
    }
}
