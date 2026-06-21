use async_trait::async_trait;
use uuid::Uuid;

use shared_types::{CasbFinding, CasbProviderKind, SaasApplication};
use sse_core::SseResult;

/// Pluggable CASB SaaS provider interface.
#[async_trait]
pub trait CasbProvider: Send + Sync {
    fn kind(&self) -> CasbProviderKind;

    fn display_name(&self) -> &str;

    async fn list_applications(&self) -> SseResult<Vec<SaasApplication>>;

    async fn scan_activity(&self, user_id: Uuid) -> SseResult<Vec<CasbFinding>>;
}
