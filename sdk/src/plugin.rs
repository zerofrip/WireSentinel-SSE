use async_trait::async_trait;

use sse_core::{SseResult, SseSecurityPolicy};

use crate::manifest::SsePluginManifest;

/// Stable hook for Wasm/native SSE provider loaders.
#[async_trait]
pub trait SsePlugin: Send + Sync {
    fn manifest(&self) -> &SsePluginManifest;

    async fn validate_policy(&self, policy: &SseSecurityPolicy) -> SseResult<()>;

    async fn on_load(&self) -> SseResult<()> {
        Ok(())
    }
}
