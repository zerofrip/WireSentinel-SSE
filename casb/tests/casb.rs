use std::sync::Arc;

use casb::{CasbEngine, GenericMockProvider, M365Provider};
use uuid::Uuid;

#[tokio::test]
async fn detects_shadow_it() {
    let engine = CasbEngine::new();
    engine.register(Arc::new(M365Provider));
    engine.register(Arc::new(GenericMockProvider));

    let records = engine.detect_shadow_it(Uuid::new_v4()).await.unwrap();
    assert!(!records.is_empty());
}

#[tokio::test]
async fn scan_all_aggregates_findings() {
    let engine = CasbEngine::new();
    engine.register(Arc::new(GenericMockProvider));

    let findings = engine.scan_all(Uuid::new_v4()).await.unwrap();
    assert_eq!(findings.len(), 1);
}
