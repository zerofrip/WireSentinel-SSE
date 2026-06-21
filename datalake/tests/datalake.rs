use datalake::{RetentionPolicy, SecurityDataLake, SecurityQueryEngine};
use uuid::Uuid;

#[test]
fn query_by_kind() {
    let lake = SecurityDataLake::new(RetentionPolicy::Days180);
    let tenant = Uuid::new_v4();
    lake.ingest(tenant, "dlp_violation", serde_json::json!({"x": 1}));
    lake.ingest(tenant, "web_access", serde_json::json!({}));

    let query = SecurityQueryEngine::new(&lake);
    assert_eq!(query.count_by_kind("dlp_violation"), 1);
}

#[test]
fn retention_presets() {
    assert_eq!(RetentionPolicy::Days365.days(), 365);
    assert_eq!(RetentionPolicy::Custom { days: 14 }.days(), 14);
}
