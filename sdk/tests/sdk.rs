use sdk::{SsePluginManifest, SseSecurityPolicy};

#[test]
fn manifest_has_capabilities() {
    let manifest = SsePluginManifest::new("test", "0.1.0", "mock");
    assert!(manifest.capabilities.contains(&"swg".into()));
}

#[test]
fn policy_new_defaults() {
    let policy = SseSecurityPolicy::new("default");
    assert!(policy.enabled);
}
