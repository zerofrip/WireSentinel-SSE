use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Manifest describing an SSE provider plugin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsePluginManifest {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub provider: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
}

impl SsePluginManifest {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            version: version.into(),
            provider: provider.into(),
            description: None,
            capabilities: vec![
                "swg".into(),
                "dlp".into(),
                "casb".into(),
                "threat".into(),
            ],
        }
    }
}
