//! WireSentinel SSE SDK — plugin trait and manifest.

mod manifest;
mod plugin;

pub use manifest::SsePluginManifest;
pub use plugin::SsePlugin;
pub use sse_core::{
    DlpAction, RiskLevel, SseResult, SseSecurityPolicy, WebAccessAction,
};
