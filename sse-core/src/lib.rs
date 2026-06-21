//! Core SSE abstractions for WireSentinel Phase 16.

mod error;

pub use error::{SseError, SseResult};
pub use shared_types::{
    DlpAction, RiskLevel, SseSecurityPolicy, WebAccessAction,
};
