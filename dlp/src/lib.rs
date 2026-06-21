//! Data Loss Prevention (Phase 16-D).

mod detection;
mod engine;

pub use detection::{detect_patterns, luhn_valid, PatternMatch};
pub use engine::DlpEngine;
pub use shared_types::{DlpAction, DlpIncident, DlpPatternKind, DlpPolicy};
