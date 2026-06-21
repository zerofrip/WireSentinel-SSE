//! Security data lake and query engine (Phase 16-I).

mod lake;
mod query;

pub use lake::SecurityDataLake;
pub use query::SecurityQueryEngine;
pub use shared_types::{RetentionPolicy, SecurityEventRecord};
