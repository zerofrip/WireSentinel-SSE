//! Secure Web Gateway (Phase 16-B).

mod gateway;

pub use gateway::SecureWebGateway;
pub use shared_types::{
    DomainReputation, UrlCategory, WebAccessAction, WebAccessResult, WebPolicy,
};
