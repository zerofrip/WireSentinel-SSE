//! Cloud Access Security Broker (Phase 16-C).

mod engine;
mod provider;
mod providers;

pub use engine::CasbEngine;
pub use provider::CasbProvider;
pub use providers::{
    BoxProvider, DropboxProvider, GenericMockProvider, GitHubProvider, GoogleProvider,
    M365Provider, SalesforceProvider, SlackProvider,
};
pub use shared_types::{CasbFinding, CasbProviderKind, SaasApplication, ShadowItRecord};
