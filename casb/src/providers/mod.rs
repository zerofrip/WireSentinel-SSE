mod generic;
mod saas;

pub use generic::GenericMockProvider;
pub use saas::{
    BoxProvider, DropboxProvider, GitHubProvider, GoogleProvider, M365Provider,
    SalesforceProvider, SlackProvider,
};
