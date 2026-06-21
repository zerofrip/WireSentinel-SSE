use async_trait::async_trait;
use uuid::Uuid;

use shared_types::{CasbFinding, CasbProviderKind, SaasApplication};
use sse_core::SseResult;

use crate::provider::CasbProvider;

macro_rules! saas_provider {
    ($struct:ident, $kind:expr, $name:expr, $domain:expr) => {
        pub struct $struct;

        #[async_trait]
        impl CasbProvider for $struct {
            fn kind(&self) -> CasbProviderKind {
                $kind
            }

            fn display_name(&self) -> &str {
                $name
            }

            async fn list_applications(&self) -> SseResult<Vec<SaasApplication>> {
                Ok(vec![SaasApplication {
                    id: Uuid::new_v4(),
                    name: $name.into(),
                    provider: self.kind(),
                    domain: $domain.into(),
                    sanctioned: true,
                    risk_score: 20,
                }])
            }

            async fn scan_activity(&self, _user_id: Uuid) -> SseResult<Vec<CasbFinding>> {
                Ok(Vec::new())
            }
        }
    };
}

saas_provider!(M365Provider, CasbProviderKind::M365, "Microsoft 365", "office.com");
saas_provider!(GoogleProvider, CasbProviderKind::Google, "Google Workspace", "google.com");
saas_provider!(SlackProvider, CasbProviderKind::Slack, "Slack", "slack.com");
saas_provider!(GitHubProvider, CasbProviderKind::GitHub, "GitHub", "github.com");
saas_provider!(DropboxProvider, CasbProviderKind::Dropbox, "Dropbox", "dropbox.com");
saas_provider!(BoxProvider, CasbProviderKind::Box, "Box", "box.com");
saas_provider!(
    SalesforceProvider,
    CasbProviderKind::Salesforce,
    "Salesforce",
    "salesforce.com"
);
