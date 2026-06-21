use std::collections::HashMap;

use chrono::Utc;
use parking_lot::RwLock;

use shared_types::{DomainReputation, UrlCategory, WebAccessAction, WebAccessResult, WebPolicy};
use sse_core::SseResult;

/// Secure Web Gateway — URL categorization, reputation, and policy enforcement.
pub struct SecureWebGateway {
    policies: RwLock<Vec<WebPolicy>>,
    reputations: RwLock<HashMap<String, DomainReputation>>,
}

impl SecureWebGateway {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            reputations: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_policy(&self, policy: WebPolicy) {
        self.policies.write().push(policy);
    }

    pub fn set_reputation(&self, reputation: DomainReputation) {
        self.reputations
            .write()
            .insert(reputation.domain.clone(), reputation);
    }

    pub fn categorize_url(&self, url: &str) -> UrlCategory {
        let lower = url.to_lowercase();
        if lower.contains("facebook") || lower.contains("twitter") {
            UrlCategory::SocialMedia
        } else if lower.contains("malware") || lower.contains("virus") {
            UrlCategory::Malware
        } else if lower.contains("phish") {
            UrlCategory::Phishing
        } else if lower.contains("dropbox") || lower.contains("drive.google") {
            UrlCategory::CloudStorage
        } else {
            UrlCategory::Uncategorized
        }
    }

    pub fn evaluate(&self, url: &str) -> SseResult<WebAccessResult> {
        let domain = extract_domain(url);
        let category = self.categorize_url(url);
        let reputation = self.reputations.read().get(&domain).cloned();

        let policies = self.policies.read();
        let mut action = WebAccessAction::Allow;
        let mut reason = "default allow".into();

        for policy in policies.iter().filter(|p| p.enabled) {
            if policy.blocked_domains.iter().any(|d| domain.ends_with(d)) {
                action = WebAccessAction::Block;
                reason = format!("domain blocked by policy {}", policy.name);
                break;
            }
            if policy
                .blocked_categories
                .iter()
                .any(|c| categories_match(c, &category))
            {
                action = policy.default_action;
                reason = format!("category blocked by policy {}", policy.name);
                break;
            }
        }

        if let Some(ref rep) = reputation {
            if rep.malicious {
                action = WebAccessAction::Block;
                reason = "malicious domain reputation".into();
            }
        }

        Ok(WebAccessResult {
            url: url.into(),
            domain,
            action,
            category: Some(category),
            reputation,
            reason,
            evaluated_at: Utc::now(),
        })
    }
}

impl Default for SecureWebGateway {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .into()
}

fn categories_match(a: &UrlCategory, b: &UrlCategory) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
        || matches!((a, b), (UrlCategory::Custom(_), UrlCategory::Custom(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_malicious_reputation() {
        let gw = SecureWebGateway::new();
        gw.set_reputation(DomainReputation {
            domain: "evil.test".into(),
            score: 5,
            malicious: true,
            categories: vec![UrlCategory::Malware],
            evaluated_at: Utc::now(),
        });
        let result = gw.evaluate("https://evil.test/page").unwrap();
        assert_eq!(result.action, WebAccessAction::Block);
    }
}
