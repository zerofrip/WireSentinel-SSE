use std::collections::HashMap;

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use shared_types::{IsolationMode, IsolationPolicy, IsolationSession, UrlCategory};
use sse_core::SseResult;

/// Browser isolation engine managing remote/containerized sessions.
pub struct BrowserIsolationEngine {
    policies: RwLock<Vec<IsolationPolicy>>,
    sessions: RwLock<HashMap<Uuid, IsolationSession>>,
    default_mode: IsolationMode,
}

impl BrowserIsolationEngine {
    pub fn new(default_mode: IsolationMode) -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            sessions: RwLock::new(HashMap::new()),
            default_mode,
        }
    }

    pub fn add_policy(&self, policy: IsolationPolicy) {
        self.policies.write().push(policy);
    }

    pub fn resolve_mode(&self, url: &str) -> IsolationMode {
        if self.default_mode == IsolationMode::Disabled {
            return IsolationMode::Disabled;
        }

        let domain = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(url);

        for policy in self.policies.read().iter().filter(|p| p.enabled) {
            if policy.target_domains.iter().any(|d| domain.ends_with(d)) {
                return policy.mode;
            }
        }

        self.default_mode
    }

    pub fn start_session(&self, user_id: Uuid, url: &str) -> SseResult<IsolationSession> {
        let mode = self.resolve_mode(url);
        if mode == IsolationMode::Disabled {
            return Err(sse_core::SseError::BrowserIsolation(
                "isolation disabled for URL".into(),
            ));
        }

        let session = IsolationSession {
            id: Uuid::new_v4(),
            user_id,
            url: url.into(),
            mode,
            started_at: Utc::now(),
            ended_at: None,
        };
        self.sessions.write().insert(session.id, session.clone());
        Ok(session)
    }

    pub fn terminate_session(&self, session_id: Uuid) -> SseResult<IsolationSession> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| sse_core::SseError::BrowserIsolation("session not found".into()))?;
        session.ended_at = Some(Utc::now());
        Ok(session.clone())
    }

    pub fn active_sessions(&self) -> Vec<IsolationSession> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.ended_at.is_none())
            .cloned()
            .collect()
    }
}

impl Default for BrowserIsolationEngine {
    fn default() -> Self {
        Self::new(IsolationMode::Remote)
    }
}

#[allow(dead_code)]
fn category_needs_isolation(category: &UrlCategory) -> bool {
    matches!(
        category,
        UrlCategory::Malware | UrlCategory::Phishing | UrlCategory::Uncategorized
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_remote_session() {
        let engine = BrowserIsolationEngine::new(IsolationMode::Remote);
        let session = engine
            .start_session(Uuid::new_v4(), "https://example.com")
            .unwrap();
        assert_eq!(session.mode, IsolationMode::Remote);
    }
}
