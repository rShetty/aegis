use std::sync::Arc;

use crate::config::EgressConfig;
use crate::db::Database;
use crate::errors::{AegisError, Result};

pub struct EgressEngine {
    db: Arc<Database>,
    config: EgressConfig,
}

impl EgressEngine {
    pub fn new(db: Arc<Database>, config: EgressConfig) -> Self {
        EgressEngine { db, config }
    }

    pub fn check(&self, agent_id: Option<&str>, destination: &str) -> Result<()> {
        let dest_host = Self::extract_host(destination);

        if let Some(agent_id) = agent_id {
            let policy = self.db.check_egress(agent_id, &dest_host)?;
            match policy {
                Some(action) if action == "allow" => return Ok(()),
                Some(action) if action == "deny" => {
                    self.db.log_egress(
                        Some(agent_id),
                        "127.0.0.1",
                        &dest_host,
                        "CONNECT",
                        "blocked",
                        Some("Denied by egress policy"),
                        None,
                    )?;
                    return Err(AegisError::EgressBlocked(format!(
                        "Egress to {} denied by policy for agent {}",
                        dest_host, agent_id
                    )));
                }
                _ => {}
            }
        }

        if self.config.default_policy == "deny" {
            self.db.log_egress(
                agent_id,
                "127.0.0.1",
                &dest_host,
                "CONNECT",
                "blocked",
                Some("Default deny - no matching allow policy"),
                None,
            )?;
            return Err(AegisError::EgressBlocked(format!(
                "Egress to {} denied (default deny)",
                dest_host
            )));
        }

        self.db.log_egress(
            agent_id,
            "127.0.0.1",
            &dest_host,
            "CONNECT",
            "allowed",
            None,
            None,
        )?;
        Ok(())
    }

    fn extract_host(url: &str) -> String {
        let without_scheme = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url);
        let host = without_scheme.split('/').next().unwrap_or(without_scheme);
        let host = host.split(':').next().unwrap_or(host);
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_engine() -> EgressEngine {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let config = EgressConfig {
            default_policy: "deny".to_string(),
            max_request_size_bytes: 1024 * 1024,
            max_connections_per_agent: 10,
            bandwidth_limit_kbps: 1024,
        };
        EgressEngine::new(db, config)
    }

    #[test]
    fn test_default_deny_blocks_unknown() {
        let engine = create_engine();
        let result = engine.check(Some("agent-1"), "https://evil.example.com/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_allow_policy_permits() {
        let engine = create_engine();
        engine
            .db
            .add_egress_policy("agent-1", "api.github.com", "allow")
            .unwrap();
        let result = engine.check(Some("agent-1"), "https://api.github.com/repos");
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_policy_blocks() {
        let engine = create_engine();
        engine
            .db
            .add_egress_policy("agent-1", "evil.example.com", "deny")
            .unwrap();
        let result = engine.check(Some("agent-1"), "https://evil.example.com/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_wildcard_policy() {
        let engine = create_engine();
        engine
            .db
            .add_egress_policy("agent-1", "*.github.com", "allow")
            .unwrap();
        let result = engine.check(Some("agent-1"), "https://api.github.com/repos");
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            EgressEngine::extract_host("https://api.github.com/repos"),
            "api.github.com"
        );
        assert_eq!(
            EgressEngine::extract_host("http://localhost:8080/path"),
            "localhost"
        );
        assert_eq!(EgressEngine::extract_host("evil.com/path"), "evil.com");
    }
}
