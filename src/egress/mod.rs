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
        crate::destination::extract_host(url)
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

    // ---------------- adversarial suite (#2) ----------------
    //
    // Every test below targets a bypass class from issue #2. The default
    // engine is default-deny; "allowed" outcomes require an explicit policy.

    fn add(engine: &EgressEngine, agent: &str, dest: &str, action: &str) {
        engine.db.add_egress_policy(agent, dest, action).unwrap();
    }

    #[test]
    fn adv_userinfo_trick_cannot_bypass_deny() {
        let engine = create_engine();
        // Agent is only allowed api.github.com...
        add(&engine, "agent-1", "api.github.com", "allow");
        // ...but tries the userinfo trick to dial evil.com.
        let result = engine.check(Some("agent-1"), "https://api.github.com@evil.com/steal");
        assert!(
            result.is_err(),
            "userinfo trick must not inherit allow rule"
        );
        // And a deny on evil.com catches it explicitly.
        add(&engine, "agent-1", "evil.com", "deny");
        assert!(
            engine
                .check(Some("agent-1"), "api.github.com@evil.com")
                .is_err()
        );
    }

    #[test]
    fn adv_case_variants_cannot_defeat_deny() {
        let engine = create_engine();
        add(&engine, "agent-1", "evil.example.com", "deny");
        add(&engine, "agent-1", "*", "allow");
        for variant in [
            "https://EVIL.EXAMPLE.COM/x",
            "https://Evil.Example.Com",
            "evil.example.COM",
        ] {
            assert!(
                engine.check(Some("agent-1"), variant).is_err(),
                "case variant {variant} must still be denied"
            );
        }
    }

    #[test]
    fn adv_trailing_dot_cannot_defeat_deny() {
        let engine = create_engine();
        add(&engine, "agent-1", "evil.example.com", "deny");
        add(&engine, "agent-1", "*", "allow");
        for variant in [
            "https://evil.example.com./x",
            "evil.example.com..",
            "https://EVIL.example.COM.:8443",
        ] {
            assert!(
                engine.check(Some("agent-1"), variant).is_err(),
                "trailing-dot variant {variant} must still be denied"
            );
        }
    }

    #[test]
    fn adv_ipv6_bracket_parsing() {
        let engine = create_engine();
        add(&engine, "agent-1", "::1", "deny");
        add(&engine, "agent-1", "*", "allow");
        // "[::1]:8080" must resolve to host "::1" (not "["), hitting the deny.
        assert!(
            engine
                .check(Some("agent-1"), "http://[::1]:8080/admin")
                .is_err()
        );
        assert!(engine.check(Some("agent-1"), "[::1]").is_err());
        // A different IPv6 host stays allowed by the catch-all.
        assert!(
            engine
                .check(Some("agent-1"), "http://[2001:db8::1]/")
                .is_ok()
        );
    }

    #[test]
    fn adv_wildcard_does_not_match_apex_or_suffix_tricks() {
        let engine = create_engine();
        add(&engine, "agent-1", "*.github.com", "allow");

        // Subdomain: allowed.
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com")
                .is_ok()
        );

        // Apex: NOT covered by *.github.com.
        assert!(engine.check(Some("agent-1"), "https://github.com").is_err());

        // Suffix tricks: NOT covered.
        assert!(
            engine
                .check(Some("agent-1"), "https://evil-github.com")
                .is_err()
        );
        assert!(
            engine
                .check(Some("agent-1"), "https://github.com.evil.io")
                .is_err()
        );
    }

    #[test]
    fn adv_prefix_wildcard_pattern_is_literal_no_bypass() {
        let engine = create_engine();
        // A pattern with a trailing '*' used to prefix-match and enabled
        // userinfo bypasses. It is now literal and matches nothing useful,
        // so the destination falls through to default-deny.
        add(&engine, "agent-1", "api.github.com*", "allow");
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com@evil.com")
                .is_err()
        );
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com/repos")
                .is_err()
        );
    }

    #[test]
    fn adv_deny_evaluated_before_allow_regardless_of_order() {
        // Insert the ALLOW first, then the more specific DENY.
        let engine = create_engine();
        add(&engine, "agent-1", "*.github.com", "allow");
        add(&engine, "agent-1", "secret.github.com", "deny");
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com")
                .is_ok()
        );
        assert!(
            engine
                .check(Some("agent-1"), "https://secret.github.com")
                .is_err()
        );

        // Reverse insertion order: deny must STILL win.
        let engine2 = create_engine();
        add(&engine2, "agent-2", "secret.github.com", "deny");
        add(&engine2, "agent-2", "*.github.com", "allow");
        assert!(
            engine2
                .check(Some("agent-2"), "https://secret.github.com")
                .is_err()
        );
        assert!(
            engine2
                .check(Some("agent-2"), "https://api.github.com")
                .is_ok()
        );
    }

    #[test]
    fn adv_empty_and_degenerate_destinations_fail_closed() {
        let engine = create_engine();
        add(&engine, "agent-1", "*", "allow");
        assert!(engine.check(Some("agent-1"), "").is_err());
        assert!(engine.check(Some("agent-1"), ".").is_err());
        assert!(engine.check(Some("agent-1"), "https://").is_err());
    }

    #[test]
    fn adv_idn_punycode_fails_closed() {
        let engine = create_engine();
        add(&engine, "agent-1", "xn--bcher-kva.example.com", "allow");
        // Punycode form matches.
        assert!(
            engine
                .check(Some("agent-1"), "https://xn--bcher-kva.example.com")
                .is_ok()
        );
        // Raw Unicode does not match anything (fails closed).
        assert!(
            engine
                .check(Some("agent-1"), "https://bücher.example.com")
                .is_err()
        );
    }
}
