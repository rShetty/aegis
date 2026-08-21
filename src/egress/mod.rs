use std::sync::Arc;

use crate::config::EgressConfig;
use crate::db::Database;
use crate::errors::{AegisError, Result};

pub struct EgressEngine {
    db: Arc<Database>,
    config: EgressConfig,
    /// When true (#4), egress is denied for any agent that has not been
    /// attested (registered via /api/attestation/attestate).
    require_attestation: bool,
}

impl EgressEngine {
    pub fn new(db: Arc<Database>, config: EgressConfig, require_attestation: bool) -> Self {
        EgressEngine {
            db,
            config,
            require_attestation,
        }
    }

    pub fn check(&self, agent_id: Option<&str>, destination: &str) -> Result<()> {
        let dest_host = Self::extract_host(destination);

        // Attestation gate (#4): when require_attestation is set, only
        // agents present in the attestation store may make egress requests.
        // Requests without an agent identity cannot be attested and are
        // denied fail-closed.
        if self.require_attestation {
            let attested = match agent_id {
                Some(id) => self.db.is_attested(id)?,
                None => false,
            };
            if !attested {
                self.db.log_egress(
                    agent_id,
                    "127.0.0.1",
                    &dest_host,
                    "CONNECT",
                    "blocked",
                    Some("Attestation required: agent is not attested"),
                    None,
                )?;
                return Err(AegisError::EgressBlocked(format!(
                    "Egress to {} denied: attestation required and agent is not attested",
                    dest_host
                )));
            }
        }

        if let Some(agent_id) = agent_id {
            let policy = self.db.check_egress(agent_id, &dest_host)?;
            match policy {
                Some(action) if action == "allow" => {
                    // Audit the allowed verdict too (#12 F1): the README
                    // guarantees every check — allowed or blocked — lands in
                    // egress_log. The bare early-return silently skipped the
                    // audit row for exactly the traffic an operator most
                    // needs evidence of.
                    self.db.log_egress(
                        Some(agent_id),
                        "127.0.0.1",
                        &dest_host,
                        "CONNECT",
                        "allowed",
                        None,
                        None,
                    )?;
                    return Ok(());
                }
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
        create_engine_with_attestation(false)
    }

    fn create_engine_with_attestation(require_attestation: bool) -> EgressEngine {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let config = EgressConfig {
            default_policy: "deny".to_string(),
            max_request_size_bytes: 1024 * 1024,
            max_connections_per_agent: 10,
            bandwidth_limit_kbps: 1024,
            log_retention_days: 30,
        };
        EgressEngine::new(db, config, require_attestation)
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

    // ---------------- allowed checks are audited (#12 F1) ----------------

    #[test]
    fn allowed_by_policy_writes_an_audit_row() {
        let engine = create_engine();
        engine
            .db
            .add_egress_policy("agent-1", "api.github.com", "allow")
            .unwrap();
        engine
            .check(Some("agent-1"), "https://api.github.com/repos")
            .unwrap();
        let log = engine.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1, "allowed checks must be audited too");
        assert_eq!(log[0]["status"], "allowed");
        assert_eq!(log[0]["agent_id"], "agent-1");
        assert_eq!(log[0]["destination"], "api.github.com");
        assert_eq!(log[0]["reason"], serde_json::Value::Null);
    }

    #[test]
    fn default_allow_policy_writes_an_audit_row() {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let config = EgressConfig {
            default_policy: "allow".to_string(),
            max_request_size_bytes: 1024 * 1024,
            max_connections_per_agent: 10,
            bandwidth_limit_kbps: 1024,
            log_retention_days: 30,
        };
        let engine = EgressEngine::new(db, config, false);
        engine
            .check(Some("agent-1"), "https://anything.example")
            .unwrap();
        let log = engine.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1, "default-allow verdicts must be audited");
        assert_eq!(log[0]["status"], "allowed");
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

    // ---------------- attestation enforcement (#4) ----------------

    #[test]
    fn attestation_enforced_blocks_unattested_agent() {
        let engine = create_engine_with_attestation(true);
        // Even an explicit allow policy must not bypass the attestation gate.
        add(&engine, "agent-1", "api.github.com", "allow");
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com")
                .is_err()
        );
    }

    #[test]
    fn attestation_enforced_allows_attested_agent() {
        let engine = create_engine_with_attestation(true);
        add(&engine, "agent-1", "api.github.com", "allow");
        engine
            .db
            .attestate_agent("agent-1", "some-hash", Some(42))
            .unwrap();
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com")
                .is_ok()
        );
        // A different (unattested) agent is still blocked.
        assert!(
            engine
                .check(Some("agent-2"), "https://api.github.com")
                .is_err()
        );
    }

    #[test]
    fn attestation_enforced_denies_missing_agent_id() {
        let engine = create_engine_with_attestation(true);
        // No agent identity -> cannot be attested -> fail closed.
        assert!(engine.check(None, "https://api.github.com").is_err());
    }

    #[test]
    fn attestation_unenforced_ignores_attestation_store() {
        let engine = create_engine_with_attestation(false);
        add(&engine, "agent-1", "api.github.com", "allow");
        // Not attested, but require_attestation=false: policy decides alone.
        assert!(
            engine
                .check(Some("agent-1"), "https://api.github.com")
                .is_ok()
        );
    }

    #[test]
    fn attestation_blocked_attempts_are_logged() {
        let engine = create_engine_with_attestation(true);
        let _ = engine.check(Some("ghost-agent"), "https://api.github.com");
        let log = engine.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["status"], "blocked");
        assert_eq!(log[0]["agent_id"], "ghost-agent");
        assert!(log[0]["reason"].as_str().unwrap().contains("not attested"));
    }
}
