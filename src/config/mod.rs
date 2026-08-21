use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub egress: EgressConfig,
    pub attestation: AttestationConfig,
    pub geo: GeoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Explicit CORS allowlist (exact origins, e.g. "https://admin.example.com").
    /// Empty list = cross-origin browser access is denied entirely (#1).
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    pub default_policy: String,
    pub max_request_size_bytes: usize,
    pub max_connections_per_agent: usize,
    pub bandwidth_limit_kbps: usize,
    /// Rows in `egress_log` older than this many days are deleted by the
    /// background pruning task (#10). Defaults to 30 when omitted; must be
    /// >= 1 — audit logs are never kept forever by default.
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: u64,
}

fn default_log_retention_days() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub enabled: bool,
    pub require_attestation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    pub enabled: bool,
    pub blocked_regions: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                // Loopback by default (#1): an egress control plane must not
                // silently expose admin APIs on all interfaces.
                host: "127.0.0.1".to_string(),
                port: 8686,
                cors_allowed_origins: vec![],
            },
            database: DatabaseConfig {
                path: "aegis.db".to_string(),
            },
            egress: EgressConfig {
                default_policy: "deny".to_string(),
                max_request_size_bytes: 10 * 1024 * 1024,
                max_connections_per_agent: 20,
                bandwidth_limit_kbps: 10240,
                log_retention_days: default_log_retention_days(),
            },
            attestation: AttestationConfig {
                enabled: true,
                require_attestation: false,
            },
            geo: GeoConfig {
                enabled: false,
                blocked_regions: vec![],
            },
        }
    }
}

/// Actions that may appear in egress policies.
pub const VALID_ACTIONS: [&str; 2] = ["allow", "deny"];

impl Config {
    /// Load and strictly validate a configuration file.
    ///
    /// Fails fast on:
    /// - missing/unreadable file,
    /// - invalid TOML or unknown/missing fields,
    /// - invalid `egress.default_policy` (must be `allow` or `deny`),
    /// - missing/empty `database.path` (no silent relative fallback).
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read config file '{}': {}. Generate a template with `aegis init`.",
                path,
                e
            )
        })?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("invalid config file '{}': {}", path, e))?;
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid config file '{}': {}", path, e))?;
        Ok(config)
    }

    /// Enforce semantic constraints beyond what TOML deserialization checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.database.path.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "database.path is required and must not be empty (refusing to silently fall back to a relative path)"
            ));
        }
        if !VALID_ACTIONS.contains(&self.egress.default_policy.as_str()) {
            return Err(anyhow::anyhow!(
                "egress.default_policy must be one of {:?}, got '{}'",
                VALID_ACTIONS,
                self.egress.default_policy
            ));
        }
        if self.server.port == 0 {
            return Err(anyhow::anyhow!("server.port must be a nonzero port"));
        }
        if self.egress.log_retention_days == 0 {
            return Err(anyhow::anyhow!(
                "egress.log_retention_days must be at least 1 (audit rows are pruned, never kept forever by default; set a larger value to retain longer)"
            ));
        }
        Ok(())
    }
}

pub fn is_valid_action(action: &str) -> bool {
    VALID_ACTIONS.contains(&action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_config(contents: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "aegis-config-test-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aegis.toml");
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().to_string()
    }

    fn valid_toml() -> String {
        r#"
[server]
host = "127.0.0.1"
port = 8686

[database]
path = "/tmp/aegis-test.db"

[egress]
default_policy = "deny"
max_request_size_bytes = 10485760
max_connections_per_agent = 20
bandwidth_limit_kbps = 10240
log_retention_days = 30

[attestation]
enabled = true
require_attestation = false

[geo]
enabled = false
blocked_regions = []
"#
        .to_string()
    }

    #[test]
    fn test_load_valid_config() {
        let path = write_temp_config(&valid_toml());
        let config = Config::load(&path).expect("valid config must load");
        assert_eq!(config.server.port, 8686);
        assert_eq!(config.egress.default_policy, "deny");
    }

    #[test]
    fn test_missing_file_fails_fast() {
        let err = Config::load("/nonexistent/aegis/nope.toml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("/nonexistent/aegis/nope.toml"), "got: {msg}");
        assert!(msg.contains("aegis init"), "got: {msg}");
    }

    #[test]
    fn test_invalid_toml_fails_fast() {
        let path = write_temp_config("this is not toml {{{{");
        let err = Config::load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("invalid config"),);
    }

    #[test]
    fn test_missing_field_fails_fast() {
        // No [database] section at all.
        let path = write_temp_config(
            r#"
[server]
host = "127.0.0.1"
port = 8686
"#,
        );
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn test_invalid_default_policy_rejected() {
        let mut toml = valid_toml();
        toml = toml.replace("default_policy = \"deny\"", "default_policy = \"block\"");
        let path = write_temp_config(&toml);
        let err = Config::load(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("default_policy"), "got: {msg}");
    }

    #[test]
    fn test_empty_db_path_rejected() {
        let toml = valid_toml().replace("path = \"/tmp/aegis-test.db\"", "path = \"\"");
        let path = write_temp_config(&toml);
        let err = Config::load(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("database.path"), "got: {msg}");
    }

    #[test]
    fn test_validate_rejects_bad_action_directly() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        let mut bad = config.clone();
        bad.egress.default_policy = "ALLOW_ALL".into();
        assert!(bad.validate().is_err());
        let mut no_db = config.clone();
        no_db.database.path = "  ".into();
        assert!(no_db.validate().is_err());
    }

    #[test]
    fn test_log_retention_days_defaults_when_omitted() {
        // Existing config files without the field must keep parsing (#10).
        let toml = valid_toml().replace("log_retention_days = 30\n", "");
        let path = write_temp_config(&toml);
        let config = Config::load(&path).expect("config without log_retention_days must load");
        assert_eq!(config.egress.log_retention_days, 30);
    }

    #[test]
    fn test_zero_log_retention_days_rejected() {
        let toml = valid_toml().replace("log_retention_days = 30", "log_retention_days = 0");
        let path = write_temp_config(&toml);
        let err = Config::load(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("log_retention_days"), "got: {msg}");
    }

    #[test]
    fn test_is_valid_action() {
        assert!(is_valid_action("allow"));
        assert!(is_valid_action("deny"));
        assert!(!is_valid_action("Allow"));
        assert!(!is_valid_action("drop"));
        assert!(!is_valid_action(""));
    }
}
