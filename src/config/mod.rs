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
                host: "0.0.0.0".to_string(),
                port: 8686,
            },
            database: DatabaseConfig {
                path: "aegis.db".to_string(),
            },
            egress: EgressConfig {
                default_policy: "deny".to_string(),
                max_request_size_bytes: 10 * 1024 * 1024,
                max_connections_per_agent: 20,
                bandwidth_limit_kbps: 10240,
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

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
