use crate::config::GeoConfig;
use crate::errors::{AegisError, Result};

pub struct GeoEngine {
    enabled: bool,
    blocked_regions: Vec<String>,
}

impl GeoEngine {
    pub fn new(config: &GeoConfig) -> Self {
        GeoEngine {
            enabled: config.enabled,
            blocked_regions: config.blocked_regions.clone(),
        }
    }

    pub fn check_destination(&self, destination: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let region = self.lookup_region(destination);

        for blocked in &self.blocked_regions {
            if &region == blocked {
                return Err(AegisError::EgressBlocked(format!(
                    "Data residency violation: destination {} in blocked region {}",
                    destination, blocked
                )));
            }
        }

        Ok(())
    }

    fn lookup_region(&self, destination: &str) -> String {
        let host = destination
            .strip_prefix("http://")
            .or_else(|| destination.strip_prefix("https://"))
            .unwrap_or(destination)
            .split('/')
            .next()
            .unwrap_or(destination)
            .split(':')
            .next()
            .unwrap_or(destination);

        let tld = host.rsplit('.').next().unwrap_or("").to_uppercase();

        match tld.as_str() {
            "CN" => "CN".to_string(),
            "RU" => "RU".to_string(),
            "IR" => "IR".to_string(),
            "KP" => "KP".to_string(),
            "EU" | "DE" | "FR" | "NL" | "IE" | "SE" | "PL" | "IT" | "ES" | "AT" | "BE" | "BG" | "HR" | "CY" | "CZ" | "DK" | "EE" | "FI" | "GR" | "HU" | "LV" | "LT" | "LU" | "MT" | "PT" | "RO" | "SK" | "SI" => "EU".to_string(),
            "US" | "COM" | "NET" | "ORG" | "IO" => "US".to_string(),
            "UK" | "CO" => "UK".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_engine(blocked: Vec<String>) -> GeoEngine {
        GeoEngine::new(&GeoConfig {
            enabled: true,
            blocked_regions: blocked,
        })
    }

    #[test]
    fn test_disabled_allows_all() {
        let engine = GeoEngine::new(&GeoConfig {
            enabled: false,
            blocked_regions: vec!["CN".to_string()],
        });
        assert!(engine.check_destination("https://evil.cn/api").is_ok());
    }

    #[test]
    fn test_blocked_region() {
        let engine = create_engine(vec!["CN".to_string()]);
        let result = engine.check_destination("https://api.service.cn/data");
        assert!(result.is_err());
    }

    #[test]
    fn test_allowed_region() {
        let engine = create_engine(vec!["CN".to_string()]);
        let result = engine.check_destination("https://api.github.com/repos");
        assert!(result.is_ok());
    }

    #[test]
    fn test_eu_tld_detected() {
        let engine = create_engine(vec!["EU".to_string()]);
        let result = engine.check_destination("https://api.service.de/data");
        assert!(result.is_err());
    }
}
