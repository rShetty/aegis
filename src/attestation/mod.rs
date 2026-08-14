use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::db::Database;
use crate::errors::{AegisError, Result};

pub struct AttestationEngine {
    db: Arc<Database>,
    enabled: bool,
}

impl AttestationEngine {
    pub fn new(db: Arc<Database>, enabled: bool) -> Self {
        AttestationEngine { db, enabled }
    }

    pub fn attestate(&self, agent_id: &str, binary_path: &str, pid: Option<i64>) -> Result<String> {
        let hash = Self::hash_file(binary_path)?;
        self.db.attestate_agent(agent_id, &hash, pid)?;
        Ok(hash)
    }

    pub fn verify(&self, agent_id: &str, binary_path: &str) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }
        let current_hash = Self::hash_file(binary_path)?;
        self.db.verify_agent(agent_id, &current_hash)
    }

    pub fn verify_hash(&self, agent_id: &str, process_hash: &str) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }
        self.db.verify_agent(agent_id, process_hash)
    }

    fn hash_file(path: &str) -> Result<String> {
        let content = std::fs::read(path)
            .map_err(|e| AegisError::AttestationFailed(format!("failed to read binary: {}", e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn hash_string(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_engine() -> AttestationEngine {
        let db = Arc::new(Database::new(":memory:").unwrap());
        AttestationEngine::new(db, true)
    }

    #[test]
    fn test_hash_string() {
        let h1 = AttestationEngine::hash_string("test");
        let h2 = AttestationEngine::hash_string("test");
        let h3 = AttestationEngine::hash_string("different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_verify_unregistered_agent() {
        let engine = create_engine();
        let result = engine.verify_hash("unknown-agent", "abc123").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_hash_matches() {
        let engine = create_engine();
        let hash = "abc123def456";
        engine
            .db
            .attestate_agent("agent-1", hash, Some(1234))
            .unwrap();
        let result = engine.verify_hash("agent-1", hash).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let engine = create_engine();
        engine
            .db
            .attestate_agent("agent-1", "correct-hash", Some(1234))
            .unwrap();
        let result = engine.verify_hash("agent-1", "wrong-hash").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_disabled_engine_always_passes() {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let engine = AttestationEngine::new(db, false);
        let result = engine.verify_hash("unknown", "anything").unwrap();
        assert!(result);
    }
}
