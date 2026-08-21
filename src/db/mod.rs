use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::Result;

/// Constant-time string comparison (#12 F4).
///
/// Compares SHA-256 digests instead of raw bytes so the comparison time does
/// not depend on the position of the first mismatch. Length differences are
/// also masked by hashing both sides to fixed 32-byte values.
fn ct_eq_str(a: &str, b: &str) -> bool {
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for (x, y) in da.iter().zip(db.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct Database {
    conn: Arc<parking_lot::Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            crate::errors::AegisError::Database(format!("failed to open database: {}", e))
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Self::run_migrations(&conn)?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    fn run_migrations(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS egress_policies (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                destination TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_egress_agent ON egress_policies(agent_id);

            CREATE TABLE IF NOT EXISTS egress_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                source_ip TEXT,
                destination TEXT,
                method TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                size_bytes INTEGER,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_egress_log_agent ON egress_log(agent_id);
            CREATE INDEX IF NOT EXISTS idx_egress_log_timestamp ON egress_log(timestamp);

            CREATE TABLE IF NOT EXISTS attested_agents (
                agent_id TEXT PRIMARY KEY,
                process_hash TEXT NOT NULL,
                pid INTEGER,
                start_time TEXT,
                attested_at TEXT NOT NULL,
                last_verified TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_counts (
                agent_id TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                window_start TEXT NOT NULL
            );
        ",
        )?;
        Ok(())
    }

    pub fn add_egress_policy(
        &self,
        agent_id: &str,
        destination: &str,
        action: &str,
    ) -> Result<String> {
        let conn = self.conn.lock();
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO egress_policies (id, agent_id, destination, action, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, agent_id, destination, action, now],
        )?;
        Ok(id)
    }

    /// Whether an agent has been attested (has a row in attested_agents).
    pub fn is_attested(&self, agent_id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM attested_agents WHERE agent_id = ?",
            params![agent_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Remove a specific policy by id, scoped to the agent. Returns whether
    /// a row was deleted.
    pub fn remove_egress_policy(&self, agent_id: &str, policy_id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let deleted = conn.execute(
            "DELETE FROM egress_policies WHERE id = ? AND agent_id = ?",
            params![policy_id, agent_id],
        )?;
        Ok(deleted > 0)
    }

    /// List policies for an agent as `(id, destination, action, created_at)`.
    pub fn get_egress_policies(
        &self,
        agent_id: &str,
    ) -> Result<Vec<(String, String, String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, destination, action, created_at FROM egress_policies WHERE agent_id = ? ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![agent_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Look up the effective policy action for a destination.
    ///
    /// Deny rules are evaluated before allow rules (#2): if any policy
    /// pattern matches and says "deny", the result is denied even when a
    /// broader allow (e.g. `*.github.com`) also matches. Returns
    /// `Some("deny")`, `Some("allow")`, or `None` when no policy matches.
    pub fn check_egress(&self, agent_id: &str, destination: &str) -> Result<Option<String>> {
        let policies = {
            let _conn = self.conn.lock();
            let mut stmt = _conn
                .prepare("SELECT destination, action FROM egress_policies WHERE agent_id = ?")?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row?);
            }
            result
        };

        let mut allow = false;
        // Deny wins over allow regardless of insertion order.
        for (dest, action) in &policies {
            if crate::destination::matches(dest, destination) {
                if action == "deny" {
                    return Ok(Some(action.clone()));
                }
                if action == "allow" {
                    allow = true;
                }
            }
        }
        if allow {
            return Ok(Some("allow".to_string()));
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_egress(
        &self,
        agent_id: Option<&str>,
        source_ip: &str,
        destination: &str,
        method: &str,
        status: &str,
        reason: Option<&str>,
        size_bytes: Option<i64>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.log_egress_at(
            agent_id,
            source_ip,
            destination,
            method,
            status,
            reason,
            size_bytes,
            &now,
        )
    }

    /// Insert an egress log row with an explicit RFC3339 timestamp.
    ///
    /// Production callers should prefer [`Database::log_egress`]; this variant
    /// exists for retention tests and operator backfill of historical rows.
    #[allow(clippy::too_many_arguments)]
    pub fn log_egress_at(
        &self,
        agent_id: Option<&str>,
        source_ip: &str,
        destination: &str,
        method: &str,
        status: &str,
        reason: Option<&str>,
        size_bytes: Option<i64>,
        timestamp: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO egress_log (agent_id, source_ip, destination, method, status, reason, size_bytes, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![agent_id, source_ip, destination, method, status, reason, size_bytes, timestamp],
        )?;
        Ok(())
    }

    /// Delete `egress_log` rows strictly older than `retention_days`.
    ///
    /// Timestamps are stored as RFC3339 strings in UTC (same formatting as
    /// [`Utc::now().to_rfc3339()`]), so lexicographic comparison against the
    /// computed cutoff is order-correct. Returns the number of deleted rows.
    pub fn prune_egress_log(&self, retention_days: u64) -> Result<u64> {
        let days = i64::try_from(retention_days).map_err(|_| {
            crate::errors::AegisError::Config("log_retention_days is too large".to_string())
        })?;
        let delta = chrono::Duration::try_days(days).ok_or_else(|| {
            crate::errors::AegisError::Config("log_retention_days is out of range".to_string())
        })?;
        let cutoff = (Utc::now() - delta).to_rfc3339();
        let conn = self.conn.lock();
        let deleted = conn.execute(
            "DELETE FROM egress_log WHERE timestamp < ?1",
            params![cutoff],
        )?;
        Ok(deleted as u64)
    }

    pub fn list_egress_log(&self, limit: i64) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, source_ip, destination, method, status, reason, size_bytes, timestamp
             FROM egress_log ORDER BY id DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let agent_id: Option<String> = row.get(1)?;
            let reason: Option<String> = row.get(6)?;
            let size: Option<i64> = row.get(7)?;
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "agent_id": agent_id,
                "source_ip": row.get::<_, String>(2)?,
                "destination": row.get::<_, String>(3)?,
                "method": row.get::<_, String>(4)?,
                "status": row.get::<_, String>(5)?,
                "reason": reason,
                "size_bytes": size,
                "timestamp": row.get::<_, String>(8)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn attestate_agent(
        &self,
        agent_id: &str,
        process_hash: &str,
        pid: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO attested_agents (agent_id, process_hash, pid, start_time, attested_at, last_verified)
             VALUES (?, ?, ?, NULL, ?, ?)",
            params![agent_id, process_hash, pid, now, now],
        )?;
        Ok(())
    }

    pub fn verify_agent(&self, agent_id: &str, process_hash: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let stored_hash: Option<String> = conn
            .query_row(
                "SELECT process_hash FROM attested_agents WHERE agent_id = ?",
                params![agent_id],
                |row| row.get(0),
            )
            .ok();
        match stored_hash {
            Some(h) => {
                // Constant-time comparison (#12 F4): this runs behind the
                // unauthenticated data-plane endpoint /api/attestation/verify,
                // so a short-circuiting `==` lets a local attacker recover
                // the registered process hash one byte at a time via
                // response-timing analysis — and with it, impersonate an
                // attested agent. Comparing SHA-256 digests makes the
                // comparison time independent of how many leading bytes
                // matched.
                let match_result = ct_eq_str(&h, process_hash);
                if match_result {
                    let now = Utc::now().to_rfc3339();
                    conn.execute(
                        "UPDATE attested_agents SET last_verified = ? WHERE agent_id = ?",
                        params![now, agent_id],
                    )?;
                }
                Ok(match_result)
            }
            None => Ok(false),
        }
    }

    pub fn list_attested_agents(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT agent_id, process_hash, pid, attested_at, last_verified FROM attested_agents",
        )?;
        let rows = stmt.query_map([], |row| {
            let pid: Option<i64> = row.get(2)?;
            Ok(serde_json::json!({
                "agent_id": row.get::<_, String>(0)?,
                "process_hash": row.get::<_, String>(1)?,
                "pid": pid,
                "attested_at": row.get::<_, String>(3)?,
                "last_verified": row.get::<_, String>(4)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn egress_stats(&self) -> Result<serde_json::Value> {
        let conn = self.conn.lock();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM egress_log", [], |row| row.get(0))?;
        let allowed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM egress_log WHERE status = 'allowed'",
            [],
            |row| row.get(0),
        )?;
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM egress_log WHERE status = 'blocked'",
            [],
            |row| row.get(0),
        )?;
        Ok(serde_json::json!({
            "total_requests": total,
            "allowed": allowed,
            "blocked": blocked,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Database {
        Database::new(":memory:").unwrap()
    }

    /// Seed a log row at `age_days` in the past and return nothing; the
    /// explicit-timestamp insert is what retention tests rely on.
    fn seed(db: &Database, agent: &str, destination: &str, age_days: u64) {
        let ts = (Utc::now() - chrono::Duration::try_days(age_days as i64).unwrap()).to_rfc3339();
        db.log_egress_at(
            Some(agent),
            "127.0.0.1",
            destination,
            "CONNECT",
            "allowed",
            None,
            None,
            &ts,
        )
        .unwrap();
    }

    #[test]
    fn prune_removes_only_rows_older_than_retention() {
        let db = mem_db();
        seed(&db, "agent-1", "old.example.com", 40);
        seed(&db, "agent-1", "older.example.com", 365);
        seed(&db, "agent-1", "fresh.example.com", 1);

        let pruned = db.prune_egress_log(30).unwrap();
        assert_eq!(pruned, 2, "the two expired rows must be deleted");

        let remaining = db.list_egress_log(10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["destination"], "fresh.example.com");
    }

    #[test]
    fn prune_with_nothing_expired_returns_zero_and_keeps_rows() {
        let db = mem_db();
        seed(&db, "agent-1", "a.example.com", 5);
        seed(&db, "agent-1", "b.example.com", 0);
        assert_eq!(db.prune_egress_log(30).unwrap(), 0);
        assert_eq!(db.list_egress_log(10).unwrap().len(), 2);
    }

    #[test]
    fn prune_on_empty_table_is_zero() {
        let db = mem_db();
        assert_eq!(db.prune_egress_log(30).unwrap(), 0);
    }

    #[test]
    fn repeated_prunes_do_not_double_count_deletions() {
        let db = mem_db();
        seed(&db, "agent-1", "old.example.com", 90);
        assert_eq!(db.prune_egress_log(30).unwrap(), 1);
        assert_eq!(db.prune_egress_log(30).unwrap(), 0, "already deleted");
    }

    #[test]
    fn pruned_rows_are_reflected_in_stats() {
        let db = mem_db();
        seed(&db, "agent-1", "old.example.com", 40);
        seed(&db, "agent-1", "fresh.example.com", 2);
        let _ = db.prune_egress_log(30).unwrap();
        let stats = db.egress_stats().unwrap();
        assert_eq!(stats["total_requests"], 1);
        assert_eq!(stats["allowed"], 1);
        assert_eq!(stats["blocked"], 0);
    }

    #[test]
    fn log_egress_at_preserves_explicit_timestamp() {
        let db = mem_db();
        let ts = (Utc::now() - chrono::Duration::try_hours(48).unwrap()).to_rfc3339();
        db.log_egress_at(
            Some("a"),
            "127.0.0.1",
            "x.com",
            "CONNECT",
            "blocked",
            None,
            None,
            &ts,
        )
        .unwrap();
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows[0]["timestamp"], serde_json::json!(ts));
    }

    // ---------------- timing-safe hash verification (#12 F4) ----------------

    #[test]
    fn verify_agent_accepts_exact_hash_and_rejects_wrong_and_partial() {
        let db = mem_db();
        db.attestate_agent("agent-1", "deadbeef", Some(1)).unwrap();
        assert!(db.verify_agent("agent-1", "deadbeef").unwrap());
        assert!(!db.verify_agent("agent-1", "deadbeee").unwrap());
        assert!(!db.verify_agent("agent-1", "").unwrap());
        assert!(!db.verify_agent("agent-1", "deadbeef00").unwrap());
    }

    #[test]
    fn ct_eq_str_is_exact_match_only() {
        assert!(ct_eq_str("abc", "abc"));
        assert!(!ct_eq_str("abc", "abd"));
        assert!(!ct_eq_str("abc", "ab"));
        assert!(!ct_eq_str("abc", "abcd"));
        assert!(!ct_eq_str("", "x"));
        assert!(ct_eq_str("", ""));
    }
}
