use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::Result;

/// Current schema version, mirrored into `PRAGMA user_version` after every
/// successful migration run (#7). Bump when adding a migration step.
const SCHEMA_VERSION: i64 = 2;

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
        // Versioned schema migrations (#7). `PRAGMA user_version` starts at 0
        // for both fresh databases and databases created by older builds
        // (which had no migration tracking at all); each step below brings
        // either kind of database up to the current shape idempotently.
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if version < 1 {
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
        }

        // v1 -> v2 (#7): true request metadata in egress_log. The verdict
        // columns (source_ip/method/size_bytes) existed from v1 — the bug was
        // fake *values*, not missing columns. v2 adds nullable provenance
        // columns; historical rows backfill as NULL, which beats carrying
        // over their placeholder values.
        if version < 2 {
            let existing = Self::table_columns(conn, "egress_log")?;
            // Skip when the column already exists so re-running on a partially
            // upgraded database stays idempotent.
            for (ddl, name) in [
                ("forwarded_for TEXT", "forwarded_for"),
                ("user_agent TEXT", "user_agent"),
            ] {
                if !existing.iter().any(|c| c == name) {
                    conn.execute_batch(&format!("ALTER TABLE egress_log ADD COLUMN {ddl};"))?;
                }
            }
        }

        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(())
    }

    /// Column names of a table, or an empty vector when it does not exist.
    fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut cols = Vec::new();
        for row in rows {
            cols.push(row?);
        }
        Ok(cols)
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

    /// Insert an egress log row, timestamped now.
    ///
    /// `source_ip`, `method`, and `size_bytes` are the real per-request values
    /// (#7) resolved by the caller — see `crate::net::resolve_client_ip`.
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
            None,
            None,
            &now,
        )
    }

    /// Insert an egress log row with full provenance and an explicit
    /// RFC3339 timestamp.
    ///
    /// Production callers should prefer [`Database::log_egress`]; this variant
    /// exists for retention tests, operator backfill of historical rows, and
    /// the HTTP layer which captures forwarded/user-agent headers (#7).
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
        forwarded_for: Option<&str>,
        user_agent: Option<&str>,
        timestamp: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO egress_log (agent_id, source_ip, destination, method, status, reason, size_bytes, forwarded_for, user_agent, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![agent_id, source_ip, destination, method, status, reason, size_bytes, forwarded_for, user_agent, timestamp],
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
            "SELECT id, agent_id, source_ip, destination, method, status, reason, size_bytes, forwarded_for, user_agent, timestamp
             FROM egress_log ORDER BY id DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let agent_id: Option<String> = row.get(1)?;
            let reason: Option<String> = row.get(6)?;
            let size: Option<i64> = row.get(7)?;
            let forwarded_for: Option<String> = row.get(8)?;
            let user_agent: Option<String> = row.get(9)?;
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "agent_id": agent_id,
                "source_ip": row.get::<_, String>(2)?,
                "destination": row.get::<_, String>(3)?,
                "method": row.get::<_, String>(4)?,
                "status": row.get::<_, String>(5)?,
                "reason": reason,
                "size_bytes": size,
                "forwarded_for": forwarded_for,
                "user_agent": user_agent,
                "timestamp": row.get::<_, String>(10)?,
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

    /// Number of policy rows across all agents (#6).
    ///
    /// Backs the `aegis_active_policies` gauge, which queries SQLite at
    /// scrape time so out-of-band policy changes are reflected immediately.
    pub fn count_egress_policies(&self) -> Result<i64> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM egress_policies", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Test-only: raw connection access for simulating database failures
    /// (e.g. dropping a table) in readiness-probe tests (#6).
    #[cfg(test)]
    pub(crate) fn conn_for_test(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
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
    use std::ops::DerefMut;

    fn mem_db() -> Database {
        Database::new(":memory:").unwrap()
    }

    /// Seed a log row at `age_days` in the past and return nothing; the
    /// explicit-timestamp insert is what retention tests rely on.
    fn seed(db: &Database, agent: &str, destination: &str, age_days: u64) {
        let ts = (Utc::now() - chrono::Duration::try_days(age_days as i64).unwrap()).to_rfc3339();
        db.log_egress_at(
            Some(agent),
            "192.0.2.50",
            destination,
            "POST",
            "allowed",
            None,
            Some(2048),
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
            "POST",
            "blocked",
            None,
            None,
            None,
            None,
            &ts,
        )
        .unwrap();
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows[0]["timestamp"], serde_json::json!(ts));
    }

    // ---------------- true request metadata in egress_log (#7) ----------------

    #[test]
    fn logged_values_round_trip_exactly() {
        let db = mem_db();
        db.log_egress(
            Some("agent-7"),
            "198.51.100.77",
            "api.example.com",
            "PUT",
            "allowed",
            None,
            Some(123_456),
        )
        .unwrap();
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["source_ip"], "198.51.100.77", "real client IP stored");
        assert_eq!(row["method"], "PUT", "actual HTTP method stored");
        assert_eq!(row["size_bytes"], 123_456, "body size stored");
        assert_eq!(row["forwarded_for"], serde_json::Value::Null);
        assert_eq!(row["user_agent"], serde_json::Value::Null);
    }

    #[test]
    fn provenance_columns_round_trip() {
        let db = mem_db();
        db.log_egress_at(
            Some("agent-7"),
            "203.0.113.4",
            "api.example.com",
            "GET",
            "allowed",
            None,
            None,
            Some("198.51.100.9, 10.0.0.2"),
            Some("aegis-harness/1.0"),
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let row = &db.list_egress_log(10).unwrap()[0];
        assert_eq!(row["source_ip"], "203.0.113.4");
        assert_eq!(row["forwarded_for"], "198.51.100.9, 10.0.0.2");
        assert_eq!(row["user_agent"], "aegis-harness/1.0");
    }

    #[test]
    fn legacy_database_is_migrated_in_place() {
        // Build a v1-shaped database by hand: the schema as it existed before
        // #7, with a placeholder row exactly as old builds wrote them.
        let file = tempfile::tempdir().unwrap();
        let path = file.path().join("legacy.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE egress_policies (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE egress_log (
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
                CREATE TABLE attested_agents (
                    agent_id TEXT PRIMARY KEY,
                    process_hash TEXT NOT NULL,
                    pid INTEGER,
                    start_time TEXT,
                    attested_at TEXT NOT NULL,
                    last_verified TEXT NOT NULL
                );
                CREATE TABLE connection_counts (
                    agent_id TEXT PRIMARY KEY,
                    count INTEGER NOT NULL DEFAULT 0,
                    window_start TEXT NOT NULL
                );

                INSERT INTO egress_log (agent_id, source_ip, destination, method, status, reason, size_bytes, timestamp)
                VALUES ('agent-old', '127.0.0.1', 'example.com', 'CONNECT', 'allowed', NULL, NULL, '2026-01-01T00:00:00+00:00');
            ",
            )
            .unwrap();
            // Old builds never set user_version.
            let v: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, 0, "precondition: hand-built legacy DB is unversioned");
        }

        // Opening with current code migrates in place and preserves data.
        let db = Database::new(path.to_str().unwrap()).unwrap();
        let cols = Database::table_columns(db.conn.lock().deref_mut(), "egress_log").unwrap();
        assert!(
            cols.contains(&"forwarded_for".to_string()),
            "cols: {cols:?}"
        );
        assert!(cols.contains(&"user_agent".to_string()), "cols: {cols:?}");
        let version: i64 = {
            let conn = db.conn.lock();
            conn.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(version, SCHEMA_VERSION);

        // Historical row survives; new writes carry full metadata.
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows.len(), 1, "migration must not lose data");
        assert_eq!(rows[0]["method"], "CONNECT");
        assert_eq!(
            rows[0]["forwarded_for"],
            serde_json::Value::Null,
            "historical rows backfill as NULL"
        );

        db.log_egress(
            Some("new-agent"),
            "198.51.100.9",
            "x.com",
            "POST",
            "allowed",
            None,
            Some(42),
        )
        .unwrap();
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["size_bytes"], 42);
    }

    #[test]
    fn fresh_database_is_created_at_current_version_and_migration_is_idempotent() {
        let file = tempfile::tempdir().unwrap();
        let path = file.path().join("fresh.db");

        // First open creates everything at SCHEMA_VERSION.
        let db = Database::new(path.to_str().unwrap()).unwrap();
        let version: i64 = {
            let conn = db.conn.lock();
            conn.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(version, SCHEMA_VERSION);
        drop(db);

        // Re-opening runs the migration path again from the current version:
        // no duplicate columns, no errors, data intact.
        let db = Database::new(path.to_str().unwrap()).unwrap();
        db.log_egress(
            Some("a"),
            "192.0.2.9",
            "y.com",
            "DELETE",
            "allowed",
            None,
            Some(7),
        )
        .unwrap();
        let rows = db.list_egress_log(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["method"], "DELETE");
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
