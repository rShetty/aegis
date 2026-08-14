use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::errors::Result;

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

    pub fn add_egress_policy(&self, agent_id: &str, destination: &str, action: &str) -> Result<()> {
        let conn = self.conn.lock();
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO egress_policies (id, agent_id, destination, action, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, agent_id, destination, action, now],
        )?;
        Ok(())
    }

    pub fn get_egress_policies(&self, agent_id: &str) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT destination, action, created_at FROM egress_policies WHERE agent_id = ? ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![agent_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

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
        for (dest, action) in &policies {
            if Self::match_destination(dest, destination) {
                return Ok(Some(action.clone()));
            }
        }
        Ok(None)
    }

    fn match_destination(pattern: &str, destination: &str) -> bool {
        if pattern == "*" || pattern == destination {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*") {
            return destination.ends_with(suffix);
        }
        if let Some(prefix) = pattern.strip_suffix("*") {
            return destination.starts_with(prefix);
        }
        false
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
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO egress_log (agent_id, source_ip, destination, method, status, reason, size_bytes, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![agent_id, source_ip, destination, method, status, reason, size_bytes, now],
        )?;
        Ok(())
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
                let match_result = h == process_hash;
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
