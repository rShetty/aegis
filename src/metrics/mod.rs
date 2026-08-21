//! Prometheus instrumentation (#6).
//!
//! Three metric families are exposed through `GET /metrics` (text
//! exposition format, no authentication — cardinality is bounded and no
//! per-agent or per-destination labels are ever attached):
//!
//! - `aegis_egress_decisions_total{outcome}` — every enforcement verdict
//!   (`allowed` / `blocked` / `error`) from the decision endpoints
//!   (`/api/egress/check`, `/api/geo/check`). Summed, it equals the
//!   `total_requests` figure in `/api/egress/stats`: every audited verdict
//!   is metered exactly once.
//! - `aegis_egress_check_latency_seconds{route}` — wall-clock handler
//!   latency histogram, including requests that failed validation.
//! - `aegis_active_policies` — number of `egress_policies` rows, read from
//!   SQLite **at scrape time** by a custom collector so policies inserted or
//!   deleted out-of-band (another process, manual SQL) are reflected without
//!   a restart and never drift from the database.
//!
//! Liveness/readiness probes are separate endpoints (`/health/live`,
//! `/health/ready`) so a wedged database can fail readiness while liveness —
//! which must stay dependency-free — keeps the orchestrator from restarting
//! a healthy-but-busy process.

use std::sync::Arc;
use std::time::Instant;

use prometheus::core::{Collector, Desc};
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder, proto};

use crate::db::Database;

/// Fully-qualified names of the exported families (single place so tests and
/// the collector cannot drift).
pub const DECISIONS_TOTAL: &str = "aegis_egress_decisions_total";
pub const CHECK_LATENCY_SECONDS: &str = "aegis_egress_check_latency_seconds";
pub const ACTIVE_POLICIES: &str = "aegis_active_policies";

/// All Aegis metrics plus the registry they are scraped from (#6).
pub struct Metrics {
    /// Scrape root exposed through `GET /metrics`.
    pub registry: Registry,

    /// Enforcement verdicts by outcome (`allowed` / `blocked` / `error`).
    pub egress_decisions_total: IntCounterVec,

    /// Wall-clock decision-endpoint latency in seconds, by route.
    pub egress_check_latency_seconds: HistogramVec,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The registry's collectors are not Debug; the family names identify
        // the instance in logs without pulling the database in.
        f.debug_struct("Metrics")
            .field(
                "families",
                &[DECISIONS_TOTAL, CHECK_LATENCY_SECONDS, ACTIVE_POLICIES],
            )
            .finish()
    }
}

impl Metrics {
    /// Build and register every metric family.
    ///
    /// `db` backs the `aegis_active_policies` gauge, which is collected at
    /// scrape time rather than mirrored eagerly.
    pub fn new(db: Arc<Database>) -> prometheus::Result<Self> {
        let registry = Registry::new();

        let egress_decisions_total = IntCounterVec::new(
            Opts::new(
                DECISIONS_TOTAL,
                "Egress enforcement verdicts by outcome (allowed, blocked, error).",
            ),
            &["outcome"],
        )?;

        // Local checks answer in microseconds; the default buckets would
        // collapse every scrape into one bucket, so use sub-ms steps.
        let egress_check_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                CHECK_LATENCY_SECONDS,
                "Wall-clock latency of egress decision endpoints, in seconds.",
            )
            .buckets(vec![
                0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &["route"],
        )?;

        registry.register(Box::new(egress_decisions_total.clone()))?;
        registry.register(Box::new(egress_check_latency_seconds.clone()))?;
        let active_policies = DbGauge::new(
            ACTIVE_POLICIES,
            "Active egress policy rows across all agents, counted in SQLite at scrape time.",
            db,
        )?;
        registry.register(Box::new(active_policies))?;

        Ok(Metrics {
            registry,
            egress_decisions_total,
            egress_check_latency_seconds,
        })
    }

    /// Record one enforcement decision (#6): bump the outcome counter and
    /// observe elapsed wall-clock latency for `route`. Called for every
    /// request that reaches a verdict, allowed or not.
    pub fn observe_decision(&self, route: &str, outcome: &str, started: Instant) {
        self.record_decision(outcome);
        self.observe_latency(route, started);
    }

    /// Count one verdict without timing it.
    pub fn record_decision(&self, outcome: &str) {
        self.egress_decisions_total
            .with_label_values(&[outcome])
            .inc();
    }

    /// Observe elapsed wall-clock latency without counting a verdict — used
    /// for requests that fail validation before enforcement (still latency
    /// data, never a decision).
    pub fn observe_latency(&self, route: &str, started: Instant) {
        self.egress_check_latency_seconds
            .with_label_values(&[route])
            .observe(started.elapsed().as_secs_f64());
    }

    /// Render the registry in the Prometheus text exposition format
    /// (`Content-Type: text/plain; version=0.0.4`).
    ///
    /// Encoding writes to an in-memory buffer over statically-valid
    /// descriptors, so the error arm is unreachable today; it is logged
    /// loudly rather than silently publishing a truncated scrape.
    pub fn render(&self) -> String {
        match TextEncoder::new().encode_to_string(&self.registry.gather()) {
            Ok(body) => body,
            Err(e) => {
                tracing::error!(error = %e, "failed to encode Prometheus metrics");
                String::new()
            }
        }
    }
}

/// A gauge whose value is queried from SQLite whenever the registry is
/// scraped (#6).
///
/// Eagerly mirroring the count into an `IntGauge` on every policy mutation
/// would drift the moment any writer bypasses this process (manual SQL,
/// another replica). Reading the authoritative store per scrape keeps the
/// exported value definitionally equal to `SELECT COUNT(*) FROM
/// egress_policies`.
struct DbGauge {
    desc: Desc,
    db: Arc<Database>,
}

impl std::fmt::Debug for DbGauge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbGauge")
            .field("desc", &self.desc.fq_name)
            .finish_non_exhaustive()
    }
}

impl DbGauge {
    fn new(name: &str, help: &str, db: Arc<Database>) -> prometheus::Result<Self> {
        Ok(DbGauge {
            desc: Desc::new(
                name.to_string(),
                help.to_string(),
                Vec::new(),
                Default::default(),
            )?,
            db,
        })
    }
}

impl Collector for DbGauge {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        let count = self.db.count_egress_policies().unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to count egress policies for scrape");
            0
        });

        let mut gauge = proto::Gauge::default();
        gauge.set_value(count as f64);

        let mut metric = proto::Metric::default();
        metric.set_gauge(gauge);

        let mut family = proto::MetricFamily::default();
        family.set_name(self.desc.fq_name.clone());
        family.set_help(self.desc.help.clone());
        family.set_field_type(proto::MetricType::GAUGE);
        family.set_metric(vec![metric]);

        vec![family]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Arc<Database> {
        Arc::new(Database::new(":memory:").unwrap())
    }

    #[test]
    fn encode_renders_registered_families() {
        let db = mem_db();
        db.add_egress_policy("agent-1", "*", "allow").unwrap();

        let metrics = Metrics::new(db).unwrap();
        metrics
            .egress_decisions_total
            .with_label_values(&["allowed"])
            .inc();
        metrics
            .egress_decisions_total
            .with_label_values(&["allowed"])
            .inc();
        metrics
            .egress_decisions_total
            .with_label_values(&["blocked"])
            .inc();
        metrics.observe_decision("/api/egress/check", "allowed", Instant::now());

        let body = metrics.render();

        assert!(
            body.contains("# TYPE aegis_egress_decisions_total counter"),
            "counter family declared: {body}"
        );
        assert!(
            body.contains("aegis_egress_decisions_total{outcome=\"allowed\"} 3"),
            "allowed counted: {body}"
        );
        assert!(
            body.contains("aegis_egress_decisions_total{outcome=\"blocked\"} 1"),
            "blocked counted separately: {body}"
        );
        assert!(
            body.contains("# TYPE aegis_egress_check_latency_seconds histogram"),
            "histogram family declared: {body}"
        );
        assert!(
            body.contains(
                "aegis_egress_check_latency_seconds_count{route=\"/api/egress/check\"} 1"
            ),
            "latency observed once: {body}"
        );
        assert!(
            body.contains("aegis_egress_check_latency_seconds_bucket{route=\"/api/egress/check\",le=\"0.005\"}"),
            "bucket series present: {body}"
        );
        assert!(
            body.contains("# TYPE aegis_active_policies gauge"),
            "gauge family declared: {body}"
        );
        assert!(
            body.contains("aegis_active_policies 1"),
            "one policy: {body}"
        );
    }

    #[test]
    fn active_policies_gauge_reads_database_at_scrape_time() {
        let db = mem_db();
        let metrics = Metrics::new(db.clone()).unwrap();

        // The registry prunes unobserved vec families from a scrape, but the
        // DB-backed gauge always reports — zero, not absence.
        assert!(
            metrics.render().contains("aegis_active_policies 0"),
            "empty table scrapes as 0"
        );

        let id_a = db
            .add_egress_policy("agent-1", "a.example.com", "allow")
            .unwrap();
        let id_b = db
            .add_egress_policy("agent-1", "b.example.com", "allow")
            .unwrap();
        assert!(
            metrics.render().contains("aegis_active_policies 2"),
            "two policies visible on next scrape"
        );

        db.remove_egress_policy("agent-1", &id_a).unwrap();
        db.remove_egress_policy("agent-1", &id_b).unwrap();
        assert!(
            metrics.render().contains("aegis_active_policies 0"),
            "deletions are reflected without touching the gauge"
        );
    }

    #[test]
    fn outcomes_are_independent_series_not_overwrites() {
        let metrics = Metrics::new(mem_db()).unwrap();
        for outcome in ["allowed", "blocked", "blocked", "error"] {
            metrics.observe_decision("/api/geo/check", outcome, Instant::now());
        }
        let body = metrics.render();
        assert!(body.contains("outcome=\"allowed\"} 1"), "{body}");
        assert!(body.contains("outcome=\"blocked\"} 2"), "{body}");
        assert!(body.contains("outcome=\"error\"} 1"), "{body}");
        assert!(
            body.contains("aegis_egress_check_latency_seconds_count{route=\"/api/geo/check\"} 4"),
            "each decision contributes one latency observation: {body}"
        );
    }
}
