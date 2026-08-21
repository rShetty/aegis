//! HTTP server layer: routing, admin authentication, CORS.
//!
//! Security model (#1):
//! - **Admin plane** (policy CRUD, attestation registration/listing, log and
//!   stats reads) requires `Authorization: Bearer <AEGIS_ADMIN_TOKEN>`,
//!   compared in constant time via SHA-256 digests.
//! - **Data plane** (`/api/egress/check`, `/api/geo/check`,
//!   `/api/attestation/verify`) is callable by agents; it is protected by
//!   network-level trust: Aegis binds to loopback by default, and operators
//!   must place it behind a trusted network boundary if agents are remote.
//! - Release builds refuse to start without an admin token unless
//!   `AEGIS_INSECURE_DEV=1` is set explicitly.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::Utc;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    attestation::AttestationEngine, config::Config, db::Database, egress::EgressEngine,
    egress::RequestContext, errors::AegisError, geo::GeoEngine, metrics::Metrics,
    net::TrustedProxies,
};

/// Paths under /api that belong to the agent data plane and do NOT require
/// the admin token. Everything else under /api is admin-only.
const DATA_PLANE_PATHS: [&str; 3] = [
    "/api/egress/check",
    "/api/geo/check",
    "/api/attestation/verify",
];

/// `X-Forwarded-For` has no constant in `http::header` (#7).
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

fn is_admin_path(path: &str) -> bool {
    path.starts_with("/api/") && !DATA_PLANE_PATHS.contains(&path)
}

/// Admin bearer token. The raw token is never stored; only its SHA-256
/// digest is kept, and verification compares digests in constant time.
#[derive(Clone)]
pub struct AdminToken {
    digest: Arc<[u8; 32]>,
}

impl AdminToken {
    pub fn new(raw: &str) -> Self {
        AdminToken {
            digest: Arc::new(Self::digest_of(raw)),
        }
    }

    fn digest_of(raw: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(raw.trim().as_bytes());
        hasher.finalize().into()
    }

    /// Constant-time comparison of the presented token against the stored
    /// digest (compares fixed-size hashes so length leaks nothing useful).
    pub fn verify(&self, presented: &str) -> bool {
        let candidate = Self::digest_of(presented);
        ct_eq_32(&self.digest, &candidate)
    }
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Run a blocking (SQLite / filesystem) operation on the dedicated blocking
/// threadpool instead of a tokio worker (#5).
pub(crate) async fn run_blocking<T, F>(f: F) -> Result<T, AegisError>
where
    F: FnOnce() -> Result<T, AegisError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AegisError::Internal(format!("blocking task failed to complete: {e}")))?
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub egress: Arc<EgressEngine>,
    pub attestation: Arc<AttestationEngine>,
    pub geo: Arc<GeoEngine>,
    /// `None` only in explicit insecure-dev mode; then the admin plane is
    /// open and a loud warning is logged at startup.
    pub admin_token: Option<AdminToken>,
    pub cors_allowed_origins: Arc<Vec<String>>,
    /// Shared counters for egress_log retention pruning (#10).
    pub retention: Arc<RetentionState>,
    /// Allowlist of proxies permitted to set `X-Forwarded-For` (#7). Empty:
    /// XFF is never honored, source_ip is always the direct peer.
    pub trusted_proxies: Arc<TrustedProxies>,
    /// Prometheus instrumentation (#6), scraped via `GET /metrics`.
    pub metrics: Arc<Metrics>,
}

/// Bookkeeping for `egress_log` retention (#10): the configured window plus
/// prune counters surfaced through `/api/egress/stats`.
pub struct RetentionState {
    /// Delete log rows older than this many days.
    pub retention_days: u64,
    /// Cumulative rows removed since server start (background task + manual
    /// endpoint combined).
    pub pruned_total: AtomicU64,
    /// Rows removed by the most recent prune that actually deleted rows
    /// (idle runs do not reset this).
    pub last_pruned: AtomicU64,
    /// RFC3339 timestamp of the most recent prune that deleted rows.
    pub last_prune_at: Mutex<Option<String>>,
}

impl RetentionState {
    fn new(retention_days: u64) -> Self {
        RetentionState {
            retention_days,
            pruned_total: AtomicU64::new(0),
            last_pruned: AtomicU64::new(0),
            last_prune_at: Mutex::new(None),
        }
    }
}

impl AppState {
    pub fn new(db: Arc<Database>, config: &Config, admin_token: Option<AdminToken>) -> Self {
        let metrics = Arc::new(
            Metrics::new(db.clone())
                .expect("static Prometheus metric descriptors are valid and freshly constructed"),
        );
        let egress = Arc::new(EgressEngine::new(
            db.clone(),
            config.egress.clone(),
            config.attestation.require_attestation,
        ));
        let attestation = Arc::new(AttestationEngine::new(
            db.clone(),
            config.attestation.enabled,
        ));
        let geo = Arc::new(GeoEngine::new(&config.geo));
        AppState {
            db,
            egress,
            attestation,
            geo,
            admin_token,
            cors_allowed_origins: Arc::new(config.server.cors_allowed_origins.clone()),
            retention: Arc::new(RetentionState::new(config.egress.log_retention_days)),
            trusted_proxies: Arc::new(TrustedProxies::from_config(&config.server.trusted_proxies)),
            metrics,
        }
    }
}

/// True per-request metadata captured before the body is consumed (#7).
struct RequestMeta {
    source_ip: String,
    method: String,
    forwarded_for: Option<String>,
    user_agent: Option<String>,
}

impl RequestMeta {
    /// Capture from the incoming request. The socket peer is authoritative;
    /// `X-Forwarded-For` counts only when the peer is a configured trusted
    /// proxy. Failures fall back to the peer, never to a placeholder constant.
    fn capture(req: &Request, peer: std::net::SocketAddr, trusted: &TrustedProxies) -> Self {
        let forwarded_for = req
            .headers()
            .get(&X_FORWARDED_FOR)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        RequestMeta {
            source_ip: crate::net::resolve_client_ip(peer.ip(), forwarded_for.as_deref(), trusted),
            method: req.method().to_string(),
            forwarded_for,
            user_agent: req
                .headers()
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }
}

/// The direct socket peer of a request, or loopback when absent.
///
/// Production requests carry `ConnectInfo` (via
/// `into_make_service_with_connect_info`); unit-test `oneshot` calls carry
/// `MockConnectInfo` instead. Both name the same truth: the socket peer.
fn peer_of(req: &Request) -> std::net::SocketAddr {
    use axum::extract::connect_info::MockConnectInfo;
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<std::net::SocketAddr>>() {
        return *addr;
    }
    if let Some(MockConnectInfo(addr)) = req
        .extensions()
        .get::<MockConnectInfo<std::net::SocketAddr>>()
    {
        return *addr;
    }
    "127.0.0.1:0".parse().expect("static SocketAddr")
}

/// Prune expired `egress_log` rows once, updating the shared retention
/// counters. Returns the number of rows deleted this run.
async fn run_prune_once(state: &AppState) -> Result<u64, AegisError> {
    let retention = state.retention.clone();
    let db = state.db.clone();
    let pruned = run_blocking(move || db.prune_egress_log(retention.retention_days)).await?;
    if pruned > 0 {
        tracing::info!(pruned, "pruned expired egress_log rows");
        // Only record prunes that actually removed rows: idle ticks must not
        // reset `last_pruned`/`last_prune_at` to zero.
        let retention = state.retention.clone();
        retention.pruned_total.fetch_add(pruned, Ordering::Relaxed);
        retention.last_pruned.store(pruned, Ordering::Relaxed);
        *retention.last_prune_at.lock() = Some(Utc::now().to_rfc3339());
    }
    Ok(pruned)
}

/// Spawn the background retention loop (#10).
///
/// Prunes once immediately at startup, then every `period`. The returned task
/// must be aborted after the server shuts down; callers own its lifetime.
pub fn spawn_retention_task(state: &AppState, period: Duration) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(e) = run_prune_once(&state).await {
                // A failed prune must never take the control plane down;
                // the next tick retries.
                tracing::error!(error = %e, "background egress_log prune failed");
            }
        }
    })
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AegisError> {
    if is_admin_path(req.uri().path()) {
        // Insecure-dev mode: no token configured, admin plane intentionally
        // open (startup logs a warning). Never the case in release builds
        // without AEGIS_INSECURE_DEV=1.
        if let Some(expected) = &state.admin_token {
            let presented = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));
            match presented {
                Some(token) if expected.verify(token) => {}
                _ => {
                    return Err(AegisError::Unauthorized(
                        "missing or invalid admin bearer token".to_string(),
                    ));
                }
            }
        }
    }
    Ok(next.run(req).await)
}

fn build_cors(origins: &[String]) -> Result<CorsLayer, AegisError> {
    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    for origin in origins {
        let value: HeaderValue = origin.parse().map_err(|_| {
            AegisError::Config(format!("invalid cors_allowed_origins entry: '{origin}'"))
        })?;
        cors = cors.allow_origin(value);
    }
    // With no origins configured, no cross-origin access is granted at all:
    // preflights are rejected and simple responses carry no ACAO headers.
    Ok(cors)
}

pub fn build_router(state: AppState) -> Result<Router, AegisError> {
    let cors = build_cors(&state.cors_allowed_origins)?;
    Ok(Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(metrics))
        .route("/api/egress/check", post(check_egress))
        .route(
            "/api/egress/policies/{agent_id}",
            get(list_policies).post(add_policy),
        )
        .route(
            "/api/egress/policies/{agent_id}/{policy_id}",
            delete(remove_policy),
        )
        .route("/api/egress/log", get(egress_log))
        .route("/api/egress/stats", get(egress_stats))
        .route("/api/egress/prune", post(prune_egress_log))
        .route("/api/attestation/attestate", post(attestate_agent))
        .route("/api/attestation/verify", post(verify_agent))
        .route("/api/attestation/agents", get(list_attested))
        .route("/api/geo/check", post(check_geo))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state))
}

/// Liveness probe (#6).
///
/// Deliberately dependency-free: the process is alive iff it can serve HTTP.
/// A wedged database must flip readiness, not liveness — restarting a
/// healthy-but-busy instance fixes nothing and loses in-flight work.
async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "aegis"})),
    )
}

/// Alias of [`health`] for orchestrators expecting `/health/live` (#6). The
/// response body is intentionally identical so dashboards can treat them as
/// one series.
async fn health_live() -> (StatusCode, Json<serde_json::Value>) {
    health().await
}

/// Readiness probe with a real database round-trip (#6): a `SELECT COUNT(*)
/// FROM egress_policies` is executed on the blocking pool, exactly as real
/// traffic would. 200 only when the query succeeds; any failure maps to 503
/// so load balancers drain the instance instead of routing to it.
///
/// The count itself is discarded — this endpoint proves *reachability*, not
/// data volume.
async fn health_ready(State(state): State<AppState>) -> Response {
    let db = state.db.clone();
    match run_blocking(move || db.count_egress_policies()).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "service": "aegis",
                "checks": {"database": "ok"},
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "readiness probe: database check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "unavailable",
                    "service": "aegis",
                    "checks": {"database": "error"},
                })),
            )
                .into_response()
        }
    }
}

/// Prometheus scrape endpoint (#6), public like the probes: cardinality is
/// bounded (three families, no per-agent labels) and it leaks no policy or
/// agent identity.
async fn metrics(State(state): State<AppState>) -> Response {
    let mut response = (StatusCode::OK, state.metrics.render()).into_response();
    if let Ok(value) = HeaderValue::from_str(PROMETHEUS_CONTENT_TYPE) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

/// `Content-Type` of the Prometheus text exposition format, version 0.0.4.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

#[derive(serde::Deserialize)]
struct CheckEgressRequest {
    agent_id: Option<String>,
    destination: String,
}

async fn check_egress(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, AegisError> {
    // Wall-clock latency for the metrics histogram (#6): starts before any
    // work, so validation failures are timed too.
    let started = Instant::now();

    // Capture true request metadata (#7) BEFORE the body is consumed:
    // trusted-proxy-aware client IP, actual HTTP method, header provenance.
    let peer = peer_of(&request);
    let meta = RequestMeta::capture(&request, peer, &state.trusted_proxies);

    let size_cap = state.egress.config.max_request_size_bytes;
    let bytes = match to_bytes_limited(request.into_body(), size_cap).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // Timed but not a verdict (#6): the request never reached
            // enforcement, so no decision counter moves.
            state.metrics.observe_latency("/api/egress/check", started);
            return Err(e);
        }
    };
    let size_bytes = Some(bytes.len() as i64);
    let req: CheckEgressRequest = match serde_json::from_slice(&bytes) {
        Ok(req) => req,
        Err(e) => {
            state.metrics.observe_latency("/api/egress/check", started);
            return Err(AegisError::BadRequest(format!("invalid JSON body: {e}")));
        }
    };

    let CheckEgressRequest {
        agent_id,
        destination,
    } = req;
    let ctx = RequestContext::new(meta.source_ip, meta.method)
        .with_size(size_bytes)
        .with_provenance(meta.forwarded_for, meta.user_agent);

    // Geo residency check FIRST (#12 F2): it is part of the verdict. Running
    // it after EgressEngine::check used to persist an "allowed" audit row
    // for requests that were then rejected by the geo gate.
    //
    // Every terminal outcome is metered (#6): `blocked` for geo and policy
    // rejections, `error` for infrastructure failures, `allowed` otherwise.
    let geo = state.geo.clone();
    let destination_for_geo = destination.clone();
    if let Err(err) = run_blocking(move || geo.check_destination(&destination_for_geo)).await {
        state.metrics.observe_decision(
            "/api/egress/check",
            if err.is_infrastructure_failure() {
                "error"
            } else {
                "blocked"
            },
            started,
        );
        return Err(err);
    }

    let egress = state.egress.clone();
    let agent_for_check = agent_id.clone();
    let destination_for_check = destination.clone();
    match run_blocking(move || {
        egress.check_with_ctx(agent_for_check.as_deref(), &destination_for_check, &ctx)
    })
    .await
    {
        Ok(()) => {
            state
                .metrics
                .observe_decision("/api/egress/check", "allowed", started);
            Ok(Json(serde_json::json!({
                "allowed": true,
                "destination": destination,
                "agent_id": agent_id,
            })))
        }
        Err(err) => {
            state.metrics.observe_decision(
                "/api/egress/check",
                if err.is_infrastructure_failure() {
                    "error"
                } else {
                    "blocked"
                },
                started,
            );
            Err(err)
        }
    }
}

/// Read a request body into memory with a hard cap so a hostile client cannot
/// balloon allocations before the size is even known.
async fn to_bytes_limited(
    body: axum::body::Body,
    max: usize,
) -> Result<axum::body::Bytes, AegisError> {
    axum::body::to_bytes(body, max)
        .await
        .map_err(|e| AegisError::BadRequest(format!("failed to read request body: {e}")))
}

async fn list_policies(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let db = state.db.clone();
    let agent_for_db = agent_id.clone();
    let policies = run_blocking(move || db.get_egress_policies(&agent_for_db)).await?;
    let result: Vec<serde_json::Value> = policies
        .into_iter()
        .map(|(id, dest, action, created)| {
            serde_json::json!({
                "id": id,
                "destination": dest,
                "action": action,
                "created_at": created,
            })
        })
        .collect();
    Ok(Json(
        serde_json::json!({"agent_id": agent_id, "policies": result}),
    ))
}

#[derive(serde::Deserialize)]
struct AddPolicyRequest {
    destination: String,
    action: String,
}

async fn add_policy(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<AddPolicyRequest>,
) -> Result<Json<serde_json::Value>, AegisError> {
    // Strict action validation (#3).
    if !crate::config::is_valid_action(&req.action) {
        return Err(AegisError::BadRequest(format!(
            "invalid action '{}': must be one of {:?}",
            req.action,
            crate::config::VALID_ACTIONS
        )));
    }
    let db = state.db.clone();
    let agent_for_db = agent_id.clone();
    let destination = req.destination.clone();
    let action = req.action.clone();
    let id =
        run_blocking(move || db.add_egress_policy(&agent_for_db, &destination, &action)).await?;
    Ok(Json(
        serde_json::json!({"added": true, "id": id, "agent_id": agent_id, "destination": req.destination, "action": req.action}),
    ))
}

async fn remove_policy(
    State(state): State<AppState>,
    Path((agent_id, policy_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let db = state.db.clone();
    let agent_for_db = agent_id;
    let policy_for_db = policy_id.clone();
    let removed =
        run_blocking(move || db.remove_egress_policy(&agent_for_db, &policy_for_db)).await?;
    if removed {
        Ok(Json(serde_json::json!({"removed": true, "id": policy_id})))
    } else {
        Err(AegisError::PolicyNotFound(policy_id))
    }
}

async fn egress_log(
    State(state): State<AppState>,
    Query(params): Query<LogQuery>,
) -> Result<Json<Vec<serde_json::Value>>, AegisError> {
    // Clamp `limit` (#12 F3): a raw negative value flows into SQLite's LIMIT
    // where it means "unlimited" (full-table dump of the audit log), and an
    // unbounded positive lets one request allocate unbounded memory. Clamp
    // into [0, 1000] instead of rejecting, so existing callers keep working.
    let limit = params.limit.unwrap_or(100).clamp(0, 1000);
    let db = state.db.clone();
    let log = run_blocking(move || db.list_egress_log(limit)).await?;
    Ok(Json(log))
}

#[derive(serde::Deserialize)]
struct LogQuery {
    limit: Option<i64>,
}

async fn egress_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let db = state.db.clone();
    let mut stats = run_blocking(move || db.egress_stats()).await?;
    // Retention bookkeeping (#10): prune counters live in memory (since
    // server start), the retention window comes from config.
    let retention = &state.retention;
    stats["retention"] = serde_json::json!({
        "retention_days": retention.retention_days,
        "pruned_total": retention.pruned_total.load(Ordering::Relaxed),
        "last_pruned": retention.last_pruned.load(Ordering::Relaxed),
        "last_prune_at": retention.last_prune_at.lock().clone(),
    });
    Ok(Json(stats))
}

/// Manual prune trigger (#10). Admin-only by virtue of not being on the data
/// plane; uses the configured `log_retention_days` window.
async fn prune_egress_log(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let pruned = run_prune_once(&state).await?;
    Ok(Json(serde_json::json!({
        "pruned": pruned,
        "retention_days": state.retention.retention_days,
        "pruned_total": state.retention.pruned_total.load(Ordering::Relaxed),
    })))
}

#[derive(serde::Deserialize)]
struct AttestateRequest {
    agent_id: String,
    binary_path: String,
    pid: Option<i64>,
}

async fn attestate_agent(
    State(state): State<AppState>,
    Json(req): Json<AttestateRequest>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let attestation = state.attestation.clone();
    let agent_for_db = req.agent_id.clone();
    let binary_path = req.binary_path.clone();
    let pid = req.pid;
    let hash =
        run_blocking(move || attestation.attestate(&agent_for_db, &binary_path, pid)).await?;
    Ok(Json(serde_json::json!({
        "attested": true,
        "agent_id": req.agent_id,
        "process_hash": hash,
    })))
}

#[derive(serde::Deserialize)]
struct VerifyRequest {
    agent_id: String,
    binary_path: Option<String>,
    process_hash: Option<String>,
}

async fn verify_agent(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let attestation = state.attestation.clone();
    let agent_for_db = req.agent_id.clone();
    let binary_path = req.binary_path.clone();
    let process_hash = req.process_hash.clone();
    let verified = run_blocking(move || {
        if let Some(path) = &binary_path {
            attestation.verify(&agent_for_db, path)
        } else if let Some(hash) = &process_hash {
            attestation.verify_hash(&agent_for_db, hash)
        } else {
            Ok(false)
        }
    })
    .await?;
    Ok(Json(serde_json::json!({
        "agent_id": req.agent_id,
        "verified": verified,
    })))
}

async fn list_attested(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, AegisError> {
    let db = state.db.clone();
    let agents = run_blocking(move || db.list_attested_agents()).await?;
    Ok(Json(agents))
}

#[derive(serde::Deserialize)]
struct CheckGeoRequest {
    destination: String,
}

async fn check_geo(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, AegisError> {
    // Latency starts before the body is read (#6): validation failures are
    // timed like every other terminal outcome.
    let started = Instant::now();

    // True request metadata for the audit rows (#7).
    let peer = peer_of(&request);
    let meta = RequestMeta::capture(&request, peer, &state.trusted_proxies);

    let size_cap = state.egress.config.max_request_size_bytes;
    let bytes = to_bytes_limited(request.into_body(), size_cap).await?;
    let size_bytes = Some(bytes.len() as i64);
    let req: CheckGeoRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AegisError::BadRequest(format!("invalid JSON body: {e}")))?;
    let CheckGeoRequest { destination } = req;
    // RFC3339 "now" captured once so both verdict branches stamp identically.
    let now = Utc::now().to_rfc3339();

    // Audit the geo verdict (#12 F7): this endpoint previously returned
    // allow/deny with no egress_log row at all, leaving data-residency
    // enforcement invisible to operators. Both outcomes are recorded — and
    // both are metered (#6), with `error` reserved for infrastructure
    // failures so a database outage never inflates "blocked".
    let geo = state.geo.clone();
    let destination_for_geo = destination.clone();
    let outcome = run_blocking(move || geo.check_destination(&destination_for_geo)).await;
    let db = state.db.clone();
    match outcome {
        Ok(()) => {
            let destination_for_log = destination.clone();
            run_blocking(move || {
                db.log_egress_at(
                    None,
                    &meta.source_ip,
                    &destination_for_log,
                    &meta.method,
                    "allowed",
                    None,
                    size_bytes,
                    meta.forwarded_for.as_deref(),
                    meta.user_agent.as_deref(),
                    &now,
                )
            })
            .await?;
            state
                .metrics
                .observe_decision("/api/geo/check", "allowed", started);
            Ok(Json(serde_json::json!({
                "allowed": true,
                "destination": destination,
            })))
        }
        Err(err) => {
            let reason = err.to_string();
            let destination_for_log = destination.clone();
            run_blocking(move || {
                db.log_egress_at(
                    None,
                    &meta.source_ip,
                    &destination_for_log,
                    &meta.method,
                    "blocked",
                    Some(&reason),
                    size_bytes,
                    meta.forwarded_for.as_deref(),
                    meta.user_agent.as_deref(),
                    &now,
                )
            })
            .await?;
            state.metrics.observe_decision(
                "/api/geo/check",
                if err.is_infrastructure_failure() {
                    "error"
                } else {
                    "blocked"
                },
                started,
            );
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_token_roundtrip() {
        let token = AdminToken::new("s3cret-value");
        assert!(token.verify("s3cret-value"));
        assert!(token.verify(" s3cret-value ")); // trimmed
        assert!(!token.verify("wrong"));
        assert!(!token.verify(""));
    }

    #[test]
    fn ct_eq_basics() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(ct_eq_32(&a, &b));
        assert!(!ct_eq_32(&a, &c));
    }

    #[test]
    fn admin_path_classification() {
        assert!(is_admin_path("/api/egress/log"));
        assert!(is_admin_path("/api/egress/stats"));
        assert!(is_admin_path("/api/egress/prune"));
        assert!(is_admin_path("/api/egress/policies/agent-1"));
        assert!(is_admin_path("/api/attestation/attestate"));
        assert!(is_admin_path("/api/attestation/agents"));
        assert!(!is_admin_path("/api/egress/check"));
        assert!(!is_admin_path("/api/geo/check"));
        assert!(!is_admin_path("/api/attestation/verify"));
        assert!(!is_admin_path("/health"));
    }

    #[test]
    fn cors_empty_allowlist_grants_nothing() {
        let cors = build_cors(&[]).unwrap();
        let _ = cors; // layer builds; behavior asserted via integration tests
    }

    #[test]
    fn cors_invalid_origin_rejected_at_build() {
        assert!(build_cors(&["not a valid origin\n".to_string()]).is_err());
    }

    // ---------------- audit integrity (#12 F1/F2) ----------------

    fn test_state(geo_blocked: Vec<String>) -> (tempfile::TempDir, AppState) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::new(":memory:").unwrap());
        let config = Config {
            server: crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                cors_allowed_origins: vec![],
                trusted_proxies: vec![],
            },
            database: crate::config::DatabaseConfig {
                path: tmp.path().join("unused.db").to_string_lossy().to_string(),
            },
            egress: crate::config::EgressConfig {
                default_policy: "deny".into(),
                max_request_size_bytes: 1 << 20,
                max_connections_per_agent: 10,
                bandwidth_limit_kbps: 1024,
                log_retention_days: 30,
            },
            attestation: crate::config::AttestationConfig {
                enabled: true,
                require_attestation: false,
            },
            geo: crate::config::GeoConfig {
                enabled: !geo_blocked.is_empty(),
                blocked_regions: geo_blocked,
            },
        };
        (tmp, AppState::new(db, &config, None))
    }

    #[tokio::test]
    async fn geo_blocked_request_does_not_leave_a_false_allowed_row() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        // Geo gate fires before the egress engine writes anything.
        let app = build_router(state.clone()).unwrap();
        let resp = axum::body::to_bytes(
            tower::ServiceExt::oneshot(
                app,
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/egress/check")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"agent_id":"agent-1","destination":"https://evil.cn/data"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
            64 * 1024,
        )
        .await
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert!(body["error"].as_str().unwrap().contains("residency"));

        // The audit trail must show the attempt as blocked — not the
        // pre-geo "allowed" row the old ordering persisted.
        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 0, "geo rejection happens before any audit write");
        let stats = state.db.egress_stats().unwrap();
        assert_eq!(stats["allowed"], 0);
    }

    #[tokio::test]
    async fn geo_ok_request_still_flows_through_egress_engine() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);
        state
            .db
            .add_egress_policy("agent-1", "api.github.com", "allow")
            .unwrap();

        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/egress/check")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"agent_id":"agent-1","destination":"https://api.github.com"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        // F1: the allowed verdict is now audited.
        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["status"], "allowed");
    }

    // ---------------- log limit clamping (#12 F3) ----------------

    #[tokio::test]
    async fn geo_check_endpoint_writes_audit_rows_for_both_verdicts() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);

        // Blocked by geo.
        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/geo/check")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"destination":"https://evil.cn/data"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 403);

        // Allowed by geo.
        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/geo/check")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"destination":"https://api.github.com"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        // Both verdicts are in the audit trail (#12 F7).
        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 2);
        let statuses: Vec<&str> = log.iter().map(|r| r["status"].as_str().unwrap()).collect();
        assert!(statuses.contains(&"allowed"));
        assert!(statuses.contains(&"blocked"));
        let blocked = log.iter().find(|r| r["status"] == "blocked").unwrap();
        assert!(blocked["reason"].as_str().unwrap().contains("residency"));
    }

    #[tokio::test]
    async fn log_limit_is_clamped() {
        let (_tmp, state) = test_state(vec![]);
        // Seed 5 rows.
        for i in 0..5 {
            state
                .db
                .log_egress(
                    Some("agent-1"),
                    "127.0.0.1",
                    &format!("host-{i}.example.com"),
                    "GET",
                    "allowed",
                    None,
                    None,
                )
                .unwrap();
        }

        let build_req = |uri: String| {
            axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        // Negative limit must NOT mean "unlimited dump" (SQLite LIMIT -1).
        let app = build_router(state.clone()).unwrap();
        let resp =
            tower::ServiceExt::oneshot(app, build_req("/api/egress/log?limit=-5".to_string()))
                .await
                .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            rows.as_array().unwrap().len(),
            0,
            "negative limit clamps to 0 rows, never an unlimited dump"
        );

        // A huge positive limit is capped at the 1000 ceiling; here it
        // returns all 5 rows without unbounded allocation.
        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            build_req(format!("/api/egress/log?limit={}", i64::MAX)),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // ---------------- true request metadata end-to-end (#7) ----------------

    use axum::extract::connect_info::MockConnectInfo;
    use std::net::SocketAddr;

    /// A router with a mocked peer address so `oneshot` requests carry
    /// ConnectInfo exactly as the real socket path would.
    fn router_with_peer(state: AppState, peer: SocketAddr) -> axum::Router {
        build_router(state).unwrap().layer(MockConnectInfo(peer))
    }

    fn post_check(
        uri: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> axum::http::Request<axum::body::Body> {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn check_logs_true_method_size_and_untrusted_peer_ip() {
        let (_tmp, state) = test_state(vec![]);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        // Peer is a random non-loopback client: no trusted proxy configured,
        // so its XFF must be ignored and the peer itself recorded.
        let client_addr: SocketAddr = "203.0.113.5:52344".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/egress/check",
                r#"{"agent_id":"agent-1","destination":"https://api.github.com/repos"}"#,
                &[("user-agent", "aegis-itest/1")],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["source_ip"], "203.0.113.5", "direct peer recorded");
        assert_eq!(
            log[0]["method"], "POST",
            "actual HTTP method of the check call"
        );
        // The buffered body length is what gets recorded (the JSON payload of
        // this very request), not a constant.
        let expected_size = log[0]["size_bytes"].as_i64().unwrap();
        assert!(
            expected_size > 0,
            "body size must be the real buffered length, got {expected_size}"
        );
    }

    #[tokio::test]
    async fn untrusted_caller_cannot_forge_source_ip_via_xff() {
        let (_tmp, state) = test_state(vec![]);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        let client_addr: SocketAddr = "198.51.100.1:40000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/egress/check",
                r#"{"agent_id":"agent-1","destination":"https://api.github.com"}"#,
                &[("x-forwarded-for", "9.9.9.9")],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0]["source_ip"], "198.51.100.1",
            "XFF from an untrusted peer must be ignored"
        );
    }

    #[tokio::test]
    async fn trusted_proxy_xff_is_honored_and_audited() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::new(":memory:").unwrap());
        let config = crate::config::Config {
            server: crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
                cors_allowed_origins: vec![],
                // Loopback LB is trusted to set XFF.
                trusted_proxies: vec!["127.0.0.1".to_string()],
            },
            database: crate::config::DatabaseConfig {
                path: tmp.path().join("unused.db").to_string_lossy().to_string(),
            },
            egress: crate::config::EgressConfig {
                default_policy: "deny".into(),
                max_request_size_bytes: 1 << 20,
                max_connections_per_agent: 10,
                bandwidth_limit_kbps: 1024,
                log_retention_days: 30,
            },
            attestation: crate::config::AttestationConfig {
                enabled: true,
                require_attestation: false,
            },
            geo: crate::config::GeoConfig {
                enabled: false,
                blocked_regions: vec![],
            },
        };
        let state = AppState::new(db, &config, None);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        let proxy_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let app = router_with_peer(state.clone(), proxy_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/egress/check",
                r#"{"agent_id":"agent-1","destination":"https://api.github.com"}"#,
                &[("x-forwarded-for", "198.51.100.77")],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0]["source_ip"], "198.51.100.77",
            "trusted proxy may speak for the client"
        );
        assert_eq!(
            log[0]["forwarded_for"], "198.51.100.77",
            "raw header kept as provenance"
        );
    }

    #[tokio::test]
    async fn geo_endpoint_logs_real_metadata_too() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);

        let client_addr: SocketAddr = "203.0.113.66:51000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/geo/check",
                r#"{"destination":"https://evil.cn/data"}"#,
                &[],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 403);

        let log = state.db.list_egress_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["status"], "blocked");
        assert_eq!(log[0]["source_ip"], "203.0.113.66");
        assert_eq!(log[0]["method"], "POST");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_not_truncated() {
        let (_tmp, state) = test_state(vec![]);
        let client_addr: SocketAddr = "203.0.113.5:53000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);

        // 2 MiB body vs the 1 MiB test cap.
        let huge = format!(
            "{{\"agent_id\":\"a\",\"destination\":\"{}\"}}",
            "x".repeat(2 * 1024 * 1024)
        );
        let resp = tower::ServiceExt::oneshot(app, post_check("/api/egress/check", &huge, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "over-cap body rejected cleanly");

        // Nothing was audited (no verdict was reached).
        assert_eq!(state.db.list_egress_log(10).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn malformed_json_body_maps_to_400_with_metadata_path() {
        let (_tmp, state) = test_state(vec![]);
        let client_addr: SocketAddr = "203.0.113.5:54000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check("/api/egress/check", "{\"destination\": ", &[]),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 400);
        assert_eq!(state.db.list_egress_log(10).unwrap().len(), 0);
    }

    // ---------------- health probes and Prometheus metrics (#6) ----------------

    use axum::body::HttpBody;

    /// `GET` a path against the router and return `(status, headers, body)`.
    async fn get_full(state: AppState, path: &str) -> (StatusCode, header::HeaderValue, String) {
        let app = build_router(state).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("GET")
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .cloned()
            .expect("every response under test carries a content type");
        let size = usize::try_from(resp.body().size_hint().exact().unwrap_or(64 * 1024))
            .unwrap_or(64 * 1024)
            .max(1024);
        let body = axum::body::to_bytes(resp.into_body(), size).await.unwrap();
        (
            status,
            content_type,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn liveness_is_dependency_free_and_readiness_probes_the_database() {
        // Both probes answer 200 on a healthy instance...
        let (_tmp, state) = test_state(vec![]);

        let (status, _, body) = get_full(state.clone(), "/health/live").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "aegis");

        let (status, _, body) = get_full(state.clone(), "/health/ready").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ready");
        assert_eq!(json["checks"]["database"], "ok");

        // ...and /health stays a valid alias with an identical body.
        let (status, _, _) = get_full(state.clone(), "/health").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_fails_closed_with_503_when_database_is_unreachable() {
        let (_tmp, state) = test_state(vec![]);
        // Simulate a broken/corrupt database: the table the probe checks is
        // gone, so every readiness round-trip fails until an operator
        // intervenes.
        {
            let conn = state.db.conn_for_test();
            conn.execute_batch("DROP TABLE egress_policies;").unwrap();
        }

        let (status, _, body) = get_full(state, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "unavailable");
        assert_eq!(json["checks"]["database"], "error");
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_text_exposition_format() {
        let (_tmp, state) = test_state(vec![]);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        // One allowed decision so the counter is non-zero in this scrape.
        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/egress/check",
                r#"{"agent_id":"agent-1","destination":"https://api.github.com"}"#,
                &[],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let (status, content_type, body) = get_full(state, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type, "text/plain; version=0.0.4",
            "standard Prometheus text exposition content type"
        );
        assert!(
            !body.contains("agent-1"),
            "no per-agent data may leak through metrics: {body}"
        );

        for family in [
            "# TYPE aegis_egress_decisions_total counter",
            "# TYPE aegis_egress_check_latency_seconds histogram",
            "# TYPE aegis_active_policies gauge",
        ] {
            assert!(body.contains(family), "missing `{family}` in:\n{body}");
        }
        assert!(
            body.contains("aegis_egress_decisions_total{outcome=\"allowed\"} 1"),
            "the allowed decision was metered: {body}"
        );
        assert!(
            body.contains("aegis_active_policies 1"),
            "gauge counts the one seeded policy: {body}"
        );
        assert!(
            body.contains(
                "aegis_egress_check_latency_seconds_count{route=\"/api/egress/check\"} 1"
            ),
            "latency observed exactly once: {body}"
        );
    }

    #[tokio::test]
    async fn blocked_verdicts_increment_outcome_blocked_not_error() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);

        // Geo-blocked decision endpoint call.
        let client_addr: SocketAddr = "203.0.113.7:55000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/geo/check",
                r#"{"destination":"https://evil.cn/x"}"#,
                &[],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 403);

        // Policy-denied egress check.
        let app = build_router(state.clone()).unwrap();
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check(
                "/api/egress/check",
                r#"{"agent_id":"agent-9","destination":"https://api.github.com"}"#,
                &[],
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 403);

        let (_, _, body) = get_full(state, "/metrics").await;
        assert!(
            body.contains("aegis_egress_decisions_total{outcome=\"blocked\"} 2"),
            "both denials are policy verdicts: {body}"
        );
        assert!(
            !body.contains("outcome=\"error\""),
            "infrastructure outcome stays at zero (series absent): {body}"
        );
    }

    #[tokio::test]
    async fn malformed_requests_are_metered_but_never_audited_as_verdicts() {
        let (_tmp, state) = test_state(vec![]);
        let client_addr: SocketAddr = "203.0.113.8:56000".parse().unwrap();
        let app = router_with_peer(state.clone(), client_addr);
        let resp = tower::ServiceExt::oneshot(
            app,
            post_check("/api/egress/check", "{\"destination\": ", &[]),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 400);

        // The request was timed (#6: validation failures are latency data)
        // but no decision counter moved: it never reached enforcement.
        let (_, _, body) = get_full(state.clone(), "/metrics").await;
        assert!(
            body.contains(
                "aegis_egress_check_latency_seconds_count{route=\"/api/egress/check\"} 1"
            ),
            "validation failure still contributes a latency observation: {body}"
        );
        assert!(
            !body.contains("aegis_egress_decisions_total{"),
            "no verdict series exists yet (families stay registered but unobserved): {body}"
        );
        assert_eq!(
            state.db.list_egress_log(10).unwrap().len(),
            0,
            "malformed input must not become audit evidence"
        );
    }

    #[tokio::test]
    async fn decisions_counter_tracks_every_audit_row_one_to_one() {
        let (_tmp, state) = test_state(vec!["CN".to_string()]);
        state.db.add_egress_policy("agent-1", "*", "allow").unwrap();

        // Two allowed checks + one geo-blocked check on the same engine.
        for dest in [
            "https://api.github.com/a",
            "https://api.github.com/b",
            "https://blocked.cn/c",
        ] {
            let app = build_router(state.clone()).unwrap();
            let resp = tower::ServiceExt::oneshot(
                app,
                post_check(
                    "/api/egress/check",
                    &format!(r#"{{"agent_id":"agent-1","destination":"{dest}"}}"#),
                    &[],
                ),
            )
            .await
            .unwrap();
            let expected = if dest.ends_with("/c") { 403 } else { 200 };
            assert_eq!(resp.status(), expected);
        }

        // Audit parity: summed over outcomes, the counter covers every
        // audited verdict exactly once. (Geo rejections on this endpoint are
        // deliberately NOT audited, per #12 F2, so the invariant is
        // `total_requests == allowed + blocked - geo_rejections`; here one
        // geo rejection occurred.)
        let stats = state.db.egress_stats().unwrap();
        let (_, _, body) = get_full(state, "/metrics").await;

        let parse = |name: &str| -> u64 {
            body.lines()
                .find_map(|l| l.strip_prefix(name)?.trim().parse::<u64>().ok())
                .unwrap_or_else(|| panic!("{name} not found in scrape:\n{body}"))
        };
        let allowed = parse("aegis_egress_decisions_total{outcome=\"allowed\"}");
        let blocked = parse("aegis_egress_decisions_total{outcome=\"blocked\"}");
        assert_eq!(
            stats["total_requests"].as_u64().unwrap(),
            allowed + blocked - 1,
            "audited rows = metered verdicts minus unaudited geo rejections"
        );
        assert_eq!(allowed, 2);
        assert_eq!(
            blocked, 1,
            "geo rejection is metered even though it is not audited (#12 F2)"
        );
    }

    #[tokio::test]
    async fn gauge_reflects_policy_crud_between_scrapes() {
        let (_tmp, state) = test_state(vec![]);

        let (_, _, body) = get_full(state.clone(), "/metrics").await;
        assert!(body.contains("aegis_active_policies 0"));

        let id = state
            .db
            .add_egress_policy("agent-1", "api.github.com", "allow")
            .unwrap();
        let (_, _, body) = get_full(state.clone(), "/metrics").await;
        assert!(body.contains("aegis_active_policies 1"), "{body}");

        assert!(state.db.remove_egress_policy("agent-1", &id).unwrap());
        let (_, _, body) = get_full(state, "/metrics").await;
        assert!(body.contains("aegis_active_policies 0"), "{body}");
    }

    #[test]
    fn infrastructure_failures_are_classified_separately_from_denials() {
        use crate::errors::AegisError;
        // Infrastructure: database/config/internal.
        assert!(AegisError::Database("x".into()).is_infrastructure_failure());
        assert!(AegisError::Config("x".into()).is_infrastructure_failure());
        assert!(AegisError::Internal("x".into()).is_infrastructure_failure());
        // Policy verdicts and caller errors are not.
        assert!(!AegisError::EgressBlocked("x".into()).is_infrastructure_failure());
        assert!(!AegisError::BadRequest("x".into()).is_infrastructure_failure());
        assert!(!AegisError::Unauthorized("x".into()).is_infrastructure_failure());
        assert!(!AegisError::PolicyNotFound("x".into()).is_infrastructure_failure());
        assert!(!AegisError::AttestationFailed("x".into()).is_infrastructure_failure());
    }
}
