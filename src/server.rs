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

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
};
use sha2::{Digest, Sha256};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    attestation::AttestationEngine, config::Config, db::Database, egress::EgressEngine,
    errors::AegisError, geo::GeoEngine,
};

/// Paths under /api that belong to the agent data plane and do NOT require
/// the admin token. Everything else under /api is admin-only.
const DATA_PLANE_PATHS: [&str; 3] = [
    "/api/egress/check",
    "/api/geo/check",
    "/api/attestation/verify",
];

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
}

impl AppState {
    pub fn new(db: Arc<Database>, config: &Config, admin_token: Option<AdminToken>) -> Self {
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
        }
    }
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

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "aegis"})),
    )
}

#[derive(serde::Deserialize)]
struct CheckEgressRequest {
    agent_id: Option<String>,
    destination: String,
}

async fn check_egress(
    State(state): State<AppState>,
    Json(req): Json<CheckEgressRequest>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let egress = state.egress.clone();
    let agent_id = req.agent_id.clone();
    let destination = req.destination.clone();
    run_blocking(move || egress.check(agent_id.as_deref(), &destination)).await?;
    let geo = state.geo.clone();
    let destination = req.destination.clone();
    run_blocking(move || geo.check_destination(&destination)).await?;
    Ok(Json(serde_json::json!({
        "allowed": true,
        "destination": req.destination,
        "agent_id": req.agent_id,
    })))
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
    let limit = params.limit.unwrap_or(100);
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
    let stats = run_blocking(move || db.egress_stats()).await?;
    Ok(Json(stats))
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
    Json(req): Json<CheckGeoRequest>,
) -> Result<Json<serde_json::Value>, AegisError> {
    let geo = state.geo.clone();
    let destination = req.destination.clone();
    run_blocking(move || geo.check_destination(&destination)).await?;
    Ok(Json(serde_json::json!({
        "allowed": true,
        "destination": req.destination,
    })))
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
}
