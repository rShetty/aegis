use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use aegis::{
    attestation::AttestationEngine, config::Config, db::Database, egress::EgressEngine,
    geo::GeoEngine,
};

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "Network egress control and runtime attestation for AI agent ecosystems")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    Init,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
    egress: Arc<EgressEngine>,
    attestation: Arc<AttestationEngine>,
    geo: Arc<GeoEngine>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let config = Config::default();
            let toml = toml::to_string_pretty(&config)?;
            std::fs::write("config.toml", toml)?;
            println!("Created config.toml");
        }
        Commands::Serve { config } => {
            // Fail fast on missing/invalid configuration (#3): never fall back
            // to defaults for a security control.
            let config = Config::load(&config)?;
            let db = Arc::new(Database::new(&config.database.path)?);
            let egress = Arc::new(EgressEngine::new(db.clone(), config.egress.clone()));
            let attestation = Arc::new(AttestationEngine::new(
                db.clone(),
                config.attestation.enabled,
            ));
            let geo = Arc::new(GeoEngine::new(&config.geo));

            let state = AppState {
                db,
                egress,
                attestation,
                geo,
            };

            let app = create_router(state);
            let addr = format!("{}:{}", config.server.host, config.server.port);
            tracing::info!("Aegis starting on {}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/egress/check", post(check_egress))
        .route(
            "/api/egress/policies/{agent_id}",
            get(list_policies).post(add_policy),
        )
        .route("/api/egress/log", get(egress_log))
        .route("/api/egress/stats", get(egress_stats))
        .route("/api/attestation/attestate", post(attestate_agent))
        .route("/api/attestation/verify", post(verify_agent))
        .route("/api/attestation/agents", get(list_attested))
        .route("/api/geo/check", post(check_geo))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "aegis"})),
    )
}

#[derive(Deserialize)]
struct CheckEgressRequest {
    agent_id: Option<String>,
    destination: String,
}

async fn check_egress(
    State(state): State<AppState>,
    Json(req): Json<CheckEgressRequest>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    state
        .egress
        .check(req.agent_id.as_deref(), &req.destination)?;
    state.geo.check_destination(&req.destination)?;
    Ok(Json(serde_json::json!({
        "allowed": true,
        "destination": req.destination,
        "agent_id": req.agent_id,
    })))
}

async fn list_policies(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    let policies = state.db.get_egress_policies(&agent_id)?;
    let result: Vec<serde_json::Value> = policies
        .into_iter()
        .map(|(dest, action, created)| {
            serde_json::json!({"destination": dest, "action": action, "created_at": created})
        })
        .collect();
    Ok(Json(
        serde_json::json!({"agent_id": agent_id, "policies": result}),
    ))
}

#[derive(Deserialize)]
struct AddPolicyRequest {
    destination: String,
    action: String,
}

async fn add_policy(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<AddPolicyRequest>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    // Strict action validation (#3): reject anything but allow/deny with 400.
    if !aegis::config::is_valid_action(&req.action) {
        return Err(aegis::errors::AegisError::BadRequest(format!(
            "invalid action '{}': must be one of {:?}",
            req.action,
            aegis::config::VALID_ACTIONS
        )));
    }
    state
        .db
        .add_egress_policy(&agent_id, &req.destination, &req.action)?;
    Ok(Json(
        serde_json::json!({"added": true, "agent_id": agent_id, "destination": req.destination, "action": req.action}),
    ))
}

async fn egress_log(
    State(state): State<AppState>,
    Query(params): Query<LogQuery>,
) -> Result<Json<Vec<serde_json::Value>>, aegis::errors::AegisError> {
    let limit = params.limit.unwrap_or(100);
    let log = state.db.list_egress_log(limit)?;
    Ok(Json(log))
}

#[derive(Deserialize)]
struct LogQuery {
    limit: Option<i64>,
}

async fn egress_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    let stats = state.db.egress_stats()?;
    Ok(Json(stats))
}

#[derive(Deserialize)]
struct AttestateRequest {
    agent_id: String,
    binary_path: String,
    pid: Option<i64>,
}

async fn attestate_agent(
    State(state): State<AppState>,
    Json(req): Json<AttestateRequest>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    let hash = state
        .attestation
        .attestate(&req.agent_id, &req.binary_path, req.pid)?;
    Ok(Json(serde_json::json!({
        "attested": true,
        "agent_id": req.agent_id,
        "process_hash": hash,
    })))
}

#[derive(Deserialize)]
struct VerifyRequest {
    agent_id: String,
    binary_path: Option<String>,
    process_hash: Option<String>,
}

async fn verify_agent(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    let verified = if let Some(path) = &req.binary_path {
        state.attestation.verify(&req.agent_id, path)?
    } else if let Some(hash) = &req.process_hash {
        state.attestation.verify_hash(&req.agent_id, hash)?
    } else {
        false
    };
    Ok(Json(serde_json::json!({
        "agent_id": req.agent_id,
        "verified": verified,
    })))
}

async fn list_attested(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, aegis::errors::AegisError> {
    let agents = state.db.list_attested_agents()?;
    Ok(Json(agents))
}

#[derive(Deserialize)]
struct CheckGeoRequest {
    destination: String,
}

async fn check_geo(
    State(state): State<AppState>,
    Json(req): Json<CheckGeoRequest>,
) -> Result<Json<serde_json::Value>, aegis::errors::AegisError> {
    state.geo.check_destination(&req.destination)?;
    Ok(Json(serde_json::json!({
        "allowed": true,
        "destination": req.destination,
    })))
}
