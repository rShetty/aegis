//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use aegis::config::{
    AttestationConfig, Config, DatabaseConfig, EgressConfig, GeoConfig, ServerConfig,
};
use aegis::db::Database;
use aegis::server::{AdminToken, AppState, build_router};

/// A valid, strict Config pointing at `db_path`, bound to loopback.
pub fn test_config(db_path: &str) -> Config {
    Config {
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            cors_allowed_origins: vec![],
            trusted_proxies: vec![],
        },
        database: DatabaseConfig {
            path: db_path.to_string(),
        },
        egress: EgressConfig {
            default_policy: "deny".into(),
            max_request_size_bytes: 1_048_576,
            max_connections_per_agent: 10,
            bandwidth_limit_kbps: 1024,
            log_retention_days: 30,
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

/// Build the shared `AppState` for a config (used directly by tests that need
/// to seed the database or spawn background tasks against the same state).
pub fn state_from_config(config: &Config, admin_token: Option<&str>) -> AppState {
    let db = Arc::new(Database::new(&config.database.path).unwrap());
    let token = admin_token.map(AdminToken::new);
    AppState::new(db, config, token)
}

/// Build the router from a config.
pub fn app_from_config(config: &Config, admin_token: Option<&str>) -> axum::Router {
    build_router(state_from_config(config, admin_token)).unwrap()
}

/// Bind an ephemeral port, serve the app, and return `(base_url, shutdown_tx,
/// server_task)`. Dropping/sending on `shutdown_tx` triggers graceful
/// shutdown, mirroring production signal handling (#5).
pub async fn spawn_app(
    config: &Config,
    admin_token: Option<&str>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (base, tx, handle, _state) = spawn_app_with_state(config, admin_token).await;
    (base, tx, handle)
}

/// Like [`spawn_app`], but also returns the shared [`AppState`] so tests can
/// seed rows through `state.db` and inspect `state.retention` counters.
pub async fn spawn_app_with_state(
    config: &Config,
    admin_token: Option<&str>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
    AppState,
) {
    let state = state_from_config(config, admin_token);
    let app = build_router(state.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    (format!("http://{addr}"), tx, handle, state)
}
