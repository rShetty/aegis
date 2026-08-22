use std::net::SocketAddr;
use std::sync::Arc;

use aegis::{
    config::Config,
    db::Database,
    server::{AdminToken, AppState, build_router},
};
use clap::{Parser, Subcommand};

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

/// Resolve the admin token from the environment (#1).
///
/// - `AEGIS_ADMIN_TOKEN` set  -> token used for the admin plane.
/// - unset in release builds  -> refuse to start unless
///   `AEGIS_INSECURE_DEV=1` is set explicitly.
/// - unset in debug builds    -> warn loudly and continue (development only).
fn resolve_admin_token() -> anyhow::Result<Option<AdminToken>> {
    if let Ok(raw) = std::env::var("AEGIS_ADMIN_TOKEN")
        && !raw.trim().is_empty()
    {
        return Ok(Some(AdminToken::new(&raw)));
    }
    #[cfg(not(debug_assertions))]
    {
        let insecure = std::env::var("AEGIS_INSECURE_DEV").is_ok_and(|v| v == "1");
        if !insecure {
            anyhow::bail!(
                "refusing to start: AEGIS_ADMIN_TOKEN is not set (required in release builds). \
                 For local development ONLY, set AEGIS_INSECURE_DEV=1"
            );
        }
        tracing::warn!("AEGIS_INSECURE_DEV=1: admin endpoints are UNAUTHENTICATED");
    }
    #[cfg(debug_assertions)]
    {
        tracing::warn!(
            "AEGIS_ADMIN_TOKEN not set: admin endpoints are UNAUTHENTICATED (debug build)"
        );
    }
    Ok(None)
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
            // Fail fast on missing/invalid configuration (#3): never fall
            // back to defaults for a security control.
            let config = Config::load(&config)?;

            let admin_token = resolve_admin_token()?;
            let db = Arc::new(Database::new(&config.database.path)?);
            let state = AppState::new(db, &config, admin_token);

            let app = build_router(state.clone())?;
            let addr = format!("{}:{}", config.server.host, config.server.port);
            tracing::info!("Aegis starting on {}", addr);
            tracing::info!(
                "egress_log retention: {} day(s); manual prune via POST /api/egress/prune",
                state.retention.retention_days
            );

            // Background egress_log pruning (#10). Prunes once at startup,
            // then hourly; aborted after the server drains.
            let retention_task =
                aegis::server::spawn_retention_task(&state, std::time::Duration::from_secs(3600));

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("Aegis listening on {}", addr);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;

            retention_task.abort();
            tracing::info!("Aegis shut down cleanly");
        }
    }

    Ok(())
}

/// Future that resolves on SIGINT (Ctrl-C) or SIGTERM (#5), letting
/// `with_graceful_shutdown` drain in-flight connections before exit.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, draining connections");
}
