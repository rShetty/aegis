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

            let app = build_router(state)?;
            let addr = format!("{}:{}", config.server.host, config.server.port);
            tracing::info!("Aegis starting on {}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }

    Ok(())
}
