mod error;
mod parser;
mod detection;
mod state;
mod routes;

use std::sync::Arc;
use tokio::sync::RwLock;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use state::AppState;
use routes::build_router;

#[derive(Parser)]
#[command(name = "prefetch_viewer", about = "Web-based Windows Prefetch file viewer with suspicious indicator detection")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Automatically open browser
    #[arg(long, default_value = "true")]
    open: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let shared_state = Arc::new(RwLock::new(AppState::new()));
    let app = build_router(shared_state);

    let addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Prefetch Viewer running at http://127.0.0.1:{}", args.port);

    if args.open {
        let url = format!("http://127.0.0.1:{}", args.port);
        let _ = open::that(&url);
    }

    axum::serve(listener, app).await?;
    Ok(())
}
