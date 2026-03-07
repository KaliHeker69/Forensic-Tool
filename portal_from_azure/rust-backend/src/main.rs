/// Resource Portal – Rust/Axum backend
/// Drop-in replacement for the Python/FastAPI backend, same API surface.

mod auth;
mod config;
mod database;
mod routes;
mod assets;
mod template_utils;
mod ioc;

use std::sync::Arc;
use axum::{http::{header, Method}, response::Redirect, routing::get, Router};
use axum::response::IntoResponse;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

use auth::middleware::AppState;
use auth::security::hash_password;
use database::Database;

// ── Logging init ────────────────────────────────────────────
//
// Sets up two log sinks:
//   1. stdout  – human-readable coloured output (or JSON when LOG_FORMAT=json)
//   2. file    – daily-rotating logs/portal.log.YYYY-MM-DD (no ANSI colours)
//
// Filter controlled by RUST_LOG env var; default: "info".
// Set LOG_FORMAT=json for structured JSON output (e.g. for log shippers).
fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_appender::rolling;
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
    std::fs::create_dir_all(&log_dir).ok();

    let json_mode = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Daily-rotating file: logs/portal.log.YYYY-MM-DD
    let file_appender = rolling::daily(&log_dir, "portal.log");
    let (non_blocking_file, guard) = tracing_appender::non_blocking(file_appender);

    if json_mode {
        tracing_subscriber::registry()
            .with(env_filter)
            // JSON to stdout (for log shippers / systemd journal parsers)
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_writer(std::io::stdout),
            )
            // JSON to rotating file
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_ansi(false)
                    .with_writer(non_blocking_file),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            // Coloured, human-readable to stdout
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_writer(std::io::stdout),
            )
            // Compact, no-ANSI to rotating file
            .with(
                fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_level(true)
                    .with_ansi(false)
                    .with_writer(non_blocking_file),
            )
            .init();
    }

    guard
}

#[tokio::main]
async fn main() {
    // Logging – guard must live until end of main so file writer flushes on exit
    let _log_guard = init_logging();

    // Database
    let db = Database::open();

    // Seed default admin user
    if !db.user_exists("admin") {
        let hash = hash_password("admin123");
        db.create_user("admin", &hash, Some("admin@portal.local"), Some("Portal Administrator"), true)
            .expect("Failed to create default admin user");
        tracing::info!("Created default admin user (username: admin, password: admin123)");
    }

    // Templates – load Jinja2-compatible templates via Tera from embedded assets
    let mut templates = tera::Tera::default();
    assets::register_templates(&mut templates).expect("Failed to register embedded templates");
    templates.autoescape_on(vec![]); // Jinja2 compatibility – templates handle escaping

    // IPsum IOC feed – load from disk (falls back to empty if not yet downloaded)
    let ipsum_data = ioc::IpsumData::load_from_file(&ioc::ipsum_path());
    let ipsum = Arc::new(tokio::sync::RwLock::new(ipsum_data));

    let state = Arc::new(AppState {
        db: Arc::new(db),
        templates: Arc::new(templates),
        ipsum,
    });

    // CORS
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:8000".parse().unwrap(),
            "http://127.0.0.1:8000".parse().unwrap(),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::COOKIE,
        ])
        .allow_credentials(true);

    // Build router
    let app = Router::new()
        // Root redirect
        .route("/", get(|| async { Redirect::to("/dashboard") }))
        // Health check
        .route("/health", get(health))
        // Mount all route modules
        .merge(routes::auth_routes::router())
        .merge(routes::dashboard::router())
        .merge(routes::resources::router())
        .merge(routes::reporting::router())
        .merge(routes::reports::router())
        .merge(routes::admin::router())
        .merge(routes::files::router())
        .merge(routes::fetched_files::router())
        .merge(routes::iocs::router())
        .merge(routes::terminal::router())
        .merge(routes::timesketch::router())
        // Static files – served from embedded assets at /static/{*file}
        .route("/static/{*file}", get(|axum::extract::Path(path): axum::extract::Path<String>| async move {
            match assets::get_static(&path) {
                Some((bytes, mime)) => (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, mime.to_string())],
                    bytes.to_vec(),
                ).into_response(),
                None => axum::http::StatusCode::NOT_FOUND.into_response(),
            }
        }))
        // Timeline Explorer – add bare route for directory redirect
        .route("/tools/timeline", get(|| async { Redirect::to("/tools/timeline/") }))
        .route("/tools/timeline/", get(|| async {
            match assets::get_timeline("index.html") {
                Some((bytes, mime)) => (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, mime.to_string())],
                    bytes.to_vec(),
                ).into_response(),
                None => axum::http::StatusCode::NOT_FOUND.into_response(),
            }
        }))
        // Timeline Explorer tool served from embedded assets
        .route("/tools/timeline/{*file}", get(|axum::extract::Path(path): axum::extract::Path<String>| async move {
            match assets::get_timeline(&path) {
                Some((bytes, mime)) => (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, mime.to_string())],
                    bytes.to_vec(),
                ).into_response(),
                None => axum::http::StatusCode::NOT_FOUND.into_response(),
            }
        }))
        // Shared state
        .with_state(state.clone())
        .layer(cors)
        // HTTP request/response logging: method, path, status, latency
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );

    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    tracing::info!("{} listening on {}", config::APP_NAME, bind);

    let listener = tokio::net::TcpListener::bind(&bind).await
        .unwrap_or_else(|e| panic!("Cannot bind to {bind}: {e}"));
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "app": config::APP_NAME,
    }))
}

