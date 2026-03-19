/// Report viewer – serves HTML reports from paths defined in report_paths.toml
///
/// The report paths file is resolved in this order:
///   1. $REPORT_PATHS_FILE env var (absolute path)
///   2. ./report_paths.toml  (relative to CWD, i.e. the portal root)
///
/// If the file is missing or a report key is absent, the request returns 404.
use axum::{
    Json, Router, extract::Path as AxPath, http::StatusCode, response::IntoResponse, routing::get,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::auth::middleware::AppState;

// ── TOML schema ────────────────────────────────────────────

#[derive(Deserialize)]
struct ReportEntry {
    name: String,
    path: String,
}

#[derive(Deserialize)]
struct ReportPathsFile {
    reports: HashMap<String, ReportEntry>,
}

// ── Runtime loader ─────────────────────────────────────────

/// Load the report_paths.toml file and return a map of
/// report_id → (display_name, file_path).
fn load_report_paths() -> HashMap<String, (String, String)> {
    let config_path = std::env::var("REPORT_PATHS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("report_paths.toml"));

    let contents = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Could not read report paths file {:?}: {e}", config_path);
            return HashMap::new();
        }
    };

    match toml::from_str::<ReportPathsFile>(&contents) {
        Ok(parsed) => parsed
            .reports
            .into_iter()
            .map(|(id, entry)| (id, (entry.name, entry.path)))
            .collect(),
        Err(e) => {
            tracing::error!("Failed to parse report_paths.toml: {e}");
            HashMap::new()
        }
    }
}

// ── Router ─────────────────────────────────────────────────

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/reports/{report_id}", get(serve_report))
}

async fn serve_report(AxPath(report_id): AxPath<String>) -> impl IntoResponse {
    let paths = load_report_paths();

    let entry = match paths.get(&report_id) {
        Some(e) => e.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"detail": "Report not found"})),
            )
                .into_response();
        }
    };

    let path = PathBuf::from(&entry.1);
    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "Report file not found on disk"})),
        )
            .into_response();
    }

    let body = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": e.to_string()})),
            )
                .into_response();
        }
    };

    ([(axum::http::header::CONTENT_TYPE, "text/html")], body).into_response()
}
