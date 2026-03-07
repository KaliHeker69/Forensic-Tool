/// Resources API – mirrors app/routers/resources.py
use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::middleware::AppState;

#[derive(Serialize, Clone)]
struct Resource {
    id: String,
    name: String,
    description: String,
    category: String,
    url: Option<String>,
    status: String,
}

fn resources_db() -> Vec<Resource> {
    vec![
        Resource { id: "timeline-explorer".into(), name: "Timeline Explorer".into(), description: "View csv exported forensic outputs".into(), category: "forensics".into(), url: Some("/tools/timeline".into()), status: "active".into() },
        Resource { id: "registry".into(), name: "Registry".into(), description: "Windows Registry analysis and investigation tool".into(), category: "forensics".into(), url: Some("/tools/registry".into()), status: "active".into() },
        Resource { id: "ntfs-data".into(), name: "NTFS Data".into(), description: "NTFS file system and metadata analysis".into(), category: "forensics".into(), url: Some("/tools/ntfs".into()), status: "active".into() },
        Resource { id: "memory-analysis".into(), name: "Memory Analysis".into(), description: "Volatile memory capture & analysis".into(), category: "forensics".into(), url: Some("/tools/memory".into()), status: "active".into() },
        Resource { id: "memory-report".into(), name: "Memory Report".into(), description: "Open the latest memory analysis report".into(), category: "reports".into(), url: Some("/reports/memory".into()), status: "active".into() },
        Resource { id: "windows-event".into(), name: "Windows Event".into(), description: "Windows Event Log viewer and analyzer".into(), category: "forensics".into(), url: Some("/tools/windows-event".into()), status: "active".into() },
        Resource { id: "shimcache-amcache-report".into(), name: "Shimcache Amcache Report".into(), description: "Open the latest shimcache/amcache report".into(), category: "reports".into(), url: Some("/reports/shimcache-amcache".into()), status: "active".into() },
        Resource { id: "prefetch-report".into(), name: "Prefetch Report".into(), description: "Open the latest prefetch analysis report".into(), category: "reports".into(), url: Some("/reports/prefetch".into()), status: "active".into() },
        Resource { id: "timesketch".into(), name: "Timesketch".into(), description: "Collaborative forensic timeline analysis".into(), category: "forensics".into(), url: Some("http://localhost:80".into()), status: "active".into() },
        Resource { id: "ioc-scan".into(), name: "IOC Scan".into(), description: "Scan results for indicators of compromise".into(), category: "reports".into(), url: Some("/reports/ioc-scan".into()), status: "active".into() },
        Resource { id: "pe-entropy".into(), name: "PE Entropy".into(), description: "Run entropy malware analysis for selected PE files".into(), category: "forensics".into(), url: Some("/fetched-files?tool=pe-entropy".into()), status: "active".into() },
        Resource { id: "windows-event".into(), name: "Windows Event".into(), description: "Windows Event Log viewer and analyzer".into(), category: "forensics".into(), url: Some("/reports/windows-event".into()), status: "active".into() },
        Resource { id: "browser-forensics".into(), name: "Browser Forensics".into(), description: "Browser history, downloads, cookies & session analysis".into(), category: "forensics".into(), url: Some("/reports/browser-forensics".into()), status: "active".into() },
        Resource { id: "iocs".into(), name: "IOCs".into(), description: "Indicators of Compromise tracker and analyzer".into(), category: "intelligence".into(), url: Some("/tools/iocs".into()), status: "active".into() },
        Resource { id: "server-terminal".into(), name: "Server Terminal".into(), description: "Interactive shell access to the analysis server".into(), category: "forensics".into(), url: Some("/tools/terminal".into()), status: "active".into() },
    ]
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/resources", get(list_resources))
        .route("/api/resources/categories/list", get(list_categories))
        .route("/api/resources/{resource_id}", get(get_resource))
}

#[derive(serde::Deserialize)]
struct FilterQuery {
    category: Option<String>,
}

async fn list_resources(
    axum::extract::Query(q): axum::extract::Query<FilterQuery>,
) -> Json<Vec<Resource>> {
    let all = resources_db();
    if let Some(cat) = q.category {
        Json(all.into_iter().filter(|r| r.category == cat).collect())
    } else {
        Json(all)
    }
}

async fn get_resource(Path(resource_id): Path<String>) -> impl IntoResponse {
    let all = resources_db();
    match all.into_iter().find(|r| r.id == resource_id) {
        Some(r) => Json(r).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"detail":"Resource not found"}))).into_response(),
    }
}

async fn list_categories() -> Json<serde_json::Value> {
    let all = resources_db();
    let cats: std::collections::HashSet<String> = all.into_iter().map(|r| r.category).collect();
    Json(serde_json::json!({"categories": cats.into_iter().collect::<Vec<_>>()}))
}
