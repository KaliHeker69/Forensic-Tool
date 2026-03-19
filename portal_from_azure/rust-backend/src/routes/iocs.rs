/// IOC routes – ipsum threat intelligence feed browser and IP lookup
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::middleware::{AdminUser, AppState, AuthUser};
use crate::config::INACTIVITY_TIMEOUT_MINUTES;
use crate::ioc;
use crate::template_utils;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tools/iocs", get(iocs_page))
        .route("/api/iocs/stats", get(stats))
        .route("/api/iocs/lookup", post(lookup))
        .route("/api/iocs/list", get(list))
        .route("/api/iocs/refresh", post(refresh))
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"detail": msg}))).into_response()
}

// ── Page ────────────────────────────────────────────────────

async fn iocs_page(State(state): State<Arc<AppState>>, AuthUser(user): AuthUser) -> Html<String> {
    let ipsum = state.ipsum.read().await;
    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        }),
    );
    ctx.insert(
        "avatar_letter",
        &template_utils::avatar_letter(&user.username),
    );
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    ctx.insert("ipsum_total", &ipsum.total);
    ctx.insert("ipsum_high", &ipsum.count_above(5));
    ctx.insert("ipsum_critical", &ipsum.count_above(8));
    ctx.insert(
        "ipsum_last_updated",
        &ipsum
            .last_updated
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Never".to_string()),
    );
    ctx.insert(
        "ipsum_source_date",
        &ipsum.source_date.clone().unwrap_or_default(),
    );
    let dist: Vec<serde_json::Value> = ipsum
        .distribution()
        .into_iter()
        .map(|(s, c)| serde_json::json!({"score": s, "count": c}))
        .collect();
    ctx.insert("ipsum_distribution", &dist);
    template_utils::render(&state.templates, "iocs.html", &ctx)
}

// ── API: stats ───────────────────────────────────────────────

async fn stats(
    AuthUser(_user): AuthUser,
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let ipsum = state.ipsum.read().await;
    let dist: Vec<serde_json::Value> = ipsum
        .distribution()
        .into_iter()
        .map(|(s, c)| serde_json::json!({"score": s, "count": c}))
        .collect();
    Json(serde_json::json!({
        "total": ipsum.total,
        "high_confidence": ipsum.count_above(5),
        "critical": ipsum.count_above(8),
        "last_updated": ipsum.last_updated
            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
        "source_date": ipsum.source_date,
        "distribution": dist,
    }))
}

// ── API: lookup ──────────────────────────────────────────────

#[derive(Deserialize)]
struct LookupRequest {
    ips: Vec<String>,
}

#[derive(Serialize)]
struct LookupResult {
    ip: String,
    score: Option<u8>,
    found: bool,
    confidence: String,
}

fn confidence_label(score: u8) -> &'static str {
    match score {
        s if s >= 8 => "Critical",
        s if s >= 5 => "High",
        s if s >= 3 => "Medium",
        _ => "Low",
    }
}

async fn lookup(
    AuthUser(_user): AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<LookupRequest>,
) -> Response {
    if req.ips.is_empty() {
        return err(StatusCode::BAD_REQUEST, "No IPs provided");
    }
    if req.ips.len() > 500 {
        return err(StatusCode::BAD_REQUEST, "Maximum 500 IPs per request");
    }

    let ipsum = state.ipsum.read().await;
    let results: Vec<LookupResult> = req
        .ips
        .iter()
        .map(|ip| {
            let ip = ip.trim().to_string();
            match ipsum.lookup(&ip) {
                Some(score) => LookupResult {
                    ip: ip.clone(),
                    score: Some(score),
                    found: true,
                    confidence: confidence_label(score).to_string(),
                },
                None => LookupResult {
                    ip: ip.clone(),
                    score: None,
                    found: false,
                    confidence: "Clean".to_string(),
                },
            }
        })
        .collect();

    Json(serde_json::json!({"results": results})).into_response()
}

// ── API: list ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ListQuery {
    min_score: Option<u8>,
    q: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn list(
    AuthUser(_user): AuthUser,
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let ipsum = state.ipsum.read().await;
    let min_score = q.min_score.unwrap_or(1);
    let search = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let per_page = q.per_page.unwrap_or(50).min(200);
    let page = q.page.unwrap_or(1).max(1);

    let filtered: Vec<&(String, u8)> = ipsum
        .sorted
        .iter()
        .filter(|(ip, score)| *score >= min_score && (search.is_empty() || ip.contains(&search)))
        .collect();

    let total_filtered = filtered.len();
    let total_pages = (total_filtered + per_page - 1).max(1) / per_page;
    let start = ((page - 1) * per_page).min(total_filtered);
    let end = (start + per_page).min(total_filtered);

    let items: Vec<serde_json::Value> = filtered[start..end]
        .iter()
        .map(|(ip, score)| {
            serde_json::json!({
                "ip": ip,
                "score": score,
                "confidence": confidence_label(*score),
            })
        })
        .collect();

    Json(serde_json::json!({
        "items": items,
        "total": total_filtered,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    }))
}

// ── API: refresh (admin only) ────────────────────────────────

async fn refresh(AdminUser(_admin): AdminUser, State(state): State<Arc<AppState>>) -> Response {
    tracing::info!(
        event = "ioc.refresh_started",
        "IPsum feed refresh triggered"
    );

    match ioc::download_ipsum().await {
        Ok(msg) => {
            // Reload the in-memory data
            let new_data = ioc::IpsumData::load_from_file(&ioc::ipsum_path());
            let total = new_data.total;
            *state.ipsum.write().await = new_data;
            tracing::info!(
                total,
                event = "ioc.refresh_complete",
                "IPsum feed refreshed"
            );
            Json(serde_json::json!({
                "ok": true,
                "message": msg,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, event = "ioc.refresh_failed", "IPsum feed refresh failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Refresh failed: {e}"),
            )
        }
    }
}
