/// Reporting routes – mirrors app/routers/reporting.py
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::auth::middleware::{AppState, AuthUser};
use crate::template_utils;
use crate::config::INACTIVITY_TIMEOUT_MINUTES;

/// In-memory report storage (same as Python's dict-based store).
type ReportsStore = Mutex<HashMap<String, Vec<Value>>>;

pub fn router() -> Router<Arc<AppState>> {
    let store: Arc<ReportsStore> = Arc::new(Mutex::new(HashMap::new()));

    Router::new()
        .route("/tools/reporting", get(reporting_page))
        .route("/tools/reporting/save", post(save_report))
        .route("/tools/reporting/export", post(export_report))
        .route("/tools/reporting/{report_id}", get(get_report).delete(delete_report))
        .layer(axum::Extension(store))
}

async fn reporting_page(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    axum::Extension(store): axum::Extension<Arc<ReportsStore>>,
) -> Html<String> {
    let reports = {
        let lock = store.lock().unwrap();
        lock.get(&user.username).cloned().unwrap_or_default()
    };
    let mut ctx = tera::Context::new();
    ctx.insert("user", &serde_json::json!({
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    }));
    ctx.insert("avatar_letter", &template_utils::avatar_letter(&user.username));
    ctx.insert("reports", &reports);
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    ctx.insert("current_date", &chrono::Local::now().format("%Y-%m-%d").to_string());
    template_utils::render(&state.templates, "reporting.html", &ctx)
}

async fn save_report(
    AuthUser(user): AuthUser,
    axum::Extension(store): axum::Extension<Arc<ReportsStore>>,
    Json(data): Json<Value>,
) -> Json<Value> {
    let report_id = data
        .get("report_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| chrono::Local::now().format("%Y%m%d%H%M%S").to_string());

    let report = serde_json::json!({
        "id": report_id,
        "title": data.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled Report"),
        "case_id": data.get("case_id").and_then(|v| v.as_str()).unwrap_or(""),
        "created_at": data.get("created_at").and_then(|v| v.as_str()).unwrap_or(""),
        "updated_at": chrono::Local::now().to_rfc3339(),
        "sections": data.get("sections").unwrap_or(&serde_json::json!({})),
        "status": data.get("status").and_then(|v| v.as_str()).unwrap_or("draft"),
    });

    let mut lock = store.lock().unwrap();
    let list = lock.entry(user.username.clone()).or_default();
    if let Some(idx) = list.iter().position(|r| r.get("id").and_then(|v| v.as_str()) == Some(&report_id)) {
        list[idx] = report;
    } else {
        list.push(report);
    }

    Json(serde_json::json!({"success": true, "message": "Report saved successfully", "report_id": report_id}))
}

async fn get_report(
    AuthUser(user): AuthUser,
    axum::Extension(store): axum::Extension<Arc<ReportsStore>>,
    AxPath(report_id): AxPath<String>,
) -> Response {
    let lock = store.lock().unwrap();
    let list = lock.get(&user.username);
    let found = list.and_then(|v| v.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(&report_id)));
    match found {
        Some(r) => Json(serde_json::json!({"success": true, "report": r})).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"success": false, "message": "Report not found"}))).into_response(),
    }
}

async fn delete_report(
    AuthUser(user): AuthUser,
    axum::Extension(store): axum::Extension<Arc<ReportsStore>>,
    AxPath(report_id): AxPath<String>,
) -> Json<Value> {
    let mut lock = store.lock().unwrap();
    if let Some(list) = lock.get_mut(&user.username) {
        list.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(&report_id));
    }
    Json(serde_json::json!({"success": true, "message": "Report deleted"}))
}

async fn export_report(
    AuthUser(_user): AuthUser,
    Json(data): Json<Value>,
) -> Json<Value> {
    let sections = data.get("sections").cloned().unwrap_or(serde_json::json!({}));
    let mut lines: Vec<String> = Vec::new();

    lines.push("=".repeat(80));
    lines.push("DIGITAL FORENSICS EXAMINATION REPORT".into());
    lines.push("=".repeat(80));
    lines.push(String::new());

    // General
    if let Some(general) = sections.get("general") {
        lines.push("SECTION 1: GENERAL INFORMATION".into());
        lines.push("-".repeat(40));
        lines.push(format!("Report Title: {}", general.get("title").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Case Identifier: {}", general.get("case_id").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Examining Organization: {}", general.get("organization").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Report Date: {}", general.get("report_date").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Examiner: {}", general.get("examiner").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(String::new());
    }

    // Request
    if let Some(req) = sections.get("request") {
        lines.push("SECTION 2: REQUEST DETAILS".into());
        lines.push("-".repeat(40));
        lines.push(format!("Date of Request: {}", req.get("request_date").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Requestor: {}", req.get("requestor").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Requestor Organization: {}", req.get("requestor_org").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Authority: {}", req.get("authority").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Scope & Purpose: {}", req.get("scope").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Specific Tasks: {}", req.get("tasks").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(String::new());
    }

    // Evidence
    if let Some(ev) = sections.get("evidence") {
        lines.push("SECTION 3: EVIDENCE RECEIVED".into());
        lines.push("-".repeat(40));
        lines.push(format!("Receipt Date: {}", ev.get("receipt_date").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Submitter: {}", ev.get("submitter").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Delivery Method: {}", ev.get("delivery_method").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Evidence Items:\n{}", ev.get("items").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(String::new());
    }

    // Methodology
    if let Some(meth) = sections.get("methodology") {
        lines.push("SECTION 4: METHODOLOGY".into());
        lines.push("-".repeat(40));
        lines.push(format!("Tools Used:\n{}", meth.get("tools").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Standards Applied: {}", meth.get("standards").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Acquisition Method: {}", meth.get("acquisition").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Procedures:\n{}", meth.get("procedures").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(String::new());
    }

    // Findings
    let findings = [
        ("system_info", "5.1 SYSTEM INFORMATION"),
        ("event_logs", "5.2 EVENT LOG ANALYSIS"),
        ("registry", "5.3 REGISTRY ANALYSIS"),
        ("filesystem", "5.4 FILE SYSTEM ANALYSIS"),
        ("timeline", "5.5 TIMELINE ANALYSIS"),
        ("user_activity", "5.6 USER ACTIVITY & ARTIFACTS"),
        ("network", "5.7 NETWORK & COMMUNICATION ARTIFACTS"),
    ];
    let has_findings = findings.iter().any(|(k, _)| sections.get(*k).is_some());
    if has_findings {
        lines.push("SECTION 5: RESULTS AND TECHNICAL FINDINGS".into());
        lines.push("-".repeat(40));
        for (key, title) in &findings {
            if let Some(val) = sections.get(*key).and_then(|v| v.as_str()) {
                lines.push(format!("\n{}", title));
                lines.push(val.to_string());
            }
        }
        lines.push(String::new());
    }

    // Analysis
    if let Some(val) = sections.get("analysis").and_then(|v| v.as_str()) {
        lines.push("SECTION 6: ANALYSIS & INTERPRETATION".into());
        lines.push("-".repeat(40));
        lines.push(val.to_string());
        lines.push(String::new());
    }

    // Conclusions
    if let Some(val) = sections.get("conclusions").and_then(|v| v.as_str()) {
        lines.push("SECTION 7: CONCLUSIONS".into());
        lines.push("-".repeat(40));
        lines.push(val.to_string());
        lines.push(String::new());
    }

    // Chain of Custody
    if let Some(val) = sections.get("chain_of_custody").and_then(|v| v.as_str()) {
        lines.push("SECTION 8: CHAIN OF CUSTODY".into());
        lines.push("-".repeat(40));
        lines.push(val.to_string());
        lines.push(String::new());
    }

    // Disposition
    if let Some(val) = sections.get("disposition").and_then(|v| v.as_str()) {
        lines.push("SECTION 9: DISPOSITION OF EVIDENCE".into());
        lines.push("-".repeat(40));
        lines.push(val.to_string());
        lines.push(String::new());
    }

    // Authorization
    if let Some(auth) = sections.get("authorization") {
        lines.push("SECTION 10: REPORT AUTHORIZATION".into());
        lines.push("-".repeat(40));
        lines.push(format!("Examiner Name: {}", auth.get("examiner_name").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(format!("Credentials: {}", auth.get("credentials").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push("Signature: _________________________".into());
        lines.push(format!("Date: {}", auth.get("sign_date").and_then(|v| v.as_str()).unwrap_or("N/A")));
        lines.push(String::new());
    }

    // Appendices
    if let Some(val) = sections.get("appendices").and_then(|v| v.as_str()) {
        lines.push("SECTION 11: APPENDICES".into());
        lines.push("-".repeat(40));
        lines.push(val.to_string());
        lines.push(String::new());
    }

    lines.push("=".repeat(80));
    lines.push("END OF REPORT".into());
    lines.push("=".repeat(80));

    Json(serde_json::json!({
        "success": true,
        "content": lines.join("\n"),
        "format": "text"
    }))
}
