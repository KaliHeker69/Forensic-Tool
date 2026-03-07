/// Fetched files + PE entropy – mirrors app/routers/fetched_files.py
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::auth::middleware::{AppState, AuthUser};
use crate::template_utils;
use crate::config::INACTIVITY_TIMEOUT_MINUTES;

const FETCHED_FILES_DIR: &str = "/srv/forensics/fetched_files";
const PE_ENTROPY_SCRIPT: &str = "/home/kali_arch/tools/pe_entropy/pe_entropy.py";
const PE_ENTROPY_PYTHON: &str = "/home/kali_arch/tools/pe_entropy/entropy/bin/python";
const PE_ALLOWED_EXT: &[&str] = &[".exe", ".dll", ".sys", ".scr", ".drv", ".ocx"];

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/fetched-files", get(fetched_files_page))
        .route("/api/fetched-files/list", get(list_files))
        .route("/api/fetched-files/download", get(download_file))
        .route("/api/fetched-files/download-zip", post(download_zip))
        .route("/api/fetched-files/run-pe-entropy", post(run_pe_entropy))
        .route("/api/fetched-files/pe-entropy-report", get(get_pe_report))
}

fn base_dir() -> PathBuf {
    let p = PathBuf::from(FETCHED_FILES_DIR);
    std::fs::create_dir_all(&p).ok();
    p
}

fn is_safe(path: &Path) -> bool {
    match path.canonicalize() {
        Ok(resolved) => {
            if let Ok(base) = PathBuf::from(FETCHED_FILES_DIR).canonicalize() {
                resolved.starts_with(&base)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn format_size(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut idx = 0;
    while size >= 1024.0 && idx < units.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", size, units[idx])
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"detail": msg}))).into_response()
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    rel_path: String,
    size: String,
    size_bytes: u64,
    modified: String,
    extension: String,
}

fn build_file_list(base: &Path, search: &str) -> Vec<FileEntry> {
    let mut results = Vec::new();
    let search_lower = search.to_lowercase();

    let iter: Box<dyn Iterator<Item = walkdir::DirEntry>> = if search.is_empty() {
        // Only top-level for no-search
        Box::new(
            walkdir::WalkDir::new(base)
                .min_depth(1)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok()),
        )
    } else {
        Box::new(
            walkdir::WalkDir::new(base)
                .into_iter()
                .filter_map(|e| e.ok()),
        )
    };

    for entry in iter {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !is_safe(path) {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !search_lower.is_empty() && !name.to_lowercase().contains(&search_lower) {
            continue;
        }
        let meta = match path.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let rel = path.strip_prefix(base).unwrap_or(path);
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();

        results.push(FileEntry {
            name,
            rel_path: rel.to_string_lossy().into_owned(),
            size: format_size(meta.len()),
            size_bytes: meta.len(),
            modified,
            extension: path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default(),
        });
    }
    results.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    results
}

// ── Page route ──────────────────────────────────────────────

#[derive(Deserialize)]
struct PageQuery {
    tool: Option<String>,
}

async fn fetched_files_page(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Query(q): Query<PageQuery>,
) -> Html<String> {
    let pe_mode = q.tool.as_deref() == Some("pe-entropy");
    let mut ctx = tera::Context::new();
    ctx.insert("user", &serde_json::json!({
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    }));
    ctx.insert("avatar_letter", &template_utils::avatar_letter(&user.username));
    ctx.insert("fetched_dir", FETCHED_FILES_DIR);
    ctx.insert("pe_entropy_mode", &pe_mode);
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    template_utils::render(&state.templates, "fetched_files.html", &ctx)
}

// ── API: list ───────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchQuery {
    search: Option<String>,
}

async fn list_files(
    AuthUser(_user): AuthUser,
    Query(q): Query<SearchQuery>,
) -> Json<serde_json::Value> {
    let base = base_dir();
    let files = build_file_list(&base, q.search.as_deref().unwrap_or(""));
    Json(serde_json::json!({
        "directory": FETCHED_FILES_DIR,
        "total": files.len(),
        "files": files,
    }))
}

// ── API: download single ────────────────────────────────────

#[derive(Deserialize)]
struct DownloadQuery {
    path: String,
}

async fn download_file(
    AuthUser(_user): AuthUser,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let base = base_dir();
    let file_path = base.join(&q.path);
    if !is_safe(&file_path) {
        return err(StatusCode::FORBIDDEN, "Access denied");
    }
    if !file_path.exists() || !file_path.is_file() {
        return err(StatusCode::NOT_FOUND, "File not found");
    }

    let body = match std::fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let mime = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();
    let name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    (
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", name),
            ),
        ],
        body,
    )
        .into_response()
}

// ── API: download ZIP ───────────────────────────────────────

async fn download_zip(
    AuthUser(_user): AuthUser,
    Json(paths): Json<Vec<String>>,
) -> Response {
    if paths.is_empty() {
        return err(StatusCode::BAD_REQUEST, "No files requested");
    }
    if paths.len() > 200 {
        return err(StatusCode::BAD_REQUEST, "Too many files requested");
    }

    let base = base_dir();
    let mut resolved: Vec<(PathBuf, String)> = Vec::new();
    for rel in &paths {
        let candidate = base.join(rel);
        if !is_safe(&candidate) || !candidate.is_file() {
            return err(StatusCode::NOT_FOUND, &format!("Invalid or missing file: {}", rel));
        }
        resolved.push((candidate, rel.clone()));
    }

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let tmp_path = tmp.path().to_path_buf();
    {
        let file = std::fs::File::create(&tmp_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (full, arcname) in &resolved {
            zip.start_file(arcname, options).ok();
            let data = std::fs::read(full).unwrap_or_default();
            zip.write_all(&data).ok();
        }
        zip.finish().ok();
    }

    let body = match std::fs::read(&tmp_path) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let _ = std::fs::remove_file(&tmp_path);

    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/zip".to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"fetched_files_{}.zip\"", ts),
            ),
        ],
        body,
    )
        .into_response()
}

// ── API: run PE entropy ─────────────────────────────────────

#[derive(Deserialize)]
struct PeRequest {
    path: String,
}

async fn run_pe_entropy(
    AuthUser(_user): AuthUser,
    Json(req): Json<PeRequest>,
) -> Response {
    let script = PathBuf::from(PE_ENTROPY_SCRIPT);
    if !script.exists() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("PE Entropy script not found: {}", PE_ENTROPY_SCRIPT));
    }

    let base = base_dir();
    let file_path = base.join(&req.path);
    if !is_safe(&file_path) {
        return err(StatusCode::FORBIDDEN, "Access denied");
    }
    if !file_path.exists() || !file_path.is_file() {
        return err(StatusCode::NOT_FOUND, "File not found");
    }

    let ext = file_path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if !PE_ALLOWED_EXT.contains(&ext.as_str()) {
        return err(StatusCode::BAD_REQUEST, "Selected file is not a supported PE type");
    }

    let report_dir = script.parent().unwrap();
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
    let report_name = format!("pe_entropy_{}_{}.html", stem, ts);
    let report_path = report_dir.join(&report_name);

    let result = Command::new(PE_ENTROPY_PYTHON)
        .arg(&script)
        .arg(&file_path)
        .arg("--json")
        .arg("--html")
        .arg(&report_path)
        // Force non-interactive matplotlib backend — required on headless servers.
        // Without this matplotlib defaults to TkAgg which needs a display and crashes.
        .env("MPLBACKEND", "Agg")
        .output();

    let output = match result {
        Ok(o) => o,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to execute PE entropy script: {}", e)),
    };

    // The script writes JSON to stdout before attempting chart rendering.
    // Parse JSON first; only hard-fail when stdout contains no valid JSON at all.
    // The script may print a status line after the JSON object (e.g. "📄 HTML report saved →…").
    // Extract just the outermost { … } block so the status line doesn't break JSON parsing.
    let full_out = String::from_utf8_lossy(&output.stdout);
    let json_str = match (full_out.find('{'), full_out.rfind('}')) {
        (Some(start), Some(end)) if end >= start => &full_out[start..=end],
        _ => "",
    };
    let parsed: serde_json::Value = if let Ok(v) = serde_json::from_str(json_str) {
        v
    } else {
        // stdout doesn't contain a JSON object — surface stderr for diagnosis
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr.trim().is_empty() {
            full_out.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("PE entropy execution failed: {}", msg));
    };

    // Log any stderr warnings (e.g. chart generation issues) without failing the request
    let stderr_txt = String::from_utf8_lossy(&output.stderr);
    if !stderr_txt.trim().is_empty() {
        tracing::warn!("pe_entropy stderr: {}", stderr_txt.trim());
    }

    let rel = file_path.strip_prefix(&base).unwrap_or(&file_path);
    let html_ok = report_path.exists();
    let mut resp = serde_json::json!({
        "ok": true,
        "file": rel.to_string_lossy(),
        "result": parsed,
    });
    if html_ok {
        resp["report_name"] = serde_json::json!(report_name);
        resp["report_path"] = serde_json::json!(report_path.to_string_lossy());
        resp["report_url"] = serde_json::json!(format!("/api/fetched-files/pe-entropy-report?name={}", report_name));
    }
    Json(resp).into_response()
}

// ── API: serve PE report ────────────────────────────────────

#[derive(Deserialize)]
struct ReportQuery {
    name: String,
}

async fn get_pe_report(
    AuthUser(_user): AuthUser,
    Query(q): Query<ReportQuery>,
) -> Response {
    let safe_name = Path::new(&q.name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if safe_name != q.name {
        return err(StatusCode::BAD_REQUEST, "Invalid report name");
    }
    if !safe_name.to_lowercase().ends_with(".html") {
        return err(StatusCode::BAD_REQUEST, "Only HTML reports are allowed");
    }

    let report_dir = PathBuf::from(PE_ENTROPY_SCRIPT)
        .parent()
        .unwrap()
        .to_path_buf();
    let report_file = report_dir.join(&safe_name);
    if let Ok(resolved) = report_file.canonicalize() {
        if let Ok(base) = report_dir.canonicalize() {
            if !resolved.starts_with(&base) {
                return err(StatusCode::FORBIDDEN, "Access denied");
            }
        }
    }

    if !report_file.exists() || !report_file.is_file() {
        return err(StatusCode::NOT_FOUND, "Report not found");
    }

    let body = match std::fs::read(&report_file) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    ([(axum::http::header::CONTENT_TYPE, "text/html")], body).into_response()
}
