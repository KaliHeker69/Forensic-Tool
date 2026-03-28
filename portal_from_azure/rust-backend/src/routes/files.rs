/// File browser API – mirrors app/routers/files.py
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::auth::middleware::AppState;

const DEFAULT_DATA_DIR: &str = "/home/kali_arch/Computed_Data";
const ALLOWED_PATHS: &[&str] = &[
    "/home/kali_arch/Computed_Data",
    "/tmp/forensic_data",
    "/data",
    "/srv/forensics",
];
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/files", get(list_directory))
        .route("/api/files/content", get(get_file_content))
        .route("/api/files/info", get(get_file_info))
}

fn is_path_allowed(path: &Path) -> bool {
    let resolved = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    for allowed in ALLOWED_PATHS {
        if let Ok(base) = Path::new(allowed).canonicalize() {
            if resolved.starts_with(&base) {
                return true;
            }
        }
    }
    false
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
        format!("{} {}", bytes, units[0])
    } else {
        format!("{:.1} {}", size, units[idx])
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"detail": msg}))).into_response()
}

// ── List directory ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListQuery {
    path: Option<String>,
}

#[derive(Serialize)]
struct FileItem {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
}

#[derive(Serialize)]
struct DirContents {
    path: String,
    parent: Option<String>,
    contents: Vec<FileItem>,
}

async fn list_directory(Query(q): Query<ListQuery>) -> Response {
    let dir = q.path.unwrap_or_else(|| DEFAULT_DATA_DIR.into());
    let target = PathBuf::from(&dir);

    if !is_path_allowed(&target) {
        return err(
            StatusCode::FORBIDDEN,
            &format!("Access to path '{}' is not allowed", dir),
        );
    }
    if !target.exists() {
        return err(
            StatusCode::NOT_FOUND,
            &format!("Directory not found: {}", dir),
        );
    }
    if !target.is_dir() {
        return err(
            StatusCode::BAD_REQUEST,
            &format!("Path is not a directory: {}", dir),
        );
    }

    let mut contents = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&target) {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| {
                    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_default()
                });

            if meta.is_dir() {
                contents.push(FileItem {
                    name,
                    kind: "folder".into(),
                    size: None,
                    modified,
                    extension: None,
                });
            } else if meta.is_file() {
                let ext = Path::new(&entry.file_name())
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
                contents.push(FileItem {
                    name,
                    kind: "file".into(),
                    size: Some(format_size(meta.len())),
                    modified,
                    extension: ext,
                });
            }
        }
    }

    let parent = target.parent().and_then(|p| {
        if is_path_allowed(p) {
            Some(p.to_string_lossy().into_owned())
        } else {
            None
        }
    });

    Json(DirContents {
        path: target.to_string_lossy().into_owned(),
        parent,
        contents,
    })
    .into_response()
}

// ── File content ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

async fn get_file_content(Query(q): Query<PathQuery>) -> Response {
    let fp = PathBuf::from(&q.path);
    if !is_path_allowed(&fp) {
        return err(
            StatusCode::FORBIDDEN,
            &format!("Access to path '{}' is not allowed", q.path),
        );
    }
    if !fp.exists() {
        return err(
            StatusCode::NOT_FOUND,
            &format!("File not found: {}", q.path),
        );
    }
    if !fp.is_file() {
        return err(
            StatusCode::BAD_REQUEST,
            &format!("Path is not a file: {}", q.path),
        );
    }
    let ext = fp
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext != "csv" && ext != "txt" && ext != "tsv" && ext != "json" && ext != "jsonl" {
        return err(
            StatusCode::BAD_REQUEST,
            "Only CSV, TSV, TXT, JSON, and JSONL files are allowed",
        );
    }
    let meta = fp.metadata().unwrap();
    if meta.len() > MAX_FILE_SIZE {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "File too large (max 100MB)");
    }
    match std::fs::read_to_string(&fp) {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Error reading file: {}", e),
        ),
    }
}

// ── File info ───────────────────────────────────────────────

async fn get_file_info(Query(q): Query<PathQuery>) -> Response {
    let fp = PathBuf::from(&q.path);
    if !is_path_allowed(&fp) {
        return err(
            StatusCode::FORBIDDEN,
            &format!("Access to path '{}' is not allowed", q.path),
        );
    }
    if !fp.exists() {
        return err(
            StatusCode::NOT_FOUND,
            &format!("Path not found: {}", q.path),
        );
    }
    let meta = fp.metadata().unwrap();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| {
            chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        });

    let is_file = meta.is_file();
    Json(serde_json::json!({
        "name": fp.file_name().map(|n| n.to_string_lossy().into_owned()),
        "path": fp.to_string_lossy(),
        "type": if is_file { "file" } else { "folder" },
        "size": if is_file { Some(format_size(meta.len())) } else { None },
        "size_bytes": if is_file { Some(meta.len()) } else { None },
        "modified": modified,
        "extension": if is_file { fp.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())) } else { None },
    }))
    .into_response()
}
