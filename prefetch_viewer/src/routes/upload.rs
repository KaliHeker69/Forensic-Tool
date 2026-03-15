use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::detection::DetectionEngine;
use crate::detection::types::SeveritySummary;
use crate::parser;
use crate::state::{PrefetchEntry, SharedState};

#[derive(Serialize)]
pub struct FileListItem {
    pub id: String,
    pub exe_name: String,
    pub prefetch_hash: String,
    pub version: u32,
    pub run_count: u32,
    pub last_run: Option<DateTime<Utc>>,
    pub score: u32,
    pub finding_counts: SeveritySummary,
    pub file_count: usize,
    pub was_compressed: bool,
}

impl FileListItem {
    pub fn from_entry(entry: &PrefetchEntry) -> Self {
        Self {
            id: entry.id.clone(),
            exe_name: entry.parsed.header.exe_name.clone(),
            prefetch_hash: entry.parsed.header.prefetch_hash.clone(),
            version: entry.parsed.version,
            run_count: entry.parsed.header.run_count,
            last_run: entry.parsed.header.last_run_times.first().cloned(),
            score: entry.analysis.score,
            finding_counts: entry.analysis.summary.clone(),
            file_count: entry.parsed.file_metrics.len(),
            was_compressed: entry.parsed.was_compressed,
        }
    }
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub uploaded: Vec<FileListItem>,
    pub errors: Vec<UploadError>,
}

#[derive(Serialize)]
pub struct UploadError {
    pub filename: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn upload_files(
    State(state): State<SharedState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Read the single uploaded JSON field
    let field = multipart
        .next_field()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: e.to_string() }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "No file provided".into() }),
            )
        })?;

    let filename = field.file_name().unwrap_or("input.json").to_string();
    let data = field.bytes().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;

    let (parsed_files, parse_errors) = parser::ingest_pecmd_json(&data);

    let engine = DetectionEngine::new();
    let mut uploaded = Vec::new();
    let mut errors: Vec<UploadError> = parse_errors
        .into_iter()
        .map(|(line, msg)| UploadError {
            filename: format!("{filename}:line {line}"),
            error: msg,
        })
        .collect();

    {
        let mut st = state.write().await;
        for parsed in parsed_files {
            let id = uuid::Uuid::new_v4().to_string();
            let analysis = engine.analyze(&id, &parsed);
            let entry = PrefetchEntry {
                id: id.clone(),
                parsed,
                analysis,
                raw_size: data.len(),
            };
            let summary = FileListItem::from_entry(&entry);
            st.entries.insert(id, entry);
            uploaded.push(summary);
        }
    }

    Ok(Json(UploadResponse { uploaded, errors }))
}
