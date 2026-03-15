use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::parser::types::PrefetchFile;
use crate::detection::types::AnalysisResult;
use crate::state::SharedState;
use super::upload::FileListItem;

#[derive(Serialize)]
pub struct FileDetail {
    pub parsed: PrefetchFile,
    pub analysis: AnalysisResult,
}

pub async fn list_files(
    State(state): State<SharedState>,
) -> Json<Vec<FileListItem>> {
    let state = state.read().await;
    let mut items: Vec<FileListItem> = state
        .entries
        .values()
        .map(FileListItem::from_entry)
        .collect();
    items.sort_by(|a, b| b.last_run.cmp(&a.last_run));
    Json(items)
}

pub async fn get_file(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<FileDetail>, StatusCode> {
    let state = state.read().await;
    match state.entries.get(&id) {
        Some(entry) => Ok(Json(FileDetail {
            parsed: entry.parsed.clone(),
            analysis: entry.analysis.clone(),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn delete_file(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut state = state.write().await;
    if state.entries.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}
