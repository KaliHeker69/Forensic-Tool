use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use super::SharedState;
use crate::registry::{self, KeyInfo, RegValue};

#[derive(Deserialize)]
pub struct ValuesQuery {
    path: Option<String>,
}

#[derive(Template)]
#[template(path = "detail_panel.html")]
struct DetailPanelTemplate {
    key_info: KeyInfo,
    values: Vec<RegValue>,
}

pub async fn get_values(
    State(state): State<SharedState>,
    Path(hive_id): Path<String>,
    Query(params): Query<ValuesQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let state = state.read().await;
    let entry = state
        .hives
        .get(&hive_id)
        .ok_or((StatusCode::NOT_FOUND, "Hive not found".to_string()))?;

    let key_path = params.path.unwrap_or_default();
    let (key_info, values) = registry::get_values_at_path(entry, &key_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let template = DetailPanelTemplate { key_info, values };
    Ok(Html(
        template.render().unwrap_or_else(|e| format!("Template error: {}", e)),
    ))
}
