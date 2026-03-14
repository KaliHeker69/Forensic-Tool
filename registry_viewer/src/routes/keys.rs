use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use super::SharedState;
use crate::registry::{self, KeyChild};

#[derive(Deserialize)]
pub struct KeysQuery {
    path: Option<String>,
}

#[derive(Template)]
#[template(path = "tree_children.html")]
struct TreeChildrenTemplate {
    hive_id: String,
    children: Vec<KeyChild>,
}

pub async fn get_children(
    State(state): State<SharedState>,
    Path(hive_id): Path<String>,
    Query(params): Query<KeysQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let state = state.read().await;
    let entry = state
        .hives
        .get(&hive_id)
        .ok_or((StatusCode::NOT_FOUND, "Hive not found".to_string()))?;

    let key_path = params.path.clone().unwrap_or_default();

    let children = if key_path.is_empty() {
        registry::get_root_children(entry)
            .map(|(_, children)| children)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    } else {
        registry::get_children_at_path(entry, &key_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    let template = TreeChildrenTemplate { hive_id, children };
    Ok(Html(
        template.render().unwrap_or_else(|e| format!("Template error: {}", e)),
    ))
}
