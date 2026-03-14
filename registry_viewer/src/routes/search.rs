use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use super::SharedState;
use crate::registry::{self, SearchResult};

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
}

#[derive(Template)]
#[template(path = "search_results.html")]
struct SearchResultsTemplate {
    results: Vec<SearchResult>,
    query: String,
    hive_id: String,
}

pub async fn search(
    State(state): State<SharedState>,
    Path(hive_id): Path<String>,
    Query(params): Query<SearchQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let state = state.read().await;
    let entry = state
        .hives
        .get(&hive_id)
        .ok_or((StatusCode::NOT_FOUND, "Hive not found".to_string()))?;

    let results = registry::search_hive(entry, &params.q, 200)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let template = SearchResultsTemplate {
        results,
        query: params.q,
        hive_id,
    };
    Ok(Html(
        template.render().unwrap_or_else(|e| format!("Template error: {}", e)),
    ))
}
