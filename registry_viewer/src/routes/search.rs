use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use super::SharedState;
use crate::registry;

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
}

#[derive(Template)]
#[template(path = "search_results.html")]
struct SearchResultsTemplate {
    results: Vec<SearchItem>,
    query: String,
    scope_label: String,
}

struct SearchItem {
    hive_id: String,
    hive_name: String,
    path: String,
    match_type: String,
    name: String,
    preview: String,
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

    let hive_results = registry::search_hive(entry, &params.q, 200)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let results = hive_results
        .into_iter()
        .map(|r| SearchItem {
            hive_id: hive_id.clone(),
            hive_name: entry.name.clone(),
            path: r.path,
            match_type: r.match_type,
            name: r.name,
            preview: r.preview,
        })
        .collect();

    let template = SearchResultsTemplate {
        results,
        query: params.q,
        scope_label: format!("selected hive ({})", entry.name),
    };
    Ok(Html(
        template.render().unwrap_or_else(|e| format!("Template error: {}", e)),
    ))
}

pub async fn search_all(
    State(state): State<SharedState>,
    Query(params): Query<SearchQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let state = state.read().await;
    if state.hives.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No hives loaded".to_string()));
    }

    let mut results = Vec::new();
    let mut hives: Vec<_> = state.hives.values().collect();
    hives.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    for entry in hives {
        if results.len() >= 400 {
            break;
        }

        let remaining = 400 - results.len();
        let per_hive = remaining.min(120);
        let hive_results = match registry::search_hive(entry, &params.q, per_hive) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Search failed for hive '{}': {}", entry.name, e);
                continue;
            }
        };

        for r in hive_results {
            results.push(SearchItem {
                hive_id: entry.id.clone(),
                hive_name: entry.name.clone(),
                path: r.path,
                match_type: r.match_type,
                name: r.name,
                preview: r.preview,
            });
        }
    }

    let template = SearchResultsTemplate {
        results,
        query: params.q,
        scope_label: "all loaded hives".to_string(),
    };
    Ok(Html(
        template.render().unwrap_or_else(|e| format!("Template error: {}", e)),
    ))
}
