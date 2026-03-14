use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::Html;

use super::SharedState;
use crate::registry;
use crate::state::HiveEntry;

struct HiveListItem {
    id: String,
    name: String,
    size_display: String,
}

#[derive(Template)]
#[template(path = "hive_list.html")]
struct HiveListTemplate {
    hives: Vec<HiveListItem>,
}

pub async fn upload(
    State(state): State<SharedState>,
    mut multipart: Multipart,
) -> Result<Html<String>, (StatusCode, String)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)))?
    {
        if field.name() == Some("hive_file") {
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Read error: {}", e)))?
                .to_vec();

            let size = data.len();
            let id = uuid::Uuid::new_v4().to_string();

            let entry = HiveEntry {
                id: id.clone(),
                name: file_name,
                data,
                size,
                log1_data: None,
                log2_data: None,
            };

            // Validate that all keys/values are traversable.
            registry::validate_full_traversal(&entry)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hive file: {}", e)))?;

            let mut state = state.write().await;
            state.hives.insert(id, entry);
            return Ok(render_hive_list(&state));
        }
    }

    Err((
        StatusCode::BAD_REQUEST,
        "No hive_file field found".to_string(),
    ))
}

pub async fn list_hives(State(state): State<SharedState>) -> Html<String> {
    let state = state.read().await;
    render_hive_list(&state)
}

pub async fn delete_hive(
    State(state): State<SharedState>,
    Path(hive_id): Path<String>,
) -> Html<String> {
    let mut state = state.write().await;
    state.hives.remove(&hive_id);
    render_hive_list(&state)
}

fn render_hive_list(state: &crate::state::AppState) -> Html<String> {
    let hives: Vec<HiveListItem> = state
        .hives
        .values()
        .map(|h| HiveListItem {
            id: h.id.clone(),
            name: h.name.clone(),
            size_display: format_size(h.size),
        })
        .collect();

    let template = HiveListTemplate { hives };
    Html(template.render().unwrap_or_default())
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}
