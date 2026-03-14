use askama::Template;
use axum::extract::State;
use axum::response::Html;

use super::SharedState;

struct HiveInfo {
    id: String,
    name: String,
    size_display: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    hives: Vec<HiveInfo>,
}

pub async fn index(State(state): State<SharedState>) -> Html<String> {
    let state = state.read().await;
    let hives: Vec<HiveInfo> = state
        .hives
        .values()
        .map(|h| HiveInfo {
            id: h.id.clone(),
            name: h.name.clone(),
            size_display: format_size(h.size),
        })
        .collect();

    let template = IndexTemplate { hives };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
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
