pub mod hives;
pub mod keys;
pub mod pages;
pub mod report;
pub mod search;
pub mod values;

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use include_dir::{include_dir, Dir};

use crate::state::AppState;

pub type SharedState = Arc<RwLock<AppState>>;

static STATIC_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/static");

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/api/upload", post(hives::upload))
        .route("/api/hives", get(hives::list_hives))
        .route("/api/hives/{hive_id}", delete(hives::delete_hive))
        .route("/api/keys/{hive_id}", get(keys::get_children))
        .route("/api/values/{hive_id}", get(values::get_values))
        .route("/api/search/{hive_id}", get(search::search))
        .route("/api/search-all", get(search::search_all))
        .route("/forensic-report", get(report::redirect_to_report))
        .route("/forensic-report/view", get(report::view_report))
        .route("/static/{*file}", get(serve_static))
        .with_state(state)
}

async fn serve_static(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    match STATIC_DIR.get_file(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                file.contents().to_vec(),
            )
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}
