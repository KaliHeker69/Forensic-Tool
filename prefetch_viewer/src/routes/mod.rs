pub mod upload;
pub mod files;
pub mod timeline;
pub mod report;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, delete};
use axum::http::{StatusCode, header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use include_dir::{include_dir, Dir};

use crate::state::SharedState;

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/upload", post(upload::upload_files))
        .route("/api/files", get(files::list_files))
        .route("/api/files/{id}", get(files::get_file))
        .route("/api/files/{id}", delete(files::delete_file))
        .route("/api/timeline", get(timeline::get_timeline))
        .route("/api/report", get(report::generate_report))
        .route("/static/{*file}", get(serve_static))
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

async fn serve_index() -> impl IntoResponse {
    match STATIC_DIR.get_file("index.html") {
        Some(file) => Html(
            String::from_utf8_lossy(file.contents()).to_string()
        ).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

async fn serve_static(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response {
    match STATIC_DIR.get_file(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            let mut response = (
                StatusCode::OK,
                file.contents().to_vec(),
            ).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            response
        }
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}
