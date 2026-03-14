use axum::http::StatusCode;
use axum::response::{Html, Redirect};
use std::path::{Path, PathBuf};

const REPORT_PATH_CONFIG: &str = "report_path.txt";

fn read_report_target() -> Result<String, String> {
    let raw = std::fs::read_to_string(REPORT_PATH_CONFIG)
        .map_err(|e| format!("Failed to read {}: {}", REPORT_PATH_CONFIG, e))?;

    let target = raw.trim();
    if target.is_empty() {
        return Err(format!("{} is empty", REPORT_PATH_CONFIG));
    }

    Ok(target.to_string())
}

fn resolve_local_report_path(target: &str) -> PathBuf {
    let path = Path::new(target);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from(target)
    }
}

pub async fn redirect_to_report() -> Result<Redirect, (StatusCode, String)> {
    let target = read_report_target().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if target.starts_with("http://") || target.starts_with("https://") {
        return Ok(Redirect::temporary(&target));
    }

    Ok(Redirect::temporary("/forensic-report/view"))
}

pub async fn view_report() -> Result<Html<String>, (StatusCode, String)> {
    let target = read_report_target().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if target.starts_with("http://") || target.starts_with("https://") {
        return Err((
            StatusCode::BAD_REQUEST,
            "Configured report path is an external URL; open /forensic-report instead".to_string(),
        ));
    }

    let report_path = resolve_local_report_path(&target);
    let html = std::fs::read_to_string(&report_path).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("Failed to read report '{}': {}", report_path.display(), e),
        )
    })?;

    Ok(Html(html))
}
