use include_dir::{include_dir, Dir};
use tera::Tera;

// Embed the `app/` directory from the project root at compile time
// `../app` is relative to the rust-backend crate directory
// assets/ lives inside rust-backend/ so it stays co-located with source forever
static APP_DIR: Dir = include_dir!("assets");
// embedded timeline explorer directory (small tool served under /tools/timeline)
static TIMELINE_DIR: Dir = include_dir!("../tools/timeline_explorer");

pub fn register_templates(tera: &mut Tera) -> Result<(), tera::Error> {
    if let Some(tpl_dir) = APP_DIR.get_dir("templates") {
        // collect all files first so we can sort them (ensure base.html registered first)
        let mut entries: Vec<_> = tpl_dir
            .files()
            .filter_map(|file| {
                file.path().file_name().and_then(|n| n.to_str()).map(|name| (name.to_string(), file))
            })
            .collect();
        // move base.html to front if present
        entries.sort_by(|a, b| {
            if a.0 == "base.html" {
                std::cmp::Ordering::Less
            } else if b.0 == "base.html" {
                std::cmp::Ordering::Greater
            } else {
                a.0.cmp(&b.0)
            }
        });
        for (name, file) in entries {
            let s = std::str::from_utf8(file.contents()).unwrap_or("");
            tera.add_raw_template(&name, s)?;
        }
    }
    Ok(())
}

pub fn get_static(path: &str) -> Option<(&'static [u8], &'static str)> {
    // APP_DIR root IS app/, so prefix with static/ for files under app/static/
    let path = path.trim_start_matches('/');
    let full = format!("static/{path}");
    if let Some(f) = APP_DIR.get_file(&full) {
        let mime = mime_guess::from_path(f.path()).first_or_octet_stream().essence_str().to_string();
        return Some((f.contents(), Box::leak(mime.into_boxed_str())));
    }
    None
}

/// Serve files belonging to the timeline explorer tool (under `/tools/timeline`).
pub fn get_timeline(path: &str) -> Option<(&'static [u8], &'static str)> {
    // TIMELINE_DIR root IS tools/timeline_explorer, so just use the path directly
    let path = path.trim_start_matches('/');
    let lookup = if path.is_empty() { "index.html" } else { path };
    if let Some(f) = TIMELINE_DIR.get_file(lookup) {
        let mime = mime_guess::from_path(f.path()).first_or_octet_stream().essence_str().to_string();
        return Some((f.contents(), Box::leak(mime.into_boxed_str())));
    }
    None
}
