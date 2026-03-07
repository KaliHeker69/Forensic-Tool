/// Template rendering helper: logs errors and returns a visible error page
/// instead of silently swallowing failures with unwrap_or_default().
use axum::response::Html;
use tera::{Context, Tera};

pub fn render(tera: &Tera, template: &str, ctx: &Context) -> Html<String> {
    match tera.render(template, ctx) {
        Ok(html) => Html(html),
        Err(e) => {
            tracing::error!("Template render error [{template}]: {e:#}");
            Html(format!(
                concat!(
                    "<!doctype html><html><body style=\"font-family:monospace;padding:2rem;",
                    "background:#0d1117;color:#e6edf3\">",
                    "<h2 style=\"color:#f85149\">Template error &mdash; {}</h2>",
                    "<pre style=\"background:#161b22;padding:1rem;border-radius:6px;",
                    "overflow:auto;white-space:pre-wrap\">{}</pre>",
                    "</body></html>"
                ),
                template, e
            ))
        }
    }
}

/// Compute the avatar letter from a username (first char, uppercased).
pub fn avatar_letter(username: &str) -> String {
    username
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string()
}
