/// Dashboard route – mirrors app/routers/dashboard.py
use axum::{
    extract::State,
    response::Html,
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::auth::middleware::{AppState, AuthUser};
use crate::config::INACTIVITY_TIMEOUT_MINUTES;
use crate::template_utils;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/dashboard", get(dashboard))
}

async fn dashboard(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Html<String> {
    // Quick ipsum stats (non-blocking read)
    let (ioc_total, ioc_high, ioc_critical, ioc_updated) = {
        let ipsum = state.ipsum.read().await;
        (
            ipsum.total,
            ipsum.count_above(5),
            ipsum.count_above(8),
            ipsum.last_updated
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        )
    };

    let resources = serde_json::json!([
        {"id":"timeline","name":"Timeline Explorer","description":"View csv exported forensic outputs","icon":"fa-solid fa-chart-line","url":"/tools/timeline/","status":"active"},
        {"id":"registry","name":"Registry","description":"Windows Registry analysis and investigation","icon":"fa-solid fa-folder-open","url":"#registry","status":"active"},
        {"id":"ntfs","name":"NTFS Data","description":"NTFS file system and metadata analysis","icon":"fa-solid fa-hdd","url":"#ntfs","status":"active"},
        {"id":"memory","name":"Memory Analysis","description":"Volatile memory capture & analysis","icon":"fa-solid fa-brain","url":"/reports/memory","status":"active"},
        {"id":"windows-event","name":"Windows Event","description":"Windows Event Log viewer and analyzer","icon":"fa-solid fa-scroll","url":"/reports/windows-event","status":"active"},
        {"id":"shimcache-amcache-report","name":"Shimcache Amcache Report","description":"Open the latest shimcache/amcache report","icon":"fa-solid fa-clipboard-check","url":"/reports/shimcache-amcache","status":"active"},
        {"id":"prefetch-report","name":"Prefetch Report","description":"Open the latest prefetch analysis report","icon":"fa-solid fa-list-check","url":"/reports/prefetch","status":"active"},
        {"id":"timesketch","name":"Timesketch","description":"Collaborative forensic timeline analysis","icon":"fa-solid fa-clock","url":"/tools/timesketch/","status":"active"},
        {"id":"ioc-scan","name":"IOC Scan","description":"Scan results for indicators of compromise","icon":"fa-solid fa-magnifying-glass","url":"/reports/ioc-scan","status":"active"},
        {"id":"ioc-hash-scan","name":"IOC/Hash Scan","description":"Cross-check IOCs and file hashes against known indicators","icon":"fa-solid fa-fingerprint","url":"/reports/ioc-scan","status":"active"},
        {"id":"network-forensics","name":"Network Forensics","description":"Investigate network artifacts, flows, and communication patterns","icon":"fa-solid fa-network-wired","url":"/reports/network-forensics","status":"active"},
        {"id":"data-theft","name":"Data Theft","description":"Review exfiltration indicators and data theft investigation findings","icon":"fa-solid fa-file-export","url":"/reports/data-theft","status":"active"},
        {"id":"browser-forensics","name":"Browser Forensics","description":"Browser history, downloads, cookies & session analysis","icon":"fa-solid fa-globe","url":"/reports/browser-forensics","status":"active"},
        {"id":"fetched-files","name":"Fetched Files","description":"Browse and download files fetched from the share","icon":"fa-solid fa-file-arrow-down","url":"/fetched-files","status":"active"},
        {"id":"pe-entropy","name":"PE Entropy","description":"Analyze selected PE files from fetched files using entropy scoring","icon":"fa-solid fa-file-shield","url":"/fetched-files?tool=pe-entropy","status":"active"},
        {"id":"iocs","name":"IOCs","description":"Indicators of Compromise tracker","icon":"fa-solid fa-bullseye","url":"/tools/iocs","status":"active","special":true},
        {"id":"server-terminal","name":"Server Terminal","description":"Interactive shell access to the analysis server","icon":"fa-solid fa-terminal","url":"/tools/terminal","status":"active"},
        {"id":"reports","name":"Reports","description":"Generate security reports","icon":"fa-solid fa-file-alt","url":"/tools/reporting","status":"active"},
        {"id":"settings","name":"Settings","description":"Portal configuration","icon":"fa-solid fa-gear","url":"#settings","status":"active"}
    ]);

    let metrics = serde_json::json!({
        "active_sessions": 1,
        "last_login": "Just now",
        "security_score": 95,
        "alerts": 3,
    });

    let mut ctx = tera::Context::new();
    ctx.insert("user", &serde_json::json!({
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    }));
    ctx.insert("avatar_letter", &template_utils::avatar_letter(&user.username));
    ctx.insert("resources", &resources);
    ctx.insert("metrics", &metrics);
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    ctx.insert("ioc_total", &ioc_total);
    ctx.insert("ioc_high", &ioc_high);
    ctx.insert("ioc_critical", &ioc_critical);
    ctx.insert("ioc_updated", &ioc_updated);

    template_utils::render(&state.templates, "dashboard.html", &ctx)
}
