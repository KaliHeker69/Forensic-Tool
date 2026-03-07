// =============================================================================
// Browser Forensics — Automated Timeline Builder
// =============================================================================
// Aggregates all timestamped events across all browser profiles into a
// single sorted timeline for forensic analysis.
// =============================================================================

use crate::models::*;

/// Build a unified, chronologically-sorted timeline from all artifact collections.
pub fn build_timeline(input: &ForensicInput) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for coll in &input.artifacts {
        let browser = coll.browser.to_string();
        let profile = coll.profile_name.clone().unwrap_or_default();

        // History entries
        for entry in &coll.history {
            if let Some(ref ts) = entry.last_visit_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "visit".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.title.clone(),
                    details: entry.visit_count.map(|vc| format!("Visit count: {}", vc)),
                });
            }
        }

        // Downloads
        for entry in &coll.downloads {
            if let Some(ref ts) = entry.start_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "download_start".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.target_path.clone(),
                    details: entry.mime_type.clone().map(|m| format!("MIME: {}", m)),
                });
            }
            if let Some(ref ts) = entry.end_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "download_end".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.target_path.clone(),
                    details: entry.state.clone(),
                });
            }
        }

        // Cookies
        for entry in &coll.cookies {
            if let Some(ref ts) = entry.creation_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "cookie_created".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.host.clone()),
                    title: Some(entry.name.clone()),
                    details: Some(format!(
                        "Secure: {}, HttpOnly: {}",
                        entry.is_secure.map_or("?", |v| if v { "yes" } else { "no" }),
                        entry.is_httponly.map_or("?", |v| if v { "yes" } else { "no" }),
                    )),
                });
            }
            if let Some(ref ts) = entry.last_access_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "cookie_accessed".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.host.clone()),
                    title: Some(entry.name.clone()),
                    details: None,
                });
            }
        }

        // Logins
        for entry in &coll.logins {
            if let Some(ref ts) = entry.date_created {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "login_created".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.origin_url.clone()),
                    title: entry.username.clone(),
                    details: entry.encrypted_with.clone(),
                });
            }
            if let Some(ref ts) = entry.date_last_used {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "login_used".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.origin_url.clone()),
                    title: entry.username.clone(),
                    details: entry.times_used.map(|t| format!("Times used: {}", t)),
                });
            }
        }

        // Autofill
        for entry in &coll.autofill {
            if let Some(ref ts) = entry.first_used {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "autofill_first_used".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: None,
                    title: Some(format!("{}: {}", entry.field_name, entry.value)),
                    details: None,
                });
            }
            if let Some(ref ts) = entry.last_used {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "autofill_last_used".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: None,
                    title: Some(format!("{}: {}", entry.field_name, entry.value)),
                    details: entry.times_used.map(|t| format!("Times used: {}", t)),
                });
            }
        }

        // Form History (Firefox)
        for entry in &coll.form_history {
            if let Some(ref ts) = entry.last_used {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "form_history".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: None,
                    title: Some(format!("{}: {}", entry.field_name, entry.value)),
                    details: None,
                });
            }
        }

        // Bookmarks
        for entry in &coll.bookmarks {
            if let Some(ref ts) = entry.date_added {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "bookmark_added".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.title.clone(),
                    details: entry.folder.clone(),
                });
            }
        }

        // Extensions
        for entry in &coll.extensions {
            if let Some(ref ts) = entry.install_date {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "extension_installed".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: None,
                    title: entry.name.clone().or_else(|| Some(entry.id.clone())),
                    details: entry.version.clone().map(|v| format!("v{}", v)),
                });
            }
        }

        // Sessions
        for entry in &coll.sessions {
            if let Some(ref ts) = entry.last_active_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "session_tab".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.title.clone(),
                    details: Some(format!(
                        "Window: {}, Tab: {}",
                        entry.window_id.map_or("?".into(), |v| v.to_string()),
                        entry.tab_index.map_or("?".into(), |v| v.to_string()),
                    )),
                });
            }
        }

        // Cache extracted items
        for entry in &coll.cache_extracted {
            if let Some(ref ts) = entry.request_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "cache_request".into(),
                    source_browser: browser.clone(),
                    profile: Some(profile.clone()),
                    url: Some(entry.url.clone()),
                    title: entry.content_type.clone(),
                    details: entry.content_length.map(|s| format!("Size: {} bytes", s)),
                });
            }
        }
    }

    // Sort chronologically
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    events
}
