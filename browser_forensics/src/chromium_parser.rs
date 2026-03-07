// =============================================================================
// Browser Forensics — Chromium Artifact Parser
// =============================================================================
// Parses Chrome / Edge / Brave profile directories.
// SQLite DBs: History (urls, visits, downloads), Cookies, Login Data,
//             Web Data (autofill), Top Sites
// JSON files: Bookmarks, Preferences
// Directory:  Extensions/
// =============================================================================

use std::path::Path;
use anyhow::Result;
use rusqlite::{Connection, OpenFlags};

use crate::models::*;

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Chromium WebKit timestamp → ISO-8601 string.
/// WebKit = microseconds since 1601-01-01 UTC
fn webkit_to_iso(ts: i64) -> Option<String> {
    if ts <= 0 {
        return None;
    }
    let unix_secs = (ts / 1_000_000) - 11_644_473_600i64;
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Open a SQLite DB read-only (with SQLITE_OPEN_READ_ONLY | NO_MUTEX).
fn open_db(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    // Try to be tolerant of WAL-mode or locked DBs
    conn.pragma_update(None, "journal_mode", "OFF").ok();
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse all artifacts from a Chromium-based profile directory and populate
/// an `ArtifactCollection`.
pub fn parse_chromium_profile(profile_dir: &Path, browser: Browser, profile_name: &str) -> ArtifactCollection {
    let mut coll = ArtifactCollection {
        browser,
        profile_path: Some(profile_dir.to_string_lossy().into()),
        profile_name: Some(profile_name.to_string()),
        history: Vec::new(),
        downloads: Vec::new(),
        cookies: Vec::new(),
        logins: Vec::new(),
        autofill: Vec::new(),
        bookmarks: Vec::new(),
        extensions: Vec::new(),
        cache: Vec::new(),
        sessions: Vec::new(),
        preferences: Vec::new(),
        top_sites: Vec::new(),
        brave_shields: Vec::new(),
        brave_rewards: None,
        brave_wallet: Vec::new(),
        brave_tor: None,
        form_history: Vec::new(),
        permissions: Vec::new(),
        typed_urls: Vec::new(),
        wal_recovered: Vec::new(),
        cache_extracted: Vec::new(),
        extension_files: Vec::new(),
    };

    // --- History DB (urls, visits, downloads) ---------------------------------
    let history_path = profile_dir.join("History");
    if history_path.exists() {
        match parse_history(&history_path) {
            Ok((h, d)) => {
                eprintln!("    [+] History: {} URLs, {} downloads", h.len(), d.len());
                coll.history = h;
                coll.downloads = d;
            }
            Err(e) => eprintln!("    [!] History parse error: {}", e),
        }
    }

    // --- Cookies DB -----------------------------------------------------------
    let cookies_path = profile_dir.join("Network").join("Cookies");
    let cookies_alt = profile_dir.join("Cookies");
    let cp = if cookies_path.exists() { Some(cookies_path) } else if cookies_alt.exists() { Some(cookies_alt) } else { None };
    if let Some(cp) = cp {
        match parse_cookies(&cp) {
            Ok(c) => {
                eprintln!("    [+] Cookies: {} entries", c.len());
                coll.cookies = c;
            }
            Err(e) => eprintln!("    [!] Cookies parse error: {}", e),
        }
    }

    // --- Login Data -----------------------------------------------------------
    let login_path = profile_dir.join("Login Data");
    if login_path.exists() {
        match parse_logins(&login_path) {
            Ok(l) => {
                eprintln!("    [+] Logins: {} entries", l.len());
                coll.logins = l;
            }
            Err(e) => eprintln!("    [!] Login Data parse error: {}", e),
        }
    }

    // --- Web Data (autofill) --------------------------------------------------
    let webdata_path = profile_dir.join("Web Data");
    if webdata_path.exists() {
        match parse_autofill(&webdata_path) {
            Ok(a) => {
                eprintln!("    [+] Autofill: {} entries", a.len());
                coll.autofill = a;
            }
            Err(e) => eprintln!("    [!] Web Data parse error: {}", e),
        }
    }

    // --- Top Sites ------------------------------------------------------------
    let topsites_path = profile_dir.join("Top Sites");
    if topsites_path.exists() {
        match parse_top_sites(&topsites_path) {
            Ok(t) => {
                eprintln!("    [+] Top Sites: {} entries", t.len());
                coll.top_sites = t;
            }
            Err(e) => eprintln!("    [!] Top Sites parse error: {}", e),
        }
    }

    // --- Bookmarks (JSON) -----------------------------------------------------
    let bookmarks_path = profile_dir.join("Bookmarks");
    if bookmarks_path.exists() {
        match parse_bookmarks(&bookmarks_path) {
            Ok(b) => {
                eprintln!("    [+] Bookmarks: {} entries", b.len());
                coll.bookmarks = b;
            }
            Err(e) => eprintln!("    [!] Bookmarks parse error: {}", e),
        }
    }

    // --- Preferences (JSON) — extract forensically interesting keys -----------
    let prefs_path = profile_dir.join("Preferences");
    if prefs_path.exists() {
        match parse_preferences(&prefs_path) {
            Ok(p) => {
                eprintln!("    [+] Preferences: {} keys", p.len());
                coll.preferences = p;
            }
            Err(e) => eprintln!("    [!] Preferences parse error: {}", e),
        }
    }

    // --- Extensions -----------------------------------------------------------
    let ext_dir = profile_dir.join("Extensions");
    if ext_dir.is_dir() {
        match parse_extensions(&ext_dir) {
            Ok(e) => {
                eprintln!("    [+] Extensions: {} entries", e.len());
                coll.extensions = e;
            }
            Err(err) => eprintln!("    [!] Extensions parse error: {}", err),
        }
    }

    // --- WAL/Journal recovery ------------------------------------------------
    let wal_rows = crate::wal_parser::recover_wal_data(profile_dir);
    if !wal_rows.is_empty() {
        eprintln!("    [+] WAL/Journal recovery: {} items", wal_rows.len());
        coll.wal_recovered = wal_rows;
    }

    // --- Cache extraction ----------------------------------------------------
    let cache_items = crate::cache_parser::parse_chromium_cache(profile_dir);
    if !cache_items.is_empty() {
        eprintln!("    [+] Cache extracted: {} items", cache_items.len());
        coll.cache_extracted = cache_items;
    }

    // --- Session store decoding ----------------------------------------------
    let session_entries = crate::session_parser::parse_chromium_sessions(profile_dir);
    if !session_entries.is_empty() {
        eprintln!("    [+] Sessions recovered: {} tabs", session_entries.len());
        coll.sessions = session_entries;
    }

    // --- Extension code files ------------------------------------------------
    let ext_files = crate::extension_extractor::extract_chromium_extension_files(profile_dir);
    if !ext_files.is_empty() {
        eprintln!("    [+] Extension code files: {} files", ext_files.len());
        coll.extension_files = ext_files;
    }

    coll
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

fn parse_history(db_path: &Path) -> Result<(Vec<HistoryEntry>, Vec<DownloadEntry>)> {
    let conn = open_db(db_path)?;

    // --- urls + visits -------------------------------------------------------
    let mut history = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT u.url, u.title, u.visit_count, u.last_visit_time,
                    v.from_visit, v.visit_duration
             FROM urls u
             LEFT JOIN visits v ON u.id = v.url
             ORDER BY u.last_visit_time DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_count: Option<i64> = row.get(2)?;
            let last_visit: Option<i64> = row.get(3)?;
            let _from_visit: Option<i64> = row.get(4)?;
            let visit_duration: Option<i64> = row.get(5)?;
            Ok((url, title, visit_count, last_visit, visit_duration))
        })?;

        // Deduplicate by URL (the LEFT JOIN may fan out)
        let mut seen = std::collections::HashSet::new();
        for row in rows.flatten() {
            let (url, title, vc, lv, dur) = row;
            if !seen.insert(url.clone()) {
                continue;
            }
            history.push(HistoryEntry {
                url,
                title,
                visit_count: vc.map(|v| v as u64),
                last_visit_time: lv.and_then(webkit_to_iso),
                visit_type: None,
                referrer: None,
                visit_duration: dur.map(|d| format!("{} µs", d)),
            });
        }
    }

    // --- downloads -----------------------------------------------------------
    let mut downloads = Vec::new();
    {
        let has_downloads = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='downloads'")
            .and_then(|mut s| s.exists([]))
            .unwrap_or(false);

        if has_downloads {
            let mut stmt = conn.prepare(
                "SELECT target_path, tab_url, start_time, end_time,
                        received_bytes, total_bytes, state, mime_type, referrer
                 FROM downloads
                 ORDER BY start_time DESC"
            )?;

            let rows = stmt.query_map([], |row| {
                Ok(DownloadEntry {
                    target_path: row.get(0)?,
                    url: row.get::<_, String>(1).unwrap_or_default(),
                    start_time: row.get::<_, Option<i64>>(2)?.and_then(webkit_to_iso),
                    end_time: row.get::<_, Option<i64>>(3)?.and_then(webkit_to_iso),
                    received_bytes: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    total_bytes: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                    state: row.get::<_, Option<i64>>(6)?.map(|s| match s {
                        0 => "in_progress".into(),
                        1 => "complete".into(),
                        2 => "cancelled".into(),
                        3 => "interrupted".into(),
                        _ => format!("unknown({})", s),
                    }),
                    mime_type: row.get(7)?,
                    referrer: row.get(8)?,
                })
            })?;

            for r in rows.flatten() {
                downloads.push(r);
            }
        }
    }

    Ok((history, downloads))
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

fn parse_cookies(db_path: &Path) -> Result<Vec<CookieEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host_key, name, path,
                creation_utc, expires_utc, last_access_utc,
                is_secure, is_httponly, is_persistent
         FROM cookies
         ORDER BY host_key, name"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(CookieEntry {
            host: row.get(0)?,
            name: row.get(1)?,
            value: None, // encrypted — we don't dump values
            path: row.get(2)?,
            creation_time: row.get::<_, Option<i64>>(3)?.and_then(webkit_to_iso),
            expiry_time: row.get::<_, Option<i64>>(4)?.and_then(webkit_to_iso),
            last_access_time: row.get::<_, Option<i64>>(5)?.and_then(webkit_to_iso),
            is_secure: row.get::<_, Option<i32>>(6)?.map(|v| v != 0),
            is_httponly: row.get::<_, Option<i32>>(7)?.map(|v| v != 0),
            encrypted: Some(true),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Login Data
// ---------------------------------------------------------------------------

fn parse_logins(db_path: &Path) -> Result<Vec<LoginEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value,
                date_created, date_last_used, times_used
         FROM logins
         ORDER BY date_last_used DESC"
    )?;

    let rows = stmt.query_map([], |row| {
        let user: Option<String> = row.get(1)?;
        Ok(LoginEntry {
            origin_url: row.get(0)?,
            username: user,
            password_present: Some(true),
            date_created: row.get::<_, Option<i64>>(2)?.and_then(webkit_to_iso),
            date_last_used: row.get::<_, Option<i64>>(3)?.and_then(webkit_to_iso),
            times_used: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            encrypted_with: Some("DPAPI".into()),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Autofill (Web Data)
// ---------------------------------------------------------------------------

fn parse_autofill(db_path: &Path) -> Result<Vec<AutofillEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let has_autofill = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='autofill'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false);

    if !has_autofill {
        return Ok(out);
    }

    let mut stmt = conn.prepare(
        "SELECT name, value, count, date_created, date_last_used
         FROM autofill
         ORDER BY date_last_used DESC"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AutofillEntry {
            field_name: row.get(0)?,
            value: row.get(1)?,
            times_used: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
            first_used: row.get::<_, Option<i64>>(3)?.and_then(webkit_to_iso),
            last_used: row.get::<_, Option<i64>>(4)?.and_then(webkit_to_iso),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Top Sites
// ---------------------------------------------------------------------------

fn parse_top_sites(db_path: &Path) -> Result<Vec<TopSiteEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT url, url_rank, title FROM top_sites ORDER BY url_rank ASC"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(TopSiteEntry {
            url: row.get(0)?,
            rank: row.get::<_, Option<i32>>(1)?.map(|v| v as u32),
            title: row.get(2)?,
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Bookmarks (JSON)
// ---------------------------------------------------------------------------

fn parse_bookmarks(path: &Path) -> Result<Vec<BookmarkEntry>> {
    let raw = std::fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&raw)?;
    let mut out = Vec::new();

    if let Some(roots) = val.get("roots").and_then(|v| v.as_object()) {
        for (folder_name, node) in roots {
            walk_bookmark_node(node, folder_name, &mut out);
        }
    }
    Ok(out)
}

fn walk_bookmark_node(node: &serde_json::Value, folder: &str, out: &mut Vec<BookmarkEntry>) {
    let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");

    if node_type == "url" {
        let url = node.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let title = node.get("name").and_then(|v| v.as_str()).map(String::from);
        let date_added = node
            .get("date_added")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(webkit_to_iso);
        let date_modified = node
            .get("date_modified")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(webkit_to_iso);
        out.push(BookmarkEntry {
            url,
            title,
            folder: Some(folder.to_string()),
            date_added,
            date_modified,
        });
    }

    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        let sub_folder = node.get("name").and_then(|v| v.as_str()).unwrap_or(folder);
        for child in children {
            walk_bookmark_node(child, sub_folder, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Preferences (JSON) — forensically interesting keys
// ---------------------------------------------------------------------------

const INTERESTING_PREF_KEYS: &[&str] = &[
    "download.default_directory",
    "download.prompt_for_download",
    "safebrowsing.enabled",
    "safebrowsing.enhanced",
    "proxy",
    "profile.name",
    "profile.default_content_setting_values",
    "extensions.settings",
    "brave.shields",
    "brave.tor",
    "dns_over_https",
    "search.suggest_enabled",
    "signin.allowed",
    "sync",
    "session.restore_on_startup",
];

fn parse_preferences(path: &Path) -> Result<Vec<PreferenceEntry>> {
    let raw = std::fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&raw)?;
    let mut out = Vec::new();

    // Flatten the top two levels and match interesting keys
    if let Some(obj) = val.as_object() {
        for (k1, v1) in obj {
            // Check top-level
            if INTERESTING_PREF_KEYS.iter().any(|&ik| ik == k1.as_str()) {
                out.push(PreferenceEntry {
                    key: k1.clone(),
                    value: v1.clone(),
                    note: None,
                });
                continue;
            }
            // Check sub-level
            if let Some(sub) = v1.as_object() {
                for (k2, v2) in sub {
                    let dotted = format!("{}.{}", k1, k2);
                    if INTERESTING_PREF_KEYS.iter().any(|&ik| ik == dotted.as_str()) {
                        out.push(PreferenceEntry {
                            key: dotted,
                            value: v2.clone(),
                            note: None,
                        });
                    }
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

fn parse_extensions(ext_dir: &Path) -> Result<Vec<ExtensionEntry>> {
    let mut out = Vec::new();

    for entry in std::fs::read_dir(ext_dir)?.flatten() {
        let ext_id_dir = entry.path();
        if !ext_id_dir.is_dir() {
            continue;
        }
        let ext_id = ext_id_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Find the latest version sub-directory with manifest.json
        let mut manifest_path: Option<std::path::PathBuf> = None;
        let mut version_dir_name: Option<String> = None;

        if let Ok(versions) = std::fs::read_dir(&ext_id_dir) {
            for vdir in versions.flatten() {
                let vpath = vdir.path();
                let m = vpath.join("manifest.json");
                if m.exists() {
                    version_dir_name = vdir.file_name().to_str().map(String::from);
                    manifest_path = Some(m);
                }
            }
        }

        // Also check manifest.json directly in ext_id_dir
        let direct = ext_id_dir.join("manifest.json");
        if direct.exists() && manifest_path.is_none() {
            manifest_path = Some(direct);
        }

        if let Some(mp) = manifest_path {
            if let Ok(raw) = std::fs::read_to_string(&mp) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let name = val.get("name").and_then(|v| v.as_str()).map(String::from);
                    let desc = val.get("description").and_then(|v| v.as_str()).map(String::from);
                    let version = val.get("version").and_then(|v| v.as_str()).map(String::from)
                        .or(version_dir_name);
                    let permissions = val.get("permissions")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        });

                    out.push(ExtensionEntry {
                        id: ext_id,
                        name,
                        version,
                        description: desc,
                        permissions,
                        install_date: None,
                        enabled: Some(true),
                        source: None,
                    });
                    continue;
                }
            }
        }

        // Couldn't parse manifest, still record the extension ID
        out.push(ExtensionEntry {
            id: ext_id,
            name: None,
            version: version_dir_name,
            description: None,
            permissions: None,
            install_date: None,
            enabled: None,
            source: None,
        });
    }
    Ok(out)
}
