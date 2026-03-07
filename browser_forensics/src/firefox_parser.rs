// =============================================================================
// Browser Forensics — Firefox Artifact Parser
// =============================================================================
// Parses Firefox profile directories.
// SQLite DBs: places.sqlite (history, bookmarks, downloads),
//             cookies.sqlite, formhistory.sqlite, permissions.sqlite
// JSON files: logins.json, extensions.json / addons.json
// =============================================================================

use std::path::Path;
use anyhow::Result;
use rusqlite::{Connection, OpenFlags};

use crate::models::*;

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Firefox timestamp → ISO-8601 string.
/// Firefox = microseconds since 1970-01-01 UTC (Unix epoch × 10⁶)
fn firefox_ts_to_iso(ts: i64) -> Option<String> {
    if ts <= 0 {
        return None;
    }
    let unix_secs = ts / 1_000_000;
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Some Firefox columns store epoch in seconds (e.g. cookies.expiry).
fn epoch_secs_to_iso(ts: i64) -> Option<String> {
    if ts <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn open_db(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.pragma_update(None, "journal_mode", "OFF").ok();
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn parse_firefox_profile(profile_dir: &Path, profile_name: &str) -> ArtifactCollection {
    let mut coll = ArtifactCollection {
        browser: Browser::Firefox,
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

    // --- places.sqlite (history + bookmarks + downloads) ---------------------
    let places_path = profile_dir.join("places.sqlite");
    if places_path.exists() {
        match parse_places(&places_path) {
            Ok((h, b, d)) => {
                eprintln!("    [+] places.sqlite: {} history, {} bookmarks, {} downloads", h.len(), b.len(), d.len());
                coll.history = h;
                coll.bookmarks = b;
                coll.downloads = d;
            }
            Err(e) => eprintln!("    [!] places.sqlite parse error: {}", e),
        }
    }

    // --- cookies.sqlite -------------------------------------------------------
    let cookies_path = profile_dir.join("cookies.sqlite");
    if cookies_path.exists() {
        match parse_cookies(&cookies_path) {
            Ok(c) => {
                eprintln!("    [+] cookies.sqlite: {} entries", c.len());
                coll.cookies = c;
            }
            Err(e) => eprintln!("    [!] cookies.sqlite parse error: {}", e),
        }
    }

    // --- formhistory.sqlite ---------------------------------------------------
    let form_path = profile_dir.join("formhistory.sqlite");
    if form_path.exists() {
        match parse_formhistory(&form_path) {
            Ok(f) => {
                eprintln!("    [+] formhistory.sqlite: {} entries", f.len());
                coll.form_history = f;
            }
            Err(e) => eprintln!("    [!] formhistory.sqlite parse error: {}", e),
        }
    }

    // --- permissions.sqlite ---------------------------------------------------
    let perms_path = profile_dir.join("permissions.sqlite");
    if perms_path.exists() {
        match parse_permissions(&perms_path) {
            Ok(p) => {
                eprintln!("    [+] permissions.sqlite: {} entries", p.len());
                coll.permissions = p;
            }
            Err(e) => eprintln!("    [!] permissions.sqlite parse error: {}", e),
        }
    }

    // --- logins.json ----------------------------------------------------------
    let logins_path = profile_dir.join("logins.json");
    if logins_path.exists() {
        match parse_logins_json(&logins_path) {
            Ok(l) => {
                eprintln!("    [+] logins.json: {} entries", l.len());
                coll.logins = l;
            }
            Err(e) => eprintln!("    [!] logins.json parse error: {}", e),
        }
    }

    // --- addons.json / extensions.json ----------------------------------------
    let addons_path = profile_dir.join("addons.json");
    let extensions_json_path = profile_dir.join("extensions.json");
    let ext_source = if addons_path.exists() {
        Some(addons_path)
    } else if extensions_json_path.exists() {
        Some(extensions_json_path)
    } else {
        None
    };
    if let Some(ep) = ext_source {
        match parse_addons_json(&ep) {
            Ok(e) => {
                eprintln!("    [+] addons: {} entries", e.len());
                coll.extensions = e;
            }
            Err(e) => eprintln!("    [!] addons parse error: {}", e),
        }
    }

    // --- WAL/Journal recovery ------------------------------------------------
    let wal_rows = crate::wal_parser::recover_wal_data(profile_dir);
    if !wal_rows.is_empty() {
        eprintln!("    [+] WAL/Journal recovery: {} items", wal_rows.len());
        coll.wal_recovered = wal_rows;
    }

    // --- Cache extraction (Firefox cache2) -----------------------------------
    let cache_items = crate::cache_parser::parse_firefox_cache(profile_dir);
    if !cache_items.is_empty() {
        eprintln!("    [+] Cache extracted: {} items", cache_items.len());
        coll.cache_extracted = cache_items;
    }

    // --- Session store decoding (jsonlz4) ------------------------------------
    let session_entries = crate::session_parser::parse_firefox_sessions(profile_dir);
    if !session_entries.is_empty() {
        eprintln!("    [+] Sessions recovered: {} tabs", session_entries.len());
        coll.sessions = session_entries;
    }

    // --- Extension code files ------------------------------------------------
    let ext_files = crate::extension_extractor::extract_firefox_extension_files(profile_dir);
    if !ext_files.is_empty() {
        eprintln!("    [+] Extension code files: {} files", ext_files.len());
        coll.extension_files = ext_files;
    }

    coll
}

// ---------------------------------------------------------------------------
// places.sqlite — history, bookmarks, downloads
// ---------------------------------------------------------------------------

fn parse_places(db_path: &Path) -> Result<(Vec<HistoryEntry>, Vec<BookmarkEntry>, Vec<DownloadEntry>)> {
    let conn = open_db(db_path)?;

    // ---- history ------------------------------------------------------------
    let mut history = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT p.url, p.title, p.visit_count, p.last_visit_date
             FROM moz_places p
             WHERE p.visit_count > 0
             ORDER BY p.last_visit_date DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(HistoryEntry {
                url: row.get(0)?,
                title: row.get(1)?,
                visit_count: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                last_visit_time: row.get::<_, Option<i64>>(3)?.and_then(firefox_ts_to_iso),
                visit_type: None,
                referrer: None,
                visit_duration: None,
            })
        })?;
        for r in rows.flatten() {
            history.push(r);
        }
    }

    // ---- bookmarks ----------------------------------------------------------
    let mut bookmarks = Vec::new();
    {
        let has_table = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='moz_bookmarks'")
            .and_then(|mut s| s.exists([]))
            .unwrap_or(false);

        if has_table {
            let mut stmt = conn.prepare(
                "SELECT p.url, b.title, b.dateAdded,
                        (SELECT pb.title FROM moz_bookmarks pb WHERE pb.id = b.parent) as folder
                 FROM moz_bookmarks b
                 JOIN moz_places p ON b.fk = p.id
                 WHERE b.type = 1
                 ORDER BY b.dateAdded DESC"
            )?;

            let rows = stmt.query_map([], |row| {
                Ok(BookmarkEntry {
                    url: row.get(0)?,
                    title: row.get(1)?,
                    date_added: row.get::<_, Option<i64>>(2)?.and_then(firefox_ts_to_iso),
                    date_modified: None,
                    folder: row.get(3)?,
                })
            })?;
            for r in rows.flatten() {
                bookmarks.push(r);
            }
        }
    }

    // ---- downloads (via moz_annos) ------------------------------------------
    let mut downloads = Vec::new();
    {
        let has_annos = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='moz_annos'")
            .and_then(|mut s| s.exists([]))
            .unwrap_or(false);

        if has_annos {
            // moz_annos links place_id → annotation (downloads/destinationFileURI, etc.)
            let mut stmt = conn.prepare(
                "SELECT p.url, a.content, a.dateAdded
                 FROM moz_annos a
                 JOIN moz_places p ON a.place_id = p.id
                 JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
                 WHERE aa.name = 'downloads/destinationFileURI'
                 ORDER BY a.dateAdded DESC"
            )?;

            let rows = stmt.query_map([], |row| {
                let url: String = row.get(0)?;
                let dest: Option<String> = row.get(1)?;
                let date: Option<i64> = row.get(2)?;
                Ok(DownloadEntry {
                    url,
                    target_path: dest,
                    start_time: date.and_then(firefox_ts_to_iso),
                    end_time: None,
                    received_bytes: None,
                    total_bytes: None,
                    state: None,
                    mime_type: None,
                    referrer: None,
                })
            })?;
            for r in rows.flatten() {
                downloads.push(r);
            }
        }
    }

    Ok((history, bookmarks, downloads))
}

// ---------------------------------------------------------------------------
// cookies.sqlite
// ---------------------------------------------------------------------------

fn parse_cookies(db_path: &Path) -> Result<Vec<CookieEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host, name, path,
                creationTime, expiry, lastAccessed,
                isSecure, isHttpOnly
         FROM moz_cookies
         ORDER BY host, name"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(CookieEntry {
            host: row.get(0)?,
            name: row.get(1)?,
            value: None,
            path: row.get(2)?,
            creation_time: row.get::<_, Option<i64>>(3)?.and_then(firefox_ts_to_iso),
            expiry_time: row.get::<_, Option<i64>>(4)?.and_then(epoch_secs_to_iso),
            last_access_time: row.get::<_, Option<i64>>(5)?.and_then(firefox_ts_to_iso),
            is_secure: row.get::<_, Option<i32>>(6)?.map(|v| v != 0),
            is_httponly: row.get::<_, Option<i32>>(7)?.map(|v| v != 0),
            encrypted: Some(false),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// formhistory.sqlite
// ---------------------------------------------------------------------------

fn parse_formhistory(db_path: &Path) -> Result<Vec<AutofillEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT fieldname, value, timesUsed, firstUsed, lastUsed
         FROM moz_formhistory
         ORDER BY lastUsed DESC"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AutofillEntry {
            field_name: row.get(0)?,
            value: row.get(1)?,
            times_used: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
            first_used: row.get::<_, Option<i64>>(3)?.and_then(firefox_ts_to_iso),
            last_used: row.get::<_, Option<i64>>(4)?.and_then(firefox_ts_to_iso),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// permissions.sqlite
// ---------------------------------------------------------------------------

fn parse_permissions(db_path: &Path) -> Result<Vec<PermissionEntry>> {
    let conn = open_db(db_path)?;
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT origin, type, permission, expireTime
         FROM moz_perms
         ORDER BY origin"
    )?;

    let rows = stmt.query_map([], |row| {
        let cap_int: Option<i32> = row.get(2)?;
        let capability = cap_int.map(|c| match c {
            1 => "allow".into(),
            2 => "deny".into(),
            3 => "prompt".into(),
            _ => format!("unknown({})", c),
        });
        Ok(PermissionEntry {
            origin: row.get(0)?,
            permission_type: row.get(1)?,
            capability,
            expiry_time: row.get::<_, Option<i64>>(3)?.and_then(epoch_secs_to_iso),
        })
    })?;

    for r in rows.flatten() {
        out.push(r);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// logins.json
// ---------------------------------------------------------------------------

fn parse_logins_json(path: &Path) -> Result<Vec<LoginEntry>> {
    let raw = std::fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&raw)?;
    let mut out = Vec::new();

    if let Some(logins) = val.get("logins").and_then(|v| v.as_array()) {
        for l in logins {
            let origin = l.get("hostname")
                .or_else(|| l.get("origin"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let username = l
                .get("encryptedUsername")
                .and_then(|v| v.as_str())
                .map(|_| "(encrypted)".to_string());
            let date_created = l
                .get("timeCreated")
                .and_then(|v| v.as_i64())
                .and_then(|ms| {
                    let secs = ms / 1000;
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                });
            let date_last_used = l
                .get("timeLastUsed")
                .and_then(|v| v.as_i64())
                .and_then(|ms| {
                    let secs = ms / 1000;
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                });
            let times_used = l
                .get("timesUsed")
                .and_then(|v| v.as_u64());

            out.push(LoginEntry {
                origin_url: origin,
                username,
                password_present: Some(true),
                date_created,
                date_last_used,
                times_used,
                encrypted_with: Some("NSS (key4.db)".into()),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// addons.json / extensions.json
// ---------------------------------------------------------------------------

fn parse_addons_json(path: &Path) -> Result<Vec<ExtensionEntry>> {
    let raw = std::fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&raw)?;
    let mut out = Vec::new();

    let addons = val.get("addons").and_then(|v| v.as_array());
    if let Some(addons) = addons {
        for a in addons {
            let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let name = a.get("name").and_then(|v| v.as_str()).map(String::from);
            let version = a.get("version").and_then(|v| v.as_str()).map(String::from);
            let desc = a.get("description").and_then(|v| v.as_str()).map(String::from);
            let enabled = a.get("active").and_then(|v| v.as_bool())
                .or_else(|| a.get("isActive").and_then(|v| v.as_bool()));
            let source = a.get("sourceURI").and_then(|v| v.as_str()).map(String::from);
            let install_date = a
                .get("installDate")
                .and_then(|v| v.as_i64())
                .and_then(|ms| {
                    let secs = ms / 1000;
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                });

            let permissions = a.get("userPermissions")
                .and_then(|v| v.get("permissions"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());

            out.push(ExtensionEntry {
                id,
                name,
                version,
                description: desc,
                permissions,
                install_date,
                enabled,
                source,
            });
        }
    }
    Ok(out)
}
