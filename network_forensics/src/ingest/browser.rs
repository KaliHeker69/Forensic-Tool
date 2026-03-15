use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::Connection;
use std::path::Path;

pub struct BrowserIngestor;

impl ArtifactParser for BrowserIngestor {
    fn name(&self) -> &'static str {
        "Browser History Parser (SQLite)"
    }

    fn parse(&self, path: &Path, _rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let mut all_events = Vec::new();
        let db_files = discover_browser_dbs(path)?;
        log::info!("Found {} browser database files", db_files.len());

        for db_path in &db_files {
            log::info!("Parsing browser DB: {}", db_path.display());
            match parse_browser_db(db_path) {
                Ok(events) => {
                    log::info!("  -> {} events from {}", events.len(), db_path.display());
                    all_events.extend(events);
                }
                Err(e) => {
                    log::warn!("Failed to parse {}: {}", db_path.display(), e);
                }
            }
        }
        Ok(all_events)
    }
}

fn discover_browser_dbs(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(files);
    }

    if path.is_dir() {
        // Chrome / Edge History (SQLite, filename "History")
        for pattern in &[
            "{}/**/History",
            "{}/**/places.sqlite",
            "{}/**/places.sqlite-wal",
        ] {
            let glob_pat = pattern.replace("{}", &path.display().to_string());
            for entry in glob::glob(&glob_pat).context("Invalid glob")? {
                if let Ok(p) = entry {
                    if !files.contains(&p) {
                        files.push(p);
                    }
                }
            }
        }
    }
    Ok(files)
}

fn parse_browser_db(db_path: &Path) -> Result<Vec<NetEvent>> {
    let conn =
        Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("Failed to open browser database")?;

    let filename = db_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    if filename == "places.sqlite" {
        parse_firefox_places(&conn)
    } else {
        // Chrome / Edge share the same Chromium schema
        parse_chromium_history(&conn)
    }
}

fn parse_chromium_history(conn: &Connection) -> Result<Vec<NetEvent>> {
    let mut events = Vec::new();

    // URLs table
    if let Ok(mut stmt) = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC",
    ) {
        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0).unwrap_or_default();
            let title: String = row.get(1).unwrap_or_default();
            let visit_count: i64 = row.get(2).unwrap_or(0);
            let last_visit: i64 = row.get(3).unwrap_or(0);
            Ok((url, title, visit_count, last_visit))
        })?;

        for row in rows.flatten() {
            let (url, title, visit_count, last_visit) = row;
            let mut ev = NetEvent::new(
                ArtifactSource::BrowserHistory,
                format!("Browser URL: {} ({})", url, title),
            );
            ev.hostname = extract_hostname_from_url(&url);
            ev.direction = Some(Direction::Outbound);
            ev.timestamp = chromium_timestamp_to_utc(last_visit);
            ev.raw_evidence = format!(
                "URL: {} Title: {} Visits: {}",
                url, title, visit_count
            );
            events.push(ev);
        }
    }

    // Downloads table
    if let Ok(mut stmt) = conn.prepare(
        "SELECT tab_url, target_path, start_time, received_bytes, total_bytes FROM downloads ORDER BY start_time DESC",
    ) {
        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0).unwrap_or_default();
            let target: String = row.get(1).unwrap_or_default();
            let start_time: i64 = row.get(2).unwrap_or(0);
            let received: i64 = row.get(3).unwrap_or(0);
            let total: i64 = row.get(4).unwrap_or(0);
            Ok((url, target, start_time, received, total))
        })?;

        for row in rows.flatten() {
            let (url, target, start_time, received, total) = row;
            let mut ev = NetEvent::new(
                ArtifactSource::BrowserHistory,
                format!("Download: {} -> {}", url, target),
            );
            ev.hostname = extract_hostname_from_url(&url);
            ev.direction = Some(Direction::Outbound);
            ev.timestamp = chromium_timestamp_to_utc(start_time);
            ev.bytes_recv = Some(received.max(0) as u64);
            ev.raw_evidence = format!(
                "Download URL: {} Target: {} Size: {}/{}",
                url, target, received, total
            );
            events.push(ev);
        }
    }

    Ok(events)
}

fn parse_firefox_places(conn: &Connection) -> Result<Vec<NetEvent>> {
    let mut events = Vec::new();

    if let Ok(mut stmt) = conn.prepare(
        "SELECT p.url, p.title, p.visit_count, h.visit_date \
         FROM moz_places p LEFT JOIN moz_historyvisits h ON p.id = h.place_id \
         ORDER BY h.visit_date DESC",
    ) {
        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0).unwrap_or_default();
            let title: String = row.get(1).unwrap_or_default();
            let visit_count: i64 = row.get(2).unwrap_or(0);
            let visit_date: i64 = row.get(3).unwrap_or(0);
            Ok((url, title, visit_count, visit_date))
        })?;

        for row in rows.flatten() {
            let (url, title, visit_count, visit_date) = row;
            let mut ev = NetEvent::new(
                ArtifactSource::BrowserHistory,
                format!("Firefox: {} ({})", url, title),
            );
            ev.hostname = extract_hostname_from_url(&url);
            ev.direction = Some(Direction::Outbound);
            // Firefox timestamps are in microseconds since Unix epoch
            ev.timestamp = DateTime::from_timestamp(
                visit_date / 1_000_000,
                ((visit_date % 1_000_000) * 1000) as u32,
            );
            ev.raw_evidence = format!(
                "URL: {} Title: {} Visits: {}",
                url, title, visit_count
            );
            events.push(ev);
        }
    }

    Ok(events)
}

/// Chromium stores timestamps as microseconds since 1601-01-01
fn chromium_timestamp_to_utc(chromium_ts: i64) -> Option<DateTime<Utc>> {
    if chromium_ts <= 0 {
        return None;
    }
    // Chromium epoch: microseconds since 1601-01-01
    // Unix epoch offset in microseconds from 1601 to 1970
    let epoch_offset: i64 = 11_644_473_600_000_000;
    let unix_us = chromium_ts - epoch_offset;
    DateTime::from_timestamp(unix_us / 1_000_000, ((unix_us % 1_000_000) * 1000) as u32)
}

fn extract_hostname_from_url(url: &str) -> Option<String> {
    // Simple extraction: find the hostname between :// and the next /
    let after_scheme = url.find("://").map(|i| &url[i + 3..])?;
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
