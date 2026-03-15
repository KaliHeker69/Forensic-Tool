use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::Connection;
use std::path::Path;

pub struct SrumIngestor;

impl ArtifactParser for SrumIngestor {
    fn name(&self) -> &'static str {
        "SRUM Database Parser"
    }

    fn parse(&self, path: &Path, _rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let db_path = find_srum_db(path)?;
        match db_path {
            Some(p) => parse_srum_db(&p),
            None => {
                log::info!("No SRUDB.dat found under {}", path.display());
                Ok(Vec::new())
            }
        }
    }
}

fn find_srum_db(path: &Path) -> Result<Option<std::path::PathBuf>> {
    if path.is_file() {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if name == "srudb.dat" || name.ends_with(".sqlite") || name.ends_with(".db") {
            return Ok(Some(path.to_path_buf()));
        }
    }
    if path.is_dir() {
        for entry in glob::glob(&format!("{}/**/SRUDB.dat", path.display()))
            .context("Invalid glob")?
        {
            if let Ok(p) = entry {
                return Ok(Some(p));
            }
        }
        // Also try common KAPE export names
        for entry in
            glob::glob(&format!("{}/**/srum*.db", path.display())).context("Invalid glob")?
        {
            if let Ok(p) = entry {
                return Ok(Some(p));
            }
        }
        for entry in
            glob::glob(&format!("{}/**/srum*.sqlite", path.display())).context("Invalid glob")?
        {
            if let Ok(p) = entry {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

fn parse_srum_db(db_path: &Path) -> Result<Vec<NetEvent>> {
    log::info!("Parsing SRUM database: {}", db_path.display());
    let conn =
        Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("Failed to open SRUM database")?;

    let mut events = Vec::new();

    // Parse network usage data (table: {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89})
    match parse_network_usage(&conn) {
        Ok(mut evts) => events.append(&mut evts),
        Err(e) => log::warn!("Failed to parse SRUM network usage table: {}", e),
    }

    // Parse network connectivity data (table: {DD6636C4-8929-4683-974E-22C046A43763})
    match parse_network_connectivity(&conn) {
        Ok(mut evts) => events.append(&mut evts),
        Err(e) => log::warn!("Failed to parse SRUM network connectivity table: {}", e),
    }

    log::info!("Extracted {} events from SRUM", events.len());
    Ok(events)
}

fn parse_network_usage(conn: &Connection) -> Result<Vec<NetEvent>> {
    // SRUM network usage table - the exact table name varies
    let table_name = find_table_like(conn, "D10CA2FE")?;
    let table_name = match table_name {
        Some(t) => t,
        None => {
            log::info!("SRUM network usage table not found");
            return Ok(Vec::new());
        }
    };

    let query = format!(
        "SELECT AppId, UserId, BytesSent, BytesRecvd, TimeStamp FROM \"{}\"",
        table_name
    );
    let mut stmt = conn.prepare(&query).context("Failed to prepare SRUM network query")?;
    let mut events = Vec::new();

    let rows = stmt.query_map([], |row| {
        let app_id: String = row.get::<_, String>(0).unwrap_or_default();
        let _user_id: String = row.get::<_, String>(1).unwrap_or_default();
        let bytes_sent: i64 = row.get::<_, i64>(2).unwrap_or(0);
        let bytes_recv: i64 = row.get::<_, i64>(3).unwrap_or(0);
        let timestamp: String = row.get::<_, String>(4).unwrap_or_default();
        Ok((app_id, bytes_sent, bytes_recv, timestamp))
    })?;

    for row in rows.flatten() {
        let (app_id, bytes_sent, bytes_recv, timestamp_str) = row;

        if bytes_sent == 0 && bytes_recv == 0 {
            continue;
        }

        let mut ev = NetEvent::new(
            ArtifactSource::Srum,
            format!(
                "SRUM: {} sent={} recv={}",
                app_id, bytes_sent, bytes_recv
            ),
        );
        ev.process_name = Some(extract_process_name(&app_id));
        ev.bytes_sent = Some(bytes_sent as u64);
        ev.bytes_recv = Some(bytes_recv as u64);
        ev.direction = Some(Direction::Outbound);
        ev.timestamp = parse_srum_timestamp(&timestamp_str);

        events.push(ev);
    }

    Ok(events)
}

fn parse_network_connectivity(conn: &Connection) -> Result<Vec<NetEvent>> {
    let table_name = find_table_like(conn, "DD6636C4")?;
    let table_name = match table_name {
        Some(t) => t,
        None => {
            log::info!("SRUM network connectivity table not found");
            return Ok(Vec::new());
        }
    };

    let query = format!(
        "SELECT AppId, UserId, ConnectedTime, TimeStamp FROM \"{}\"",
        table_name
    );
    let mut stmt = conn
        .prepare(&query)
        .context("Failed to prepare SRUM connectivity query")?;
    let mut events = Vec::new();

    let rows = stmt.query_map([], |row| {
        let app_id: String = row.get::<_, String>(0).unwrap_or_default();
        let _user_id: String = row.get::<_, String>(1).unwrap_or_default();
        let connected_time: i64 = row.get::<_, i64>(2).unwrap_or(0);
        let timestamp: String = row.get::<_, String>(3).unwrap_or_default();
        Ok((app_id, connected_time, timestamp))
    })?;

    for row in rows.flatten() {
        let (app_id, connected_time, timestamp_str) = row;
        if connected_time == 0 {
            continue;
        }

        let mut ev = NetEvent::new(
            ArtifactSource::Srum,
            format!("SRUM connectivity: {} time={}s", app_id, connected_time),
        );
        ev.process_name = Some(extract_process_name(&app_id));
        ev.direction = Some(Direction::Outbound);
        ev.timestamp = parse_srum_timestamp(&timestamp_str);
        events.push(ev);
    }

    Ok(events)
}

fn find_table_like(conn: &Connection, pattern: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ?1",
    )?;
    let pattern_like = format!("%{}%", pattern);
    let mut rows = stmt.query([&pattern_like])?;
    if let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        return Ok(Some(name));
    }
    Ok(None)
}

fn extract_process_name(app_id: &str) -> String {
    // SRUM AppId can be a path like \device\harddiskvolume2\windows\system32\svchost.exe
    // or just a name
    let normalized = app_id.replace('\\', "/");
    normalized
        .rsplit('/')
        .next()
        .unwrap_or(app_id)
        .to_lowercase()
}

fn parse_srum_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try various formats
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
        .or_else(|| {
            // Windows FILETIME as integer string
            s.parse::<i64>().ok().and_then(|ft| {
                if ft <= 0 {
                    return None;
                }
                // Windows FILETIME: 100-nanosecond intervals since 1601-01-01
                let unix_epoch_offset = 116_444_736_000_000_000i64;
                let unix_nanos = (ft - unix_epoch_offset) * 100;
                DateTime::from_timestamp(unix_nanos / 1_000_000_000, (unix_nanos % 1_000_000_000) as u32)
            })
        })
}
