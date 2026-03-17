/// Live JSON parser — ingests JSON files from live network capture tools.
///
/// This handles pre-formatted JSON output from tools like tshark, Zeek, or
/// custom packet capture scripts. Each JSON record should contain network
/// connection fields (src/dst IP, port, protocol, timestamp).
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::net::IpAddr;
use std::path::Path;

pub struct LiveJsonIngestor;

impl ArtifactParser for LiveJsonIngestor {
    fn name(&self) -> &'static str {
        "Live Capture JSON Parser"
    }

    fn parse(&self, path: &Path, _rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let files = discover_json_files(path)?;
        log::info!("Found {} live JSON files", files.len());
        let mut events = Vec::new();

        for fp in &files {
            log::info!("Parsing live JSON: {}", fp.display());
            match parse_live_json(fp) {
                Ok(mut evts) => events.append(&mut evts),
                Err(e) => log::warn!("Failed to parse {}: {}", fp.display(), e),
            }
        }

        log::info!("Extracted {} live capture events", events.len());
        Ok(events)
    }
}

fn discover_json_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file()
        && path
            .extension()
            .map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        files.push(path.to_path_buf());
        return Ok(files);
    }
    if path.is_dir() {
        let pattern = format!("{}/**/*.json", path.display());
        for entry in glob::glob(&pattern).context("Invalid glob")? {
            if let Ok(p) = entry {
                files.push(p);
            }
        }
    }
    Ok(files)
}

fn parse_live_json(path: &Path) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read live JSON file")?;
    let file_hint = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let normalized = data.trim_start_matches('\u{feff}').trim_start();

    let records: Vec<Value> = if normalized.starts_with('[') {
        serde_json::from_str(normalized).context("Failed to parse JSON array")?
    } else if normalized.starts_with('{') {
        vec![serde_json::from_str(normalized).context("Failed to parse JSON object")?]
    } else {
        normalized
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };

    let mut events = Vec::new();
    for rec in &records {
        if let Some(ev) = normalize_live_record(rec, &file_hint) {
            events.push(ev);
        }
    }
    Ok(events)
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let cleaned = s
        .split('%')
        .next()
        .unwrap_or(s)
        .split('/')
        .next()
        .unwrap_or(s)
        .trim();

    if cleaned.is_empty() || cleaned == "0.0.0.0" || cleaned == "::" {
        return None;
    }

    cleaned.trim_start_matches("::ffff:").parse::<IpAddr>().ok()
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    if let Some(ms) = parse_ms_date(s) {
        return DateTime::<Utc>::from_timestamp_millis(ms);
    }

    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
}

fn parse_ms_date(s: &str) -> Option<i64> {
    // PowerShell JSON date format: /Date(1773639536000)/
    let start = s.find("/Date(")? + 6;
    let end = s[start..].find(')')? + start;
    s[start..end].parse::<i64>().ok()
}

fn get_num_u16(rec: &Value, key: &str) -> Option<u16> {
    rec.get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|n| if n >= 0 { Some(n as u64) } else { None }))
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .map(|n| n as u16)
}

fn get_num_u32(rec: &Value, key: &str) -> Option<u32> {
    rec.get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|n| if n >= 0 { Some(n as u64) } else { None }))
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .map(|n| n as u32)
}

fn get_num_u64(rec: &Value, key: &str) -> Option<u64> {
    rec.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().and_then(|n| if n >= 0 { Some(n as u64) } else { None }))
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    })
}

fn normalize_live_record(rec: &Value, file_hint: &str) -> Option<NetEvent> {
    if file_hint.contains("collection_metadata") || file_hint == "manifest" {
        return None;
    }

    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::LiveCapture, raw);

    ev.timestamp = get_str(rec, "timestamp")
        .or_else(|| get_str(rec, "ts"))
        .or_else(|| get_str(rec, "Timestamp"))
        .or_else(|| get_str(rec, "CreationTime"))
        .or_else(|| get_str(rec, "CreationDate"))
        .and_then(parse_ts);

    ev.local_addr = get_str(rec, "src_ip")
        .or_else(|| get_str(rec, "SourceAddress"))
        .or_else(|| get_str(rec, "src"))
        .or_else(|| get_str(rec, "LocalAddress"))
        .and_then(parse_ip);

    ev.local_port = get_str(rec, "src_port")
        .or_else(|| get_str(rec, "SourcePort"))
        .and_then(|s| s.parse().ok())
        .or_else(|| get_num_u16(rec, "src_port"))
        .or_else(|| get_num_u16(rec, "LocalPort"));

    ev.remote_addr = get_str(rec, "dst_ip")
        .or_else(|| get_str(rec, "DestAddress"))
        .or_else(|| get_str(rec, "dst"))
        .or_else(|| get_str(rec, "RemoteAddress"))
        .or_else(|| get_str(rec, "IPAddress"))
        .or_else(|| get_str(rec, "NextHop"))
        .and_then(parse_ip);

    ev.remote_port = get_str(rec, "dst_port")
        .or_else(|| get_str(rec, "DestPort"))
        .and_then(|s| s.parse().ok())
        .or_else(|| get_num_u16(rec, "dst_port"))
        .or_else(|| get_num_u16(rec, "RemotePort"));

    ev.protocol = get_str(rec, "protocol")
        .or_else(|| get_str(rec, "proto"))
        .or_else(|| get_str(rec, "Protocol"))
        .map(|p| match p.to_lowercase().as_str() {
            "tcp" | "6" => Protocol::Tcp,
            "udp" | "17" => Protocol::Udp,
            "icmp" | "1" => Protocol::Icmp,
            _ => Protocol::Other,
        });

    if ev.protocol.is_none() {
        if file_hint.contains("tcp") {
            ev.protocol = Some(Protocol::Tcp);
        } else if file_hint.contains("udp") {
            ev.protocol = Some(Protocol::Udp);
        }
    }

    ev.process_name = get_str(rec, "process_name")
        .or_else(|| get_str(rec, "ProcessName"))
        .map(String::from);

    if ev.process_name.is_none()
        && (file_hint.contains("process_inventory")
            || file_hint.contains("network_process_modules")
            || file_hint.contains("unsigned_network_binaries"))
    {
        ev.process_name = get_str(rec, "Name").map(String::from);
    }

    ev.pid = get_num_u32(rec, "pid")
        .or_else(|| get_num_u32(rec, "PID"))
        .or_else(|| get_num_u32(rec, "OwningProcess"))
        .or_else(|| get_num_u32(rec, "ProcessId"));

    ev.hostname = get_str(rec, "ServerName")
        .or_else(|| get_str(rec, "ClientComputerName"))
        .or_else(|| get_str(rec, "RecordName"))
        .map(String::from);

    ev.bytes_sent = get_num_u64(rec, "bytes_sent")
        .or_else(|| get_num_u64(rec, "BytesSent"))
        .or_else(|| get_num_u64(rec, "BytesTransferred"));

    ev.bytes_recv = get_num_u64(rec, "bytes_recv")
        .or_else(|| get_num_u64(rec, "BytesRecv"))
        .or_else(|| get_num_u64(rec, "BytesTotal"));

    if file_hint.contains("unsigned_network_binaries") {
        if let Some(status) = get_str(rec, "SignatureStatus") {
            if !status.eq_ignore_ascii_case("Valid") {
                ev.tags.push(Tag::UnsignedProcess);
                ev.tags.push(Tag::SuspiciousProcess);
            }
        }
    }

    if file_hint.contains("firewall") {
        ev.tags.push(Tag::Custom("firewall_snapshot".to_string()));
    }

    if file_hint.contains("smb_connections") {
        if let Some(share) = get_str(rec, "ShareName") {
            let share_lc = share.to_lowercase();
            if share_lc.contains("c$") || share_lc.contains("admin$") {
                ev.tags.push(Tag::AdminShareAccess);
                ev.tags.push(Tag::LateralMovement);
            }
        }
    }

    if ev.direction.is_none() {
        if let Some(state) = get_num_u16(rec, "State") {
            // TCP state enum often maps LISTEN to 2 in PowerShell output.
            if state == 2 {
                ev.direction = Some(Direction::Inbound);
            }
        }
        if ev.direction.is_none() {
            ev.direction = Some(Direction::Unknown);
        }
    }

    // Keep records that contain network addressing, host-level destination,
    // process identity, or meaningful forensic tags.
    if ev.local_addr.is_some()
        || ev.remote_addr.is_some()
        || ev.hostname.is_some()
        || ev.pid.is_some()
        || ev.process_name.is_some()
        || !ev.tags.is_empty()
    {
        Some(ev)
    } else {
        None
    }
}
