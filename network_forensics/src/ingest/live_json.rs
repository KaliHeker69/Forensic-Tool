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

    let records: Vec<Value> = if data.trim_start().starts_with('[') {
        serde_json::from_str(&data).context("Failed to parse JSON array")?
    } else {
        data.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };

    let mut events = Vec::new();
    for rec in &records {
        if let Some(ev) = normalize_live_record(rec) {
            events.push(ev);
        }
    }
    Ok(events)
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim_start_matches("::ffff:").parse::<IpAddr>().ok()
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
}

fn normalize_live_record(rec: &Value) -> Option<NetEvent> {
    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::LiveCapture, raw);

    ev.timestamp = get_str(rec, "timestamp")
        .or_else(|| get_str(rec, "ts"))
        .or_else(|| get_str(rec, "Timestamp"))
        .and_then(parse_ts);

    ev.local_addr = get_str(rec, "src_ip")
        .or_else(|| get_str(rec, "SourceAddress"))
        .or_else(|| get_str(rec, "src"))
        .and_then(parse_ip);

    ev.local_port = get_str(rec, "src_port")
        .or_else(|| get_str(rec, "SourcePort"))
        .and_then(|s| s.parse().ok())
        .or_else(|| rec.get("src_port").and_then(Value::as_u64).map(|n| n as u16));

    ev.remote_addr = get_str(rec, "dst_ip")
        .or_else(|| get_str(rec, "DestAddress"))
        .or_else(|| get_str(rec, "dst"))
        .and_then(parse_ip);

    ev.remote_port = get_str(rec, "dst_port")
        .or_else(|| get_str(rec, "DestPort"))
        .and_then(|s| s.parse().ok())
        .or_else(|| rec.get("dst_port").and_then(Value::as_u64).map(|n| n as u16));

    ev.protocol = get_str(rec, "protocol")
        .or_else(|| get_str(rec, "proto"))
        .map(|p| match p.to_lowercase().as_str() {
            "tcp" | "6" => Protocol::Tcp,
            "udp" | "17" => Protocol::Udp,
            "icmp" | "1" => Protocol::Icmp,
            _ => Protocol::Other,
        });

    ev.process_name = get_str(rec, "process_name")
        .or_else(|| get_str(rec, "ProcessName"))
        .map(String::from);

    ev.bytes_sent = rec
        .get("bytes_sent")
        .or_else(|| rec.get("BytesSent"))
        .and_then(Value::as_u64);

    ev.bytes_recv = rec
        .get("bytes_recv")
        .or_else(|| rec.get("BytesRecv"))
        .and_then(Value::as_u64);

    ev.direction = Some(Direction::Unknown);

    // Only keep records that have at least one IP address
    if ev.local_addr.is_some() || ev.remote_addr.is_some() {
        Some(ev)
    } else {
        None
    }
}
