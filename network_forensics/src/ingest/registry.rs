/// Registry parser — consumes KAPE RECmd JSON output.
///
/// RECmd exports registry key/value data as JSON objects with fields like
/// "HivePath", "Key", "ValueName", "ValueData", "LastWriteTimestamp", etc.
/// We extract network-relevant entries: TypedURLs, RDP MRU, network profiles,
/// mapped drives, firewall rules, Run keys, BITS registry jobs, WinSock LSP.
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::path::Path;

pub struct RegistryIngestor;

impl ArtifactParser for RegistryIngestor {
    fn name(&self) -> &'static str {
        "Registry JSON Parser (KAPE RECmd)"
    }

    fn parse(&self, path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let files = discover_json_files(path)?;
        log::info!("Found {} registry JSON files", files.len());
        let mut events = Vec::new();

        for file_path in &files {
            log::info!("Parsing registry JSON: {}", file_path.display());
            match parse_registry_json(file_path, rules) {
                Ok(mut evts) => events.append(&mut evts),
                Err(e) => log::warn!("Failed to parse {}: {}", file_path.display(), e),
            }
        }
        log::info!("Extracted {} registry events", events.len());
        Ok(events)
    }
}

fn discover_json_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file()
        && path.extension().map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        files.push(path.to_path_buf());
        return Ok(files);
    }
    if path.is_dir() {
        for pattern in &["{}/**/*reg*.json", "{}/**/*Registry*.json", "{}/**/*RECmd*.json"] {
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

fn parse_registry_json(path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read registry JSON")?;

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
        if let Some(ev) = classify_registry_entry(rec, rules) {
            events.push(ev);
        }
    }
    Ok(events)
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
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
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
}

fn classify_registry_entry(rec: &Value, rules: &RuleSet) -> Option<NetEvent> {
    let key = get_str(rec, "Key")
        .or_else(|| get_str(rec, "KeyPath"))
        .unwrap_or("")
        .to_lowercase();
    let value_name = get_str(rec, "ValueName").unwrap_or("").to_lowercase();
    let value_data = get_str(rec, "ValueData")
        .or_else(|| get_str(rec, "ValueData2"))
        .unwrap_or("");
    let timestamp = get_str(rec, "LastWriteTimestamp")
        .or_else(|| get_str(rec, "Timestamp"))
        .and_then(parse_ts);
    let raw = serde_json::to_string(rec).unwrap_or_default();

    // TypedURLs (IE/Edge)
    if key.contains("typedurls") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.hostname = extract_hostname(value_data);
        ev.direction = Some(Direction::Outbound);
        ev.raw_evidence = format!("TypedURL: {}", value_data);
        return Some(ev);
    }

    // RDP MRU
    if key.contains("terminal server client\\servers") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.hostname = Some(
            key.rsplit('\\')
                .next()
                .unwrap_or(value_data)
                .to_string(),
        );
        ev.direction = Some(Direction::Outbound);
        ev.tags.push(Tag::RdpAccess);
        ev.raw_evidence = format!("RDP MRU: {}", key);
        return Some(ev);
    }

    // Network profiles
    if key.contains("networklist\\profiles") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.raw_evidence = format!("Network Profile: {} = {}", value_name, value_data);
        return Some(ev);
    }

    // Mapped network drives
    if key.contains("network") && value_name.contains("remotepath") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.hostname = extract_unc_host(value_data);
        ev.direction = Some(Direction::Outbound);
        ev.tags.push(Tag::LateralMovement);
        ev.raw_evidence = format!("Mapped drive: {}", value_data);
        return Some(ev);
    }

    // Run / RunOnce keys — flag entries with network references
    if key.contains("\\run") {
        let lc_data = value_data.to_lowercase();
        if lc_data.contains("http")
            || lc_data.contains("ftp")
            || lc_data.contains("\\\\")
            || rules.suspicious_tools.iter().any(|t| lc_data.contains(t.as_str()))
        {
            let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
            ev.timestamp = timestamp;
            ev.process_name = Some(value_name.clone());
            ev.tags.push(Tag::PersistenceMechanism);
            ev.raw_evidence = format!("Run key: {} -> {}", value_name, value_data);
            return Some(ev);
        }
    }

    // Firewall rules in registry
    if key.contains("firewallpolicy") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.tags.push(Tag::PersistenceMechanism);
        ev.raw_evidence = format!("Firewall registry: {} = {}", value_name, value_data);
        return Some(ev);
    }

    // BITS registry jobs
    if key.contains("\\bits") {
        let lc_data = value_data.to_lowercase();
        if lc_data.contains("http") || lc_data.contains("ftp") {
            let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
            ev.timestamp = timestamp;
            ev.hostname = extract_hostname(value_data);
            ev.tags.push(Tag::BitsAbuse);
            ev.tags.push(Tag::C2Indicator);
            ev.raw_evidence = format!("BITS registry: {}", value_data);
            return Some(ev);
        }
    }

    // WinSock LSP
    if key.contains("winsock2") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.raw_evidence = format!("WinSock LSP: {} = {}", value_name, value_data);
        return Some(ev);
    }

    // DNS server config in SYSTEM hive
    if key.contains("tcpip\\parameters") && value_name.contains("nameserver") {
        let mut ev = NetEvent::new(ArtifactSource::Registry, raw);
        ev.timestamp = timestamp;
        ev.remote_addr = value_data.parse().ok();
        ev.raw_evidence = format!("DNS config: {} = {}", value_name, value_data);
        return Some(ev);
    }

    None
}

fn extract_hostname(url_or_path: &str) -> Option<String> {
    if let Some(idx) = url_or_path.find("://") {
        let after = &url_or_path[idx + 3..];
        let host = after.split('/').next()?.split(':').next()?;
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }
    None
}

fn extract_unc_host(unc_path: &str) -> Option<String> {
    let path = unc_path.trim_start_matches('\\');
    let host = path.split('\\').next()?;
    if !host.is_empty() {
        Some(host.to_string())
    } else {
        None
    }
}
