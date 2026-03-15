/// Filesystem parser — consumes KAPE MFTECmd JSON output.
///
/// MFTECmd exports $MFT and USN Journal entries as JSON. We flag entries
/// related to network tools, staging directories, and suspicious file drops.
/// Also handles hosts file changes, scheduled task XMLs, PowerShell history,
/// and Amcache entries when provided as JSON.
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::path::Path;

pub struct FilesystemIngestor;

impl ArtifactParser for FilesystemIngestor {
    fn name(&self) -> &'static str {
        "Filesystem JSON Parser (KAPE MFTECmd / Amcache / hosts / PS history)"
    }

    fn parse(&self, path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let files = discover_fs_json_files(path)?;
        log::info!("Found {} filesystem JSON files", files.len());
        let mut events = Vec::new();

        for fp in &files {
            log::info!("Parsing filesystem JSON: {}", fp.display());
            match parse_fs_json(fp, rules) {
                Ok(mut evts) => events.append(&mut evts),
                Err(e) => log::warn!("Failed to parse {}: {}", fp.display(), e),
            }
        }

        // Also look for hosts file (plain text)
        if let Ok(hosts_events) = parse_hosts_file(path) {
            events.extend(hosts_events);
        }

        // Also look for PowerShell ConsoleHost_history.txt
        if let Ok(ps_events) = parse_powershell_history(path, rules) {
            events.extend(ps_events);
        }

        log::info!("Extracted {} filesystem events", events.len());
        Ok(events)
    }
}

fn discover_fs_json_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file()
        && path.extension().map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        files.push(path.to_path_buf());
        return Ok(files);
    }
    if path.is_dir() {
        for pat in &[
            "{}/**/*MFT*.json",
            "{}/**/*USN*.json",
            "{}/**/*Amcache*.json",
            "{}/**/*amcache*.json",
            "{}/**/*ScheduledTask*.json",
            "{}/**/*scheduledtask*.json",
        ] {
            let glob_pat = pat.replace("{}", &path.display().to_string());
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

fn parse_fs_json(path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read filesystem JSON")?;
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

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
        if filename.contains("amcache") {
            if let Some(ev) = parse_amcache_entry(rec, rules) {
                events.push(ev);
            }
        } else if filename.contains("scheduledtask") {
            if let Some(ev) = parse_scheduled_task_entry(rec, rules) {
                events.push(ev);
            }
        } else {
            // MFT / USN entries
            if let Some(ev) = parse_mft_entry(rec, rules) {
                events.push(ev);
            }
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

/// MFT / USN Journal — flag network tool file drops
fn parse_mft_entry(rec: &Value, rules: &RuleSet) -> Option<NetEvent> {
    let filename = get_str(rec, "FileName")
        .or_else(|| get_str(rec, "Name"))
        .unwrap_or("");
    let parent_path = get_str(rec, "ParentPath")
        .or_else(|| get_str(rec, "FullPath"))
        .unwrap_or("");
    let lc_name = filename.to_lowercase();

    // Only flag network-relevant file events
    let is_tool = rules.suspicious_tools
        .iter()
        .any(|t| lc_name.contains(&t.replace(".exe", "")));
    let is_staging = parent_path.to_lowercase().contains("temp")
        || parent_path.to_lowercase().contains("staging")
        || parent_path.to_lowercase().contains("download");

    if !is_tool && !is_staging {
        return None;
    }

    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::Mft, raw);
    ev.timestamp = get_str(rec, "Created0x10")
        .or_else(|| get_str(rec, "LastModified0x10"))
        .or_else(|| get_str(rec, "Timestamp"))
        .and_then(parse_ts);
    ev.process_name = Some(lc_name.clone());

    if is_tool {
        ev.tags.push(Tag::NetworkToolExecution);
    }
    ev.raw_evidence = format!("MFT: {}\\{}", parent_path, filename);
    Some(ev)
}

/// Amcache — execution evidence for network tools with hashes
fn parse_amcache_entry(rec: &Value, rules: &RuleSet) -> Option<NetEvent> {
    let filename = get_str(rec, "FileName")
        .or_else(|| get_str(rec, "ProgramName"))
        .or_else(|| get_str(rec, "Name"))
        .unwrap_or("");
    let lc = filename.to_lowercase();

    let is_tool = rules.suspicious_tools.iter().any(|t| lc.contains(t.as_str()));
    if !is_tool {
        return None;
    }

    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::Prefetch, raw); // logically same as exec evidence
    ev.timestamp = get_str(rec, "FileKeyLastWriteTimestamp")
        .or_else(|| get_str(rec, "Timestamp"))
        .and_then(parse_ts);
    ev.process_name = Some(lc);
    ev.tags.push(Tag::NetworkToolExecution);
    ev.raw_evidence = format!(
        "Amcache: {} SHA1={}",
        filename,
        get_str(rec, "SHA1").unwrap_or("?")
    );
    Some(ev)
}

/// Scheduled Task XML entries parsed to JSON — flag network-fetching tasks
fn parse_scheduled_task_entry(rec: &Value, rules: &RuleSet) -> Option<NetEvent> {
    let task_name = get_str(rec, "TaskName")
        .or_else(|| get_str(rec, "Name"))
        .unwrap_or("");
    let action = get_str(rec, "ActionCommand")
        .or_else(|| get_str(rec, "Command"))
        .or_else(|| get_str(rec, "Actions"))
        .unwrap_or("");
    let arguments = get_str(rec, "ActionArguments")
        .or_else(|| get_str(rec, "Arguments"))
        .unwrap_or("");

    let combined = format!("{} {} {}", task_name, action, arguments).to_lowercase();
    if !combined.contains("http")
        && !combined.contains("ftp")
        && !combined.contains("\\\\")
        && !rules.suspicious_tools
            .iter()
            .any(|t| combined.contains(&t.replace(".exe", "")))
    {
        return None;
    }

    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::ScheduledTask, raw);
    ev.timestamp = get_str(rec, "Date")
        .or_else(|| get_str(rec, "RegistrationDate"))
        .and_then(parse_ts);
    ev.tags.push(Tag::PersistenceMechanism);
    ev.raw_evidence = format!(
        "Scheduled Task: {} Cmd: {} Args: {}",
        task_name, action, arguments
    );
    Some(ev)
}

/// Parse the hosts file for DNS overrides (plain text)
fn parse_hosts_file(path: &Path) -> Result<Vec<NetEvent>> {
    let mut events = Vec::new();
    let candidates = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        let mut v = Vec::new();
        for entry in
            glob::glob(&format!("{}/**/hosts", path.display())).context("Invalid glob")?
        {
            if let Ok(p) = entry {
                v.push(p);
            }
        }
        v
    };

    for hosts_path in candidates {
        if let Ok(content) = std::fs::read_to_string(&hosts_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // Non-comment, non-empty line is a hosts entry
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[0];
                    let host = parts[1];
                    // Skip standard loopback entries
                    if host == "localhost" && (ip == "127.0.0.1" || ip == "::1") {
                        continue;
                    }
                    let mut ev =
                        NetEvent::new(ArtifactSource::HostsFile, trimmed.to_string());
                    ev.remote_addr = ip.parse().ok();
                    ev.hostname = Some(host.to_string());
                    ev.raw_evidence = format!("hosts: {} -> {}", ip, host);
                    events.push(ev);
                }
            }
        }
    }
    Ok(events)
}

/// Parse PowerShell ConsoleHost_history.txt for network commands
fn parse_powershell_history(path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
    let mut events = Vec::new();

    let candidates = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        let mut v = Vec::new();
        for entry in glob::glob(&format!(
            "{}/**/ConsoleHost_history.txt",
            path.display()
        ))
        .context("Invalid glob")?
        {
            if let Ok(p) = entry {
                v.push(p);
            }
        }
        v
    };

    for ps_path in candidates {
        if let Ok(content) = std::fs::read_to_string(&ps_path) {
            for line in content.lines() {
                if rules.matches_network_keyword(line) {
                    let mut ev = NetEvent::new(
                        ArtifactSource::PowerShellHistory,
                        line.to_string(),
                    );
                    ev.process_name = Some("powershell.exe".to_string());
                    ev.direction = Some(Direction::Outbound);
                    ev.tags.push(Tag::C2Indicator);
                    ev.raw_evidence = format!("PS History: {}", line.trim());
                    events.push(ev);
                }
            }
        }
    }
    Ok(events)
}
