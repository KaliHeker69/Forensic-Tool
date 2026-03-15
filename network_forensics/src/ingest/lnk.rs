/// LNK file parser — consumes KAPE LECmd JSON output.
///
/// LECmd exports .lnk shortcut file metadata as JSON. We extract network share
/// paths (UNC targets) from recently accessed LNK files and JumpList entries.
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::path::Path;

pub struct LnkIngestor;

impl ArtifactParser for LnkIngestor {
    fn name(&self) -> &'static str {
        "LNK / JumpList JSON Parser (KAPE LECmd)"
    }

    fn parse(&self, path: &Path, _rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let files = discover_lnk_json_files(path)?;
        log::info!("Found {} LNK JSON files", files.len());
        let mut events = Vec::new();

        for fp in &files {
            log::info!("Parsing LNK JSON: {}", fp.display());
            match parse_lnk_json(fp) {
                Ok(mut evts) => events.append(&mut evts),
                Err(e) => log::warn!("Failed to parse {}: {}", fp.display(), e),
            }
        }
        log::info!("Extracted {} LNK events", events.len());
        Ok(events)
    }
}

fn discover_lnk_json_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file()
        && path.extension().map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        files.push(path.to_path_buf());
        return Ok(files);
    }
    if path.is_dir() {
        for pat in &[
            "{}/**/*lnk*.json",
            "{}/**/*LECmd*.json",
            "{}/**/*JumpList*.json",
            "{}/**/*AutomaticDestinations*.json",
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

fn parse_lnk_json(path: &Path) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read LNK JSON")?;

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
        if let Some(ev) = normalize_lnk_record(rec) {
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

fn normalize_lnk_record(rec: &Value) -> Option<NetEvent> {
    // LECmd JSON fields: TargetPath / LocalPath / NetworkPath / Arguments
    let target = get_str(rec, "TargetPath")
        .or_else(|| get_str(rec, "LocalPath"))
        .unwrap_or("");
    let network_path = get_str(rec, "NetworkPath").unwrap_or("");
    let arguments = get_str(rec, "Arguments").unwrap_or("");

    // We only care about entries referencing network shares or URLs
    let has_unc = target.contains("\\\\") || network_path.contains("\\\\");
    let has_url = target.contains("://")
        || arguments.to_lowercase().contains("http")
        || arguments.to_lowercase().contains("ftp");

    if !has_unc && !has_url {
        return None;
    }

    let raw = serde_json::to_string(rec).unwrap_or_default();
    let mut ev = NetEvent::new(ArtifactSource::LnkFile, raw);

    ev.timestamp = get_str(rec, "SourceAccessed")
        .or_else(|| get_str(rec, "TargetAccessed"))
        .or_else(|| get_str(rec, "SourceCreated"))
        .and_then(parse_ts);

    if has_unc {
        let unc = if !network_path.is_empty() {
            network_path
        } else {
            target
        };
        ev.hostname = extract_unc_host(unc);
        ev.tags.push(Tag::LateralMovement);
        ev.raw_evidence = format!("LNK UNC: {}", unc);
    } else {
        ev.hostname = extract_url_hostname(target).or_else(|| extract_url_hostname(arguments));
        ev.raw_evidence = format!("LNK URL: {} args={}", target, arguments);
    }
    ev.direction = Some(Direction::Outbound);

    Some(ev)
}

fn extract_unc_host(unc: &str) -> Option<String> {
    let trimmed = unc.trim_start_matches('\\');
    let host = trimmed.split('\\').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn extract_url_hostname(s: &str) -> Option<String> {
    let idx = s.find("://")?;
    let after = &s[idx + 3..];
    let host = after.split('/').next()?.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
