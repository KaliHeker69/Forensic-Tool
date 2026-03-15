use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::Path;

pub struct PrefetchIngestor;

impl ArtifactParser for PrefetchIngestor {
    fn name(&self) -> &'static str {
        "Prefetch JSON Parser"
    }

    fn parse(&self, path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let files = discover_json_files(path, "prefetch")?;
        let mut events = Vec::new();

        for file_path in &files {
            log::info!("Parsing prefetch JSON: {}", file_path.display());
            match parse_prefetch_json(file_path, rules) {
                Ok(mut evts) => events.append(&mut evts),
                Err(e) => log::warn!("Failed to parse {}: {}", file_path.display(), e),
            }
        }

        log::info!("Extracted {} prefetch events", events.len());
        Ok(events)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PrefetchEntry {
    #[serde(alias = "executable_name", alias = "ExecutableName", alias = "SourceFilename")]
    executable_name: Option<String>,
    #[serde(alias = "run_count", alias = "RunCount")]
    run_count: Option<u32>,
    #[serde(alias = "last_run", alias = "LastRun", alias = "SourceCreated")]
    last_run: Option<String>,
    #[serde(alias = "previous_runs", alias = "PreviousRuns")]
    previous_runs: Option<Vec<String>>,
    #[serde(alias = "files_loaded", alias = "FilesLoaded")]
    files_loaded: Option<Vec<String>>,
    #[serde(alias = "source_file", alias = "SourceFile")]
    source_file: Option<String>,
}

fn discover_json_files(path: &Path, hint: &str) -> Result<Vec<std::path::PathBuf>> {
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
        let pattern = format!("{}/**/*{}*.json", path.display(), hint);
        for entry in glob::glob(&pattern).context("Invalid glob")? {
            if let Ok(p) = entry {
                files.push(p);
            }
        }
        // Also try generic JSON files if no hint-specific files found
        if files.is_empty() {
            let pattern = format!("{}/**/*.json", path.display());
            for entry in glob::glob(&pattern).context("Invalid glob")? {
                if let Ok(p) = entry {
                    let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                    if name.contains(hint) {
                        files.push(p);
                    }
                }
            }
        }
    }
    Ok(files)
}

fn parse_prefetch_json(path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read prefetch JSON")?;
    let mut events = Vec::new();

    // Try parsing as array first, then as single object
    let entries: Vec<PrefetchEntry> = serde_json::from_str::<Vec<PrefetchEntry>>(&data)
        .or_else(|_| {
            serde_json::from_str::<PrefetchEntry>(&data).map(|e| vec![e])
        })
        .context("Failed to parse prefetch JSON")?;

    for entry in entries {
        let exe_name = entry
            .executable_name
            .as_deref()
            .unwrap_or("unknown")
            .to_lowercase();

        // Only flag network-relevant tools
        let is_suspicious = rules.is_suspicious_tool(&exe_name);

        let mut ev = NetEvent::new(
            ArtifactSource::Prefetch,
            format!(
                "Prefetch: {} runs={}",
                exe_name,
                entry.run_count.unwrap_or(0)
            ),
        );
        ev.process_name = Some(exe_name.clone());
        ev.timestamp = entry.last_run.as_deref().and_then(parse_flexible_timestamp);

        if is_suspicious {
            ev.tags.push(Tag::NetworkToolExecution);
            ev.tags.push(Tag::SuspiciousProcess);
        }

        ev.raw_evidence = format!(
            "Executable: {} RunCount: {} Source: {}",
            entry.executable_name.as_deref().unwrap_or("?"),
            entry.run_count.unwrap_or(0),
            entry.source_file.as_deref().unwrap_or("?"),
        );

        events.push(ev);
    }

    Ok(events)
}

fn parse_flexible_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
}
