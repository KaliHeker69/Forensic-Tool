/// IPsum threat-intelligence feed management.
///
/// Feed: https://github.com/stamparm/ipsum
/// Format: tab-separated  "<ip>\t<score>"  lines; comment lines start with '#'.
/// Higher score = more blacklists containing that IP = higher confidence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local};

pub const IPSUM_URL: &str =
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt";

/// Directory where ipsum.txt is stored (configurable via IOC_DIR env var).
pub fn ioc_dir() -> PathBuf {
    std::env::var("IOC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("ioc"))
}

pub fn ipsum_path() -> PathBuf {
    ioc_dir().join("ipsum.txt")
}

// ── Data ──────────────────────────────────────────────────

/// In-memory representation of the ipsum feed.
#[derive(Debug, Default)]
pub struct IpsumData {
    /// Fast O(1) lookup: raw IP string → score
    pub entries: HashMap<String, u8>,
    /// Pre-sorted (score desc, ip asc) for pagination / top-N display
    pub sorted: Vec<(String, u8)>,
    /// Total number of IP entries
    pub total: usize,
    /// Modification time of the feed file
    pub last_updated: Option<DateTime<Local>>,
    /// Date string from the feed header comment (e.g. "2026-02-21")
    pub source_date: Option<String>,
}

impl IpsumData {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse ipsum.txt from disk.
    pub fn load_from_file(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Could not read ipsum feed");
                return Self::empty();
            }
        };

        // Derive last_updated from file mtime
        let last_updated = path
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.with_timezone(&Local));

        let mut entries = HashMap::new();
        let mut source_date: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                // Extract date from: "# Last update: Sat, 21 Feb 2026 03:01:02 +0100"
                if source_date.is_none() && line.to_lowercase().contains("last update") {
                    source_date = line
                        .splitn(2, ':')
                        .nth(1)
                        .map(|s| s.trim().to_string());
                }
                continue;
            }
            let mut parts = line.splitn(2, '\t');
            if let (Some(ip), Some(score_str)) = (parts.next(), parts.next()) {
                if let Ok(score) = score_str.trim().parse::<u8>() {
                    entries.insert(ip.trim().to_string(), score);
                }
            }
        }

        let mut sorted: Vec<(String, u8)> = entries
            .iter()
            .map(|(ip, &score)| (ip.clone(), score))
            .collect();
        // Sort by score descending, then IP ascending for deterministic order
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        let total = entries.len();
        tracing::info!(
            total,
            last_updated = ?last_updated,
            "Ipsum feed loaded"
        );

        Self {
            entries,
            sorted,
            total,
            last_updated,
            source_date,
        }
    }

    /// Look up a single IP. Returns its score or None if not in feed.
    pub fn lookup(&self, ip: &str) -> Option<u8> {
        self.entries.get(ip.trim()).copied()
    }

    /// Number of IPs with score >= threshold.
    pub fn count_above(&self, min_score: u8) -> usize {
        self.entries.values().filter(|&&s| s >= min_score).count()
    }

    /// Score distribution: (score → count), descending by score.
    pub fn distribution(&self) -> Vec<(u8, usize)> {
        let mut dist: HashMap<u8, usize> = HashMap::new();
        for &score in self.entries.values() {
            *dist.entry(score).or_insert(0) += 1;
        }
        let mut v: Vec<(u8, usize)> = dist.into_iter().collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v
    }
}

// ── Download ──────────────────────────────────────────────

/// Download the latest ipsum.txt to disk.
/// Uses curl (always available on Kali) to avoid adding reqwest dependency.
pub async fn download_ipsum() -> Result<String, String> {
    let path = ipsum_path();
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("Cannot create ioc dir: {e}"))?;

    let path_str = path.to_string_lossy().into_owned();

    let out = tokio::process::Command::new("curl")
        .args([
            "-fsSL",
            "--connect-timeout", "30",
            "--max-time", "120",
            "-o", &path_str,
            IPSUM_URL,
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to run curl: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl failed: {}", err.trim()));
    }

    // Count lines as a sanity check
    let lines = std::fs::read_to_string(&path)
        .map(|c| c.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).count())
        .unwrap_or(0);

    Ok(format!("Downloaded {} IPs to {}", lines, path_str))
}
