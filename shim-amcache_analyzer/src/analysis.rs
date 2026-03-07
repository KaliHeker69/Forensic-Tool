//! Analysis engine for correlating ShimCache and AmCache entries

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use chrono::{NaiveDateTime, Utc};
use clap::ValueEnum;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use crate::parsers::{AmCacheEntry, ShimCacheEntry};
use crate::rules::CompiledRules;

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Clean => write!(f, "clean"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Correlated entry combining ShimCache and AmCache data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEntry {
    pub path: String,
    pub normalized_path: String,
    pub in_shimcache: bool,
    pub in_amcache: bool,
    pub risk_level: RiskLevel,
    pub risk_indicators: Vec<String>,
    
    // ShimCache data
    pub shim_modified_time: Option<String>,
    pub shim_cache_position: Option<i64>,
    pub shim_executed: Option<bool>,
    
    // AmCache data
    pub sha1: Option<String>,
    pub file_size: Option<i64>,
    pub first_run_time: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub file_version: Option<String>,
    pub file_description: Option<String>,
    pub binary_type: Option<String>,
    pub link_date: Option<String>,
    pub is_os_component: Option<bool>,
    
    // Derived
    pub filename: String,
    pub extension: String,
    
    // VirusTotal result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vt_result: Option<VtResult>,
}

/// VirusTotal lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtResult {
    pub found: bool,
    pub malicious: i32,
    pub suspicious: i32,
    pub undetected: i32,
    pub names: Vec<String>,
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub path: String,
    pub source: String,
    pub sha1: Option<String>,
    pub details: Option<String>,
}

/// Hash analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashAnalysis {
    pub unique_hashes: HashSet<String>,
    pub hash_to_paths: HashMap<String, Vec<String>>,
    pub known_bad: Vec<String>,
    pub known_good: Vec<String>,
    pub unknown: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub vt_results: HashMap<String, VtResult>,
}

/// Statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statistics {
    pub total_shimcache: usize,
    pub total_amcache: usize,
    pub total_correlated: usize,
    pub entries_in_both: usize,
    pub shimcache_only: usize,
    pub amcache_only: usize,
    pub executed_count: usize,
    pub with_hash: usize,
    pub with_company: usize,
    pub risk_distribution: HashMap<String, usize>,
    pub top_extensions: Vec<(String, usize)>,
    pub top_directories: Vec<(String, usize)>,
}

/// Complete analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub analysis_time: String,
    pub statistics: Statistics,
    pub correlated_entries: Vec<CorrelatedEntry>,
    pub suspicious_entries: Vec<CorrelatedEntry>,
    pub timeline: Vec<TimelineEvent>,
    pub hash_analysis: HashAnalysis,
}

/// Main correlation analyzer
pub struct CorrelationAnalyzer {
    shimcache_entries: Vec<ShimCacheEntry>,
    amcache_entries: Vec<AmCacheEntry>,
    known_good: HashSet<String>,
    known_bad: HashSet<String>,
    rules: CompiledRules,
}

impl CorrelationAnalyzer {
    pub fn new(known_good: HashSet<String>, known_bad: HashSet<String>, rules: CompiledRules) -> Self {
        Self {
            shimcache_entries: Vec::new(),
            amcache_entries: Vec::new(),
            known_good,
            known_bad,
            rules,
        }
    }

    pub fn add_shimcache_entries(&mut self, entries: Vec<ShimCacheEntry>) {
        self.shimcache_entries.extend(entries);
    }

    pub fn add_amcache_entries(&mut self, entries: Vec<AmCacheEntry>) {
        self.amcache_entries.extend(entries);
    }

    /// Normalize path for comparison
    fn normalize_path(path: &str) -> String {
        let mut normalized = path.to_lowercase().replace('/', "\\");
        
        // Remove drive letter
        if normalized.len() >= 2 && normalized.chars().nth(1) == Some(':') {
            normalized = normalized[2..].to_string();
        }
        
        // Trim slashes
        normalized.trim_matches('\\').to_string()
    }

    /// Correlate entries from both sources
    fn correlate(&self) -> HashMap<String, CorrelatedEntry> {
        let mut correlated: HashMap<String, CorrelatedEntry> = HashMap::new();

        // Index ShimCache entries
        for entry in &self.shimcache_entries {
            let norm_path = Self::normalize_path(&entry.path);
            
            let corr = correlated.entry(norm_path.clone()).or_insert_with(|| {
                CorrelatedEntry {
                    path: entry.path.clone(),
                    normalized_path: norm_path.clone(),
                    in_shimcache: false,
                    in_amcache: false,
                    risk_level: RiskLevel::Clean,
                    risk_indicators: Vec::new(),
                    shim_modified_time: None,
                    shim_cache_position: None,
                    shim_executed: None,
                    sha1: None,
                    file_size: None,
                    first_run_time: None,
                    product_name: None,
                    company_name: None,
                    file_version: None,
                    file_description: None,
                    binary_type: None,
                    link_date: None,
                    is_os_component: None,
                    filename: entry.filename.clone(),
                    extension: entry.extension.clone(),
                    vt_result: None,
                }
            });

            corr.in_shimcache = true;
            corr.shim_modified_time = entry.modified_time.clone();
            corr.shim_cache_position = entry.cache_position;
            corr.shim_executed = entry.executed;
            
            if entry.file_size.is_some() && corr.file_size.is_none() {
                corr.file_size = entry.file_size;
            }
        }

        // Index AmCache entries
        for entry in &self.amcache_entries {
            let norm_path = Self::normalize_path(&entry.path);
            
            let corr = correlated.entry(norm_path.clone()).or_insert_with(|| {
                CorrelatedEntry {
                    path: entry.path.clone(),
                    normalized_path: norm_path.clone(),
                    in_shimcache: false,
                    in_amcache: false,
                    risk_level: RiskLevel::Clean,
                    risk_indicators: Vec::new(),
                    shim_modified_time: None,
                    shim_cache_position: None,
                    shim_executed: None,
                    sha1: None,
                    file_size: None,
                    first_run_time: None,
                    product_name: None,
                    company_name: None,
                    file_version: None,
                    file_description: None,
                    binary_type: None,
                    link_date: None,
                    is_os_component: None,
                    filename: entry.filename.clone(),
                    extension: entry.extension.clone(),
                    vt_result: None,
                }
            });

            corr.in_amcache = true;
            
            // Prefer AmCache data
            if entry.sha1.is_some() {
                corr.sha1 = entry.sha1.clone();
            }
            if entry.file_size.is_some() {
                corr.file_size = entry.file_size;
            }
            if entry.first_run_time.is_some() {
                corr.first_run_time = entry.first_run_time.clone();
            }
            if entry.product_name.is_some() {
                corr.product_name = entry.product_name.clone();
            }
            if entry.company_name.is_some() {
                corr.company_name = entry.company_name.clone();
            }
            if entry.file_version.is_some() {
                corr.file_version = entry.file_version.clone();
            }
            if entry.file_description.is_some() {
                corr.file_description = entry.file_description.clone();
            }
            if entry.binary_type.is_some() {
                corr.binary_type = entry.binary_type.clone();
            }
            if entry.link_date.is_some() {
                corr.link_date = entry.link_date.clone();
            }
            if entry.is_os_component.is_some() {
                corr.is_os_component = entry.is_os_component;
            }
            
            // Update filename if empty
            if corr.filename.is_empty() {
                corr.filename = entry.filename.clone();
                corr.extension = entry.extension.clone();
            }
        }

        correlated
    }

    /// Analyze risk indicators for an entry
    fn analyze_entry_risk(&self, entry: &mut CorrelatedEntry) {
        let path_lower = entry.path.to_lowercase();
        let mut indicators = Vec::new();
        let mut risk_level = RiskLevel::Clean;

        // Check if in trusted path
        let is_trusted_path = self.rules.is_trusted_path(&entry.path);

        // Check if trusted publisher
        let is_trusted_publisher = self.rules.is_trusted_publisher(
            entry.company_name.as_deref(),
            entry.product_name.as_deref(),
        );

        // Check suspicious paths (only if not in trusted path)
        if !is_trusted_path {
            if let Some(desc) = self.rules.check_suspicious_path(&entry.path) {
                indicators.push(format!("Suspicious path: {}", desc));
                if risk_level < RiskLevel::Medium {
                    risk_level = RiskLevel::Medium;
                }
            }
        }

        // Check suspicious filenames
        if let Some(desc) = self.rules.check_suspicious_filename(&entry.filename) {
            indicators.push(format!("Suspicious filename: {}", desc));
            if risk_level < RiskLevel::High {
                risk_level = RiskLevel::High;
            }
        }

        // Check system executable mimicry (HIGH priority - real threat)
        let is_valid_system_executable =
            matches!(self.rules.check_system_executable(&entry.filename, &entry.path), Some(true));

        if let Some(in_valid) = self.rules.check_system_executable(&entry.filename, &entry.path) {
            if !in_valid {
                indicators.push(format!(
                    "CRITICAL: System executable '{}' in unexpected location!",
                    entry.filename
                ));
                risk_level = RiskLevel::Critical;
            }
        }

        // Check for executables in risky temp locations (only for non-trusted publishers)
        // Exception: legitimate Windows temp executables (DISM, Windows Defender, VC redist, etc.)
        let is_legitimate_temp_executable = self.rules.is_legitimate_temp_executable(&entry.path);

        if !is_trusted_publisher && !is_trusted_path {
            if self.rules.is_risky_temp_path(&entry.path) && !is_legitimate_temp_executable {
                if self.rules.is_executable_extension(&entry.extension) {
                    indicators.push("Executable in risky temporary location".to_string());
                    if risk_level < RiskLevel::Medium {
                        risk_level = RiskLevel::Medium;
                    }
                }
            }
        }

        // Check for entries only in ShimCache (but not if in trusted path)
        if entry.in_shimcache
            && !entry.in_amcache
            && !is_trusted_path
            && !is_trusted_publisher
            && !is_legitimate_temp_executable
            && !is_valid_system_executable
        {
            indicators.push("Entry only in ShimCache (file may be deleted or portable)".to_string());
            if risk_level < RiskLevel::Low {
                risk_level = RiskLevel::Low;
            }
        }

        // Check for unknown publisher in non-trusted locations
        // Exception: legitimate Windows temp executables (DISM, Windows Defender, VC redist, etc.)
        if !is_trusted_path && !is_trusted_publisher && !is_legitimate_temp_executable {
            if entry.company_name.is_none() && entry.product_name.is_none() {
                if entry.extension == ".exe" {
                    // Only flag if also has other suspicious indicators or is in user space
                    if path_lower.contains("\\users\\") || path_lower.contains("\\temp\\") {
                        indicators.push("Unknown publisher for executable in user space".to_string());
                        if risk_level < RiskLevel::Low {
                            risk_level = RiskLevel::Low;
                        }
                    }
                }
            }
        }

        // Check known bad hashes (always critical)
        if let Some(ref sha1) = entry.sha1 {
            if self.known_bad.contains(sha1) {
                indicators.push("SHA1 matches known malicious hash!".to_string());
                risk_level = RiskLevel::Critical;
            }
        }

        // Check for recently compiled executables
        if let (Some(ref link_date), Some(ref first_run)) = (&entry.link_date, &entry.first_run_time) {
            if let (Some(link_dt), Some(run_dt)) = (
                Self::parse_timestamp(link_date),
                Self::parse_timestamp(first_run),
            ) {
                let delta = run_dt.signed_duration_since(link_dt);
                // Only flag if < 1 hour and NOT a trusted path/publisher
                if delta.num_hours() < 1 && delta.num_hours() >= 0 && !is_trusted_path && !is_trusted_publisher {
                    indicators.push("Recently compiled executable (< 1 hour before execution)".to_string());
                    if risk_level < RiskLevel::High {
                        risk_level = RiskLevel::High;
                    }
                }
            }
        }

        // Executables in Downloads folder (always worth noting)
        if path_lower.contains("\\downloads\\")
            && entry.extension == ".exe"
            && !self.rules.is_legitimate_download_executable(&entry.path)
        {
            indicators.push("Executable found in Downloads folder".to_string());
            if risk_level < RiskLevel::Low {
                risk_level = RiskLevel::Low;
            }
        }

        entry.risk_indicators = indicators;
        entry.risk_level = risk_level;
    }

    fn parse_timestamp(ts: &str) -> Option<NaiveDateTime> {
        // Try common formats
        let formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
        ];

        for fmt in &formats {
            if let Ok(dt) = NaiveDateTime::parse_from_str(ts, fmt) {
                return Some(dt);
            }
        }
        None
    }

    /// Build timeline from all entries
    fn build_timeline(&self, correlated: &HashMap<String, CorrelatedEntry>) -> Vec<TimelineEvent> {
        let mut events = Vec::new();

        for entry in correlated.values() {
            // Add first run time events
            if let Some(ref ts) = entry.first_run_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "first_execution".to_string(),
                    path: entry.path.clone(),
                    source: "amcache".to_string(),
                    sha1: entry.sha1.clone(),
                    details: entry.product_name.clone(),
                });
            }

            // Add ShimCache modification time events
            if let Some(ref ts) = entry.shim_modified_time {
                events.push(TimelineEvent {
                    timestamp: ts.clone(),
                    event_type: "file_modified".to_string(),
                    path: entry.path.clone(),
                    source: "shimcache".to_string(),
                    sha1: entry.sha1.clone(),
                    details: entry.shim_cache_position.map(|p| format!("Position: {}", p)),
                });
            }
        }

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        events
    }

    /// Analyze hashes
    fn analyze_hashes(&self, correlated: &HashMap<String, CorrelatedEntry>) -> HashAnalysis {
        let mut unique_hashes = HashSet::new();
        let mut hash_to_paths: HashMap<String, Vec<String>> = HashMap::new();

        for entry in correlated.values() {
            if let Some(ref sha1) = entry.sha1 {
                unique_hashes.insert(sha1.clone());
                hash_to_paths
                    .entry(sha1.clone())
                    .or_default()
                    .push(entry.path.clone());
            }
        }

        let mut known_bad = Vec::new();
        let mut known_good = Vec::new();
        let mut unknown = Vec::new();

        for hash in &unique_hashes {
            if self.known_bad.contains(hash) {
                known_bad.push(hash.clone());
            } else if self.known_good.contains(hash) {
                known_good.push(hash.clone());
            } else {
                unknown.push(hash.clone());
            }
        }

        HashAnalysis {
            unique_hashes,
            hash_to_paths,
            known_bad,
            known_good,
            unknown,
            vt_results: HashMap::new(),
        }
    }

    /// Generate statistics
    fn generate_statistics(
        &self,
        correlated: &HashMap<String, CorrelatedEntry>,
    ) -> Statistics {
        let mut risk_distribution: HashMap<String, usize> = HashMap::new();
        let mut extension_counts: HashMap<String, usize> = HashMap::new();
        let mut directory_counts: HashMap<String, usize> = HashMap::new();
        
        let mut entries_in_both = 0;
        let mut shimcache_only = 0;
        let mut amcache_only = 0;
        let mut executed_count = 0;
        let mut with_hash = 0;
        let mut with_company = 0;

        for entry in correlated.values() {
            // Count risk levels
            *risk_distribution.entry(entry.risk_level.to_string()).or_default() += 1;

            // Count extensions
            let ext = if entry.extension.is_empty() {
                "no_extension".to_string()
            } else {
                entry.extension.clone()
            };
            *extension_counts.entry(ext).or_default() += 1;

            // Count directories
            let dir = entry.normalized_path.rsplitn(2, '\\').nth(1).unwrap_or("root");
            *directory_counts.entry(dir.to_string()).or_default() += 1;

            // Count overlap
            if entry.in_shimcache && entry.in_amcache {
                entries_in_both += 1;
            } else if entry.in_shimcache {
                shimcache_only += 1;
            } else {
                amcache_only += 1;
            }

            // Count executed
            if entry.shim_executed == Some(true) {
                executed_count += 1;
            }

            // Count with hash
            if entry.sha1.is_some() {
                with_hash += 1;
            }

            // Count with company
            if entry.company_name.is_some() {
                with_company += 1;
            }
        }

        // Sort and take top 20
        let mut ext_vec: Vec<_> = extension_counts.into_iter().collect();
        ext_vec.sort_by(|a, b| b.1.cmp(&a.1));
        ext_vec.truncate(20);

        let mut dir_vec: Vec<_> = directory_counts.into_iter().collect();
        dir_vec.sort_by(|a, b| b.1.cmp(&a.1));
        dir_vec.truncate(20);

        Statistics {
            total_shimcache: self.shimcache_entries.len(),
            total_amcache: self.amcache_entries.len(),
            total_correlated: correlated.len(),
            entries_in_both,
            shimcache_only,
            amcache_only,
            executed_count,
            with_hash,
            with_company,
            risk_distribution,
            top_extensions: ext_vec,
            top_directories: dir_vec,
        }
    }

    /// Check hash against VirusTotal
    #[cfg(feature = "virustotal")]
    fn check_virustotal(sha1: &str, api_key: &str) -> Option<VtResult> {
        use reqwest::blocking::Client;

        let client = Client::new();
        let url = format!("https://www.virustotal.com/api/v3/files/{}", sha1);

        match client
            .get(&url)
            .header("x-apikey", api_key)
            .timeout(std::time::Duration::from_secs(30))
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>() {
                        let stats = json["data"]["attributes"]["last_analysis_stats"].clone();
                        let names = json["data"]["attributes"]["names"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .take(5)
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        return Some(VtResult {
                            found: true,
                            malicious: stats["malicious"].as_i64().unwrap_or(0) as i32,
                            suspicious: stats["suspicious"].as_i64().unwrap_or(0) as i32,
                            undetected: stats["undetected"].as_i64().unwrap_or(0) as i32,
                            names,
                        });
                    }
                } else if response.status().as_u16() == 404 {
                    return Some(VtResult {
                        found: false,
                        malicious: 0,
                        suspicious: 0,
                        undetected: 0,
                        names: Vec::new(),
                    });
                }
                None
            }
            Err(_) => None,
        }
    }

    /// Generate complete analysis report
    pub fn generate_report(
        &mut self,
        _check_vt: bool,
        _vt_api_key: Option<&str>,
    ) -> Result<AnalysisReport> {
        // Correlate entries
        let mut correlated = self.correlate();

        // Analyze risks for each entry (parallel)
        let entries: Vec<_> = correlated.values().cloned().collect();
        let analyzed: Vec<_> = entries
            .into_par_iter()
            .map(|mut entry| {
                self.analyze_entry_risk(&mut entry);
                entry
            })
            .collect();

        // Update correlated with analyzed entries
        for entry in analyzed {
            correlated.insert(entry.normalized_path.clone(), entry);
        }

        // Build hash analysis
        let hash_analysis = self.analyze_hashes(&correlated);

        // Check VirusTotal if enabled
        #[cfg(feature = "virustotal")]
        if check_vt {
            if let Some(api_key) = vt_api_key {
                // Only check unknown hashes, limit to avoid rate limiting
                let hashes_to_check: Vec<_> = hash_analysis.unknown.iter().take(20).cloned().collect();
                
                for sha1 in hashes_to_check {
                    if let Some(vt_result) = Self::check_virustotal(&sha1, api_key) {
                        if vt_result.malicious > 0 {
                            // Update entries with this hash
                            for entry in correlated.values_mut() {
                                if entry.sha1.as_ref() == Some(&sha1) {
                                    entry.vt_result = Some(vt_result.clone());
                                    entry.risk_level = RiskLevel::Critical;
                                    entry.risk_indicators.push(format!(
                                        "VirusTotal: {} malicious detections",
                                        vt_result.malicious
                                    ));
                                }
                            }
                        }
                        hash_analysis.vt_results.insert(sha1, vt_result);
                    }
                    // Rate limiting
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        }

        // Build timeline
        let timeline = self.build_timeline(&correlated);

        // Generate statistics
        let statistics = self.generate_statistics(&correlated);

        // Collect entries
        let mut all_entries: Vec<_> = correlated.into_values().collect();
        all_entries.sort_by(|a, b| a.path.cmp(&b.path));

        // Filter suspicious
        let suspicious: Vec<_> = all_entries
            .iter()
            .filter(|e| e.risk_level != RiskLevel::Clean)
            .cloned()
            .collect();

        Ok(AnalysisReport {
            analysis_time: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            statistics,
            correlated_entries: all_entries,
            suspicious_entries: suspicious,
            timeline,
            hash_analysis,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            CorrelationAnalyzer::normalize_path(r"C:\Windows\System32\cmd.exe"),
            "windows\\system32\\cmd.exe"
        );
        assert_eq!(
            CorrelationAnalyzer::normalize_path(r"c:/windows/system32/cmd.exe"),
            "windows\\system32\\cmd.exe"
        );
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Clean);
    }
}
