//! Threat Intelligence module for external API lookups
//!
//! Supports:
//! - AbuseIPDB: IP reputation checking
//! - VirusTotal: IP/URL/Hash analysis
//! - urlscan.io: URL and domain scanning
//!
//! API keys are loaded from environment variables or config file.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Threat intelligence lookup result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelResult {
    /// IP address or URL that was checked
    pub indicator: String,
    /// AbuseIPDB confidence score (0-100)
    pub abuseipdb_score: Option<u32>,
    /// AbuseIPDB country code
    pub abuseipdb_country: Option<String>,
    /// AbuseIPDB ISP
    pub abuseipdb_isp: Option<String>,
    /// AbuseIPDB total reports
    pub abuseipdb_reports: Option<u32>,
    /// VirusTotal detection ratio (e.g., "5/70")
    pub virustotal_detections: Option<String>,
    /// VirusTotal last analysis date
    pub virustotal_scan_date: Option<String>,
    /// urlscan.io verdict
    pub urlscan_verdict: Option<String>,
    /// urlscan.io malicious score (0-100)
    pub urlscan_score: Option<u32>,
    /// urlscan.io scan URL (link to results)
    pub urlscan_result_url: Option<String>,
    /// Whether the IP/URL is considered malicious
    pub is_malicious: bool,
    /// Human-readable status
    pub status: String,
    /// Error message if lookup failed
    pub error: Option<String>,
}

/// AbuseIPDB API response
#[derive(Debug, Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "camelCase")]
struct AbuseIpDbData {
    ip_address: String,
    is_public: bool,
    abuse_confidence_score: u32,
    country_code: Option<String>,
    isp: Option<String>,
    total_reports: u32,
    #[serde(default)]
    is_whitelisted: Option<bool>,
}

/// VirusTotal API response for IP addresses
#[derive(Debug, Deserialize)]
struct VirusTotalIpResponse {
    data: VirusTotalIpData,
}

#[derive(Debug, Deserialize)]
struct VirusTotalIpData {
    attributes: VirusTotalIpAttributes,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VirusTotalIpAttributes {
    last_analysis_stats: Option<VirusTotalStats>,
    last_analysis_date: Option<i64>,
    country: Option<String>,
    as_owner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
    undetected: u32,
}

/// urlscan.io search API response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UrlscanSearchResponse {
    results: Vec<UrlscanSearchResult>,
    total: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UrlscanSearchResult {
    #[serde(rename = "_id")]
    id: String,
    result: String,
    task: UrlscanTask,
    verdicts: Option<UrlscanVerdicts>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UrlscanTask {
    url: String,
    domain: Option<String>,
    time: String,
}

#[derive(Debug, Deserialize)]
struct UrlscanVerdicts {
    overall: Option<UrlscanVerdict>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UrlscanVerdict {
    score: i32,
    malicious: bool,
    #[serde(default)]
    categories: Vec<String>,
}

/// Threat intelligence configuration
#[derive(Debug, Clone, Default)]
pub struct ThreatIntelConfig {
    /// AbuseIPDB API key
    pub abuseipdb_api_key: Option<String>,
    /// VirusTotal API key
    pub virustotal_api_key: Option<String>,
    /// urlscan.io API key
    pub urlscan_api_key: Option<String>,
    /// Enable threat intelligence lookups
    pub enabled: bool,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum IPs to check (to avoid rate limiting)
    pub max_lookups: usize,
}

/// API keys configuration file structure
#[derive(Debug, Deserialize)]
struct ApiKeysFile {
    abuseipdb: Option<ApiKeyEntry>,
    virustotal: Option<ApiKeyEntry>,
    urlscan: Option<ApiKeyEntry>,
    settings: Option<ApiKeysSettings>,
}

#[derive(Debug, Deserialize)]
struct ApiKeyEntry {
    api_key: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ApiKeysSettings {
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_max_lookups")]
    max_lookups: usize,
}

fn default_true() -> bool { true }
fn default_timeout() -> u64 { 10 }
fn default_max_lookups() -> usize { 20 }

impl ThreatIntelConfig {
    /// Load configuration from a JSON file (recommended for security)
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read API keys file: {}", e))?;
        
        let config: ApiKeysFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse API keys file: {}", e))?;
        
        let settings = config.settings.unwrap_or(ApiKeysSettings {
            timeout_secs: 10,
            max_lookups: 20,
        });
        
        Ok(Self {
            abuseipdb_api_key: config.abuseipdb
                .filter(|e| e.enabled)
                .and_then(|e| e.api_key)
                .filter(|k| !k.is_empty()),
            virustotal_api_key: config.virustotal
                .filter(|e| e.enabled)
                .and_then(|e| e.api_key)
                .filter(|k| !k.is_empty()),
            urlscan_api_key: config.urlscan
                .filter(|e| e.enabled)
                .and_then(|e| e.api_key)
                .filter(|k| !k.is_empty()),
            enabled: true,
            timeout_secs: settings.timeout_secs,
            max_lookups: settings.max_lookups,
        })
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            abuseipdb_api_key: std::env::var("ABUSEIPDB_API_KEY").ok(),
            virustotal_api_key: std::env::var("VIRUSTOTAL_API_KEY").ok(),
            urlscan_api_key: std::env::var("URLSCAN_API_KEY").ok(),
            enabled: std::env::var("THREAT_INTEL_ENABLED")
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false),
            timeout_secs: std::env::var("THREAT_INTEL_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            max_lookups: std::env::var("THREAT_INTEL_MAX_LOOKUPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
        }
    }

    /// Check if any API is configured
    pub fn has_api_keys(&self) -> bool {
        self.abuseipdb_api_key.is_some() || self.virustotal_api_key.is_some() || self.urlscan_api_key.is_some()
    }
}

/// Threat intelligence lookup service
pub struct ThreatIntelService {
    config: ThreatIntelConfig,
    client: reqwest::blocking::Client,
    cache: HashMap<String, ThreatIntelResult>,
}

impl ThreatIntelService {
    /// Create a new threat intelligence service
    pub fn new(config: ThreatIntelConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_secs);
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            config,
            client,
            cache: HashMap::new(),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(ThreatIntelConfig::from_env())
    }

    /// Check if the service is enabled and has API keys
    pub fn is_available(&self) -> bool {
        self.config.enabled && self.config.has_api_keys()
    }

    /// Lookup an IP address against threat intelligence sources
    pub fn lookup_ip(&mut self, ip: &str) -> ThreatIntelResult {
        // Check cache first
        if let Some(cached) = self.cache.get(ip) {
            return cached.clone();
        }

        // Skip private IPs
        if is_private_ip(ip) {
            let result = ThreatIntelResult {
                indicator: ip.to_string(),
                status: "Private IP - skipped".to_string(),
                ..Default::default()
            };
            self.cache.insert(ip.to_string(), result.clone());
            return result;
        }

        let mut result = ThreatIntelResult {
            indicator: ip.to_string(),
            status: "Checking...".to_string(),
            ..Default::default()
        };

        // Query AbuseIPDB
        if let Some(ref api_key) = self.config.abuseipdb_api_key {
            match self.query_abuseipdb(ip, api_key) {
                Ok(abuse_result) => {
                    result.abuseipdb_score = Some(abuse_result.abuse_confidence_score);
                    result.abuseipdb_country = abuse_result.country_code;
                    result.abuseipdb_isp = abuse_result.isp;
                    result.abuseipdb_reports = Some(abuse_result.total_reports);
                    
                    // Consider malicious if score > 25 or has multiple reports
                    if abuse_result.abuse_confidence_score > 25 || abuse_result.total_reports > 5 {
                        result.is_malicious = true;
                    }
                }
                Err(e) => {
                    result.error = Some(format!("AbuseIPDB error: {}", e));
                }
            }
        }

        // Query VirusTotal
        if let Some(ref api_key) = self.config.virustotal_api_key {
            match self.query_virustotal_ip(ip, api_key) {
                Ok(vt_result) => {
                    if let Some(stats) = vt_result.last_analysis_stats {
                        let total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
                        let detections = stats.malicious + stats.suspicious;
                        result.virustotal_detections = Some(format!("{}/{}", detections, total));
                        
                        // Consider malicious if detection ratio > 5%
                        if total > 0 && (detections as f32 / total as f32) > 0.05 {
                            result.is_malicious = true;
                        }
                    }
                    if let Some(timestamp) = vt_result.last_analysis_date {
                        if let Some(dt) = chrono::DateTime::from_timestamp(timestamp, 0) {
                            result.virustotal_scan_date = Some(dt.format("%Y-%m-%d").to_string());
                        }
                    }
                }
                Err(e) => {
                    let existing_error = result.error.take().unwrap_or_default();
                    result.error = Some(format!("{}; VT error: {}", existing_error, e));
                }
            }
        }

        // Query urlscan.io
        if let Some(ref api_key) = self.config.urlscan_api_key {
            match self.query_urlscan_ip(ip, api_key) {
                Ok(urlscan_result) => {
                    if let Some(verdict) = urlscan_result {
                        result.urlscan_score = Some(verdict.score as u32);
                        result.urlscan_verdict = Some(if verdict.malicious { 
                            "Malicious".to_string() 
                        } else { 
                            "Clean".to_string() 
                        });
                        result.urlscan_result_url = Some(verdict.result_url);
                        
                        // Consider malicious if urlscan flags it
                        if verdict.malicious || verdict.score > 50 {
                            result.is_malicious = true;
                        }
                    }
                }
                Err(e) => {
                    let existing_error = result.error.take().unwrap_or_default();
                    result.error = Some(format!("{}; urlscan error: {}", existing_error, e));
                }
            }
        }

        // Set final status
        if result.is_malicious {
            result.status = "⚠️ MALICIOUS".to_string();
        } else if result.abuseipdb_score.is_some() || result.virustotal_detections.is_some() || result.urlscan_verdict.is_some() {
            result.status = "✓ Clean".to_string();
        } else if result.error.is_some() {
            result.status = "Lookup failed".to_string();
        } else {
            result.status = "No API keys configured".to_string();
        }

        self.cache.insert(ip.to_string(), result.clone());
        result
    }

    /// Lookup multiple IPs (with rate limiting)
    pub fn lookup_ips(&mut self, ips: &[String]) -> HashMap<String, ThreatIntelResult> {
        let mut results = HashMap::new();
        
        // Deduplicate and limit
        let unique_ips: Vec<_> = ips.iter()
            .filter(|ip| !is_private_ip(ip))
            .take(self.config.max_lookups)
            .collect();

        for ip in unique_ips {
            results.insert(ip.clone(), self.lookup_ip(ip));
            // Small delay to avoid rate limiting
            std::thread::sleep(Duration::from_millis(500));
        }

        results
    }

    fn query_abuseipdb(&self, ip: &str, api_key: &str) -> Result<AbuseIpDbData, String> {
        let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90", ip);
        
        let response = self.client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }

        let data: AbuseIpDbResponse = response.json().map_err(|e| e.to_string())?;
        Ok(data.data)
    }

    fn query_virustotal_ip(&self, ip: &str, api_key: &str) -> Result<VirusTotalIpAttributes, String> {
        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
        
        let response = self.client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }

        let data: VirusTotalIpResponse = response.json().map_err(|e| e.to_string())?;
        Ok(data.data.attributes)
    }

    fn query_urlscan_ip(&self, ip: &str, api_key: &str) -> Result<Option<UrlscanResultInfo>, String> {
        // urlscan.io uses search API to find scans containing the IP
        let url = format!("https://urlscan.io/api/v1/search/?q=ip:{}", ip);
        
        let response = self.client
            .get(&url)
            .header("API-Key", api_key)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }

        let data: UrlscanSearchResponse = response.json().map_err(|e| e.to_string())?;
        
        // Find the most recent scan with verdict info
        for scan in data.results.iter().take(5) {
            if let Some(ref verdicts) = scan.verdicts {
                if let Some(ref overall) = verdicts.overall {
                    return Ok(Some(UrlscanResultInfo {
                        score: overall.score,
                        malicious: overall.malicious,
                        result_url: scan.result.clone(),
                    }));
                }
            }
        }
        
        // No verdict found
        Ok(None)
    }
}

/// Helper struct for urlscan.io result info
struct UrlscanResultInfo {
    score: i32,
    malicious: bool,
    result_url: String,
}

/// Check if an IP address is private (RFC1918, loopback, etc.)
fn is_private_ip(ip: &str) -> bool {
    // Parse IP and check if it's private
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_broadcast()
                    || ipv4.is_unspecified()
                    || ip.starts_with("169.254.")  // Link-local
            }
            std::net::IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unspecified()
            }
        }
    } else {
        // If we can't parse it, treat as external
        false
    }
}

/// Convert ThreatIntelResult to ThreatIntelData for Finding
impl From<ThreatIntelResult> for crate::ThreatIntelData {
    fn from(result: ThreatIntelResult) -> Self {
        Self {
            abuseipdb_score: result.abuseipdb_score,
            abuseipdb_country: result.abuseipdb_country,
            abuseipdb_isp: result.abuseipdb_isp,
            abuseipdb_reports: result.abuseipdb_reports,
            virustotal_detections: result.virustotal_detections,
            virustotal_scan_date: result.virustotal_scan_date,
            urlscan_verdict: result.urlscan_verdict,
            urlscan_score: result.urlscan_score,
            urlscan_result_url: result.urlscan_result_url,
            is_malicious: result.is_malicious,
            lookup_status: result.status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }
}
