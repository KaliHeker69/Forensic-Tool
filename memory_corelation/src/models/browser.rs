//! Browser-related data models for custom browser history/download plugins

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Timestamped;

/// Browser history entry from custom browser history plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistory {
    /// Visit timestamp
    #[serde(alias = "Timestamp", alias = "LastVisitTime", alias = "visit_time")]
    pub timestamp: DateTime<Utc>,

    /// Visited URL
    #[serde(alias = "URL", alias = "Url", alias = "url")]
    pub url: String,

    /// Page title
    #[serde(alias = "Title", alias = "title")]
    pub title: Option<String>,

    /// Visit count
    #[serde(alias = "VisitCount", alias = "visit_count")]
    pub visit_count: Option<u32>,

    /// Browser type (chrome, firefox, edge)
    #[serde(alias = "Browser", alias = "browser", default)]
    pub browser: String,

    /// Browser profile
    #[serde(alias = "Profile", alias = "profile")]
    pub profile: Option<String>,

    /// Transition type (link, typed, etc.)
    #[serde(alias = "Transition", alias = "transition_type")]
    pub transition: Option<String>,
}

impl BrowserHistory {
    /// Extract domain from URL
    pub fn domain(&self) -> Option<&str> {
        let url = self.url.as_str();
        // Handle http:// and https://
        let start = if url.starts_with("https://") {
            8
        } else if url.starts_with("http://") {
            7
        } else {
            0
        };

        let rest = &url[start..];
        rest.split('/').next().and_then(|s| s.split(':').next())
    }

    /// Check if URL looks suspicious (short URLs, known malware TLDs, etc.)
    pub fn is_suspicious_url(&self) -> bool {
        let lower = self.url.to_lowercase();
        
    // Known URL shorteners
    let shorteners = [
        "bit.ly",   // Bitly service :contentReference[oaicite:1]{index=1}
        "tinyurl.com", // TinyURL :contentReference[oaicite:2]{index=2}
        "t.co",     // Twitter/X shortener :contentReference[oaicite:3]{index=3}
        "ow.ly",    // Hootsuite’s service :contentReference[oaicite:4]{index=4}
        "is.gd",    // Lightweight shortener :contentReference[oaicite:5]{index=5}
        "bit.do",   // Shortener often listed :contentReference[oaicite:6]{index=6}
        "cutt.ly",  // Cuttly service :contentReference[oaicite:7]{index=7}
        "buff.ly",  // Buffer’s short domain :contentReference[oaicite:8]{index=8}
        "tiny.cc",  // Tiny.cc shortener :contentReference[oaicite:9]{index=9}
        "bl.ink",   // BL.INK shortener :contentReference[oaicite:10]{index=10}
        "rebrand.ly", // Rebrandly branded short links :contentReference[oaicite:11]{index=11}
        "short.io",   // Short.io alias domain :contentReference[oaicite:12]{index=12}
        "snip.ly",    // Sniply analytics shortener :contentReference[oaicite:13]{index=13}
        "t2m.io",     // T2M URL shortener :contentReference[oaicite:14]{index=14}
        "short-link.me", // Short-link.me tool :contentReference[oaicite:15]{index=15}
        "kutt.it",    // Kutt (open source) :contentReference[oaicite:16]{index=16}
        "lstu.fr",    // LSTU shortener :contentReference[oaicite:17]{index=17}
        "shlink.io",  // Shlink self-hosted shortener :contentReference[oaicite:18]{index=18}
    ];

        if shorteners.iter().any(|s| lower.contains(s)) {
            return true;
        }

        // Direct IP addresses
        if regex::Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            .map(|r| r.is_match(&lower))
            .unwrap_or(false)
        {
            return true;
        }

        // Suspicious file extensions in URL
        let suspicious_extensions = [".exe", ".scr", ".bat", ".ps1", ".hta", ".dll"];
        if suspicious_extensions.iter().any(|ext| lower.contains(ext)) {
            return true;
        }

        // Suspicious keywords
    let suspicious_keywords = [
        "download", "free", "crack", "keygen", "torrent",
        "warez", "serials", "patch", "install", "setup",

        "login", "signin", "logon", "auth", "account", "secure", // credential phish triggers :contentReference[oaicite:1]{index=1}
        "confirm", "validate", "verification", "verify", "reset",
        "update", "upgrade", "support", "help",

        "bank", "paypal", "appleid", "amazon", "microsoft", // brand-related could be spoof attempts :contentReference[oaicite:2]{index=2}
        "invoice", "billing", "payment", "order",

        "alert", "notice", "warning", "security",
        "captcha", "challenge",

        "cheap", "deal", "discount", "coupon", "bonus", "offer", // social-engineering lure words
        "earn", "profit", "cash", "reward"
    ];

        suspicious_keywords.iter().filter(|k| lower.contains(*k)).count() >= 2
    }

    /// Check if this looks like a drive-by download attempt
    pub fn is_potential_driveby(&self) -> bool {
        let lower = self.url.to_lowercase();

        lower.contains(".php?")
            || lower.contains("redirect")
            || lower.contains("download.php")
            || lower.contains("get.php")
            || lower.contains("file.php")
            || lower.contains("load.php")
            || lower.contains("update.php")
            || lower.contains("install.php")

            // common malicious script endpoints
            || lower.contains(".asp?")
            || lower.contains(".aspx?")
            || lower.contains(".jsp?")
            || lower.contains(".cgi?")
            || lower.contains(".pl?")
            || lower.contains(".sh?")

            // forced download indicators
            || lower.contains("attachment")
            || lower.contains("attach=")
            || lower.contains("file=")
            || lower.contains("payload")
            || lower.contains("raw=")

            // executable or installer delivery
            || lower.contains(".exe")
            || lower.contains(".msi")
            || lower.contains(".scr")
            || lower.contains(".bat")
            || lower.contains(".cmd")
            || lower.contains(".ps1")
            || lower.contains(".jar")
            || lower.contains(".apk")
            || lower.contains(".dmg")
            || lower.contains(".pkg")

            // compressed payloads often used for drive-by
            || lower.contains(".zip")
            || lower.contains(".rar")
            || lower.contains(".7z")
            || lower.contains(".iso")
            || lower.contains(".cab")

            // suspicious redirects + IDs
            || (lower.contains("?id=") && (
                lower.contains(".exe")
                || lower.contains(".zip")
                || lower.contains(".js")
            ))

            // javascript or data URI abuse
            || lower.starts_with("javascript:")
            || lower.starts_with("data:")
    }
}

impl Timestamped for BrowserHistory {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        Some(self.timestamp)
    }
}

/// Download history entry from custom download plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadHistory {
    /// Download start timestamp
    #[serde(alias = "Timestamp", alias = "StartTime", alias = "start_time")]
    pub timestamp: DateTime<Utc>,

    /// Download URL
    #[serde(alias = "URL", alias = "Url", alias = "url", alias = "TabUrl")]
    pub url: String,

    /// Target file path
    #[serde(alias = "TargetPath", alias = "CurrentPath", alias = "target_path")]
    pub target_path: String,

    /// Total file size in bytes
    #[serde(alias = "TotalBytes", alias = "total_bytes")]
    pub total_bytes: Option<u64>,

    /// Received bytes
    #[serde(alias = "ReceivedBytes", alias = "received_bytes")]
    pub received_bytes: Option<u64>,

    /// Browser type
    #[serde(alias = "Browser", alias = "browser", default)]
    pub browser: String,

    /// Download state (complete, interrupted, etc.)
    #[serde(alias = "State", alias = "state")]
    pub state: Option<String>,

    /// Danger type if flagged by browser
    #[serde(alias = "DangerType", alias = "danger_type")]
    pub danger_type: Option<String>,

    /// MIME type
    #[serde(alias = "MimeType", alias = "mime_type")]
    pub mime_type: Option<String>,

    /// End timestamp
    #[serde(alias = "EndTime", alias = "end_time")]
    pub end_time: Option<DateTime<Utc>>,
}

impl DownloadHistory {
    /// Extract filename from target path
    pub fn filename(&self) -> &str {
        self.target_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.target_path)
    }

    /// Check if downloaded file is executable
    pub fn is_executable(&self) -> bool {
        let lower = self.target_path.to_lowercase();
        let exe_extensions = [
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
            ".msi", ".jar", ".com", ".pif",
        ];
        exe_extensions.iter().any(|ext| lower.ends_with(ext))
    }

    /// Check if download was flagged as dangerous by browser
    pub fn was_flagged_dangerous(&self) -> bool {
        self.danger_type
            .as_ref()
            .map(|d| !d.is_empty() && d != "0" && d.to_lowercase() != "safe")
            .unwrap_or(false)
    }

    /// Extract domain from URL
    pub fn domain(&self) -> Option<&str> {
        let url = self.url.as_str();
        let start = if url.starts_with("https://") {
            8
        } else if url.starts_with("http://") {
            7
        } else {
            0
        };
        let rest = &url[start..];
        rest.split('/').next().and_then(|s| s.split(':').next())
    }

    /// Check if download is complete
    pub fn is_complete(&self) -> bool {
        if let (Some(total), Some(received)) = (self.total_bytes, self.received_bytes) {
            return total > 0 && received >= total;
        }
        self.state
            .as_ref()
            .map(|s| s.to_lowercase().contains("complete"))
            .unwrap_or(false)
    }
}

impl Timestamped for DownloadHistory {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        Some(self.timestamp)
    }
}

/// Correlation between browser activity and other artifacts
#[derive(Debug, Clone, Serialize)]
pub struct BrowserCorrelation {
    pub history_entry: Option<BrowserHistory>,
    pub download_entry: Option<DownloadHistory>,
    pub matched_file: Option<String>,
    pub matched_network: Option<String>,
    pub time_delta_secs: Option<i64>,
    pub correlation_type: BrowserCorrelationType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BrowserCorrelationType {
    /// Browser visit followed by download
    VisitThenDownload,
    /// Download followed by file access
    DownloadThenFileAccess,
    /// Browser visit correlated with network connection
    VisitThenNetwork,
    /// Full chain: visit → download → execution
    FullAttackChain,
}
