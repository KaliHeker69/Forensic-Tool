// =============================================================================
// Browser Forensics — Data Models
// =============================================================================
// Covers: Chrome, Edge, Brave, Firefox, Internet Explorer
// Artifact types: History, Downloads, Cookies, Logins, Autofill, Bookmarks,
//                 Extensions, Cache, Sessions, and browser-specific artifacts.
// =============================================================================

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Supported browsers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Edge,
    #[serde(rename = "EdgeLegacy")]
    EdgeLegacy,
    Brave,
    Firefox,
    #[serde(rename = "InternetExplorer")]
    InternetExplorer,
    Other(String),
}

impl std::fmt::Display for Browser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Browser::Chrome => write!(f, "Google Chrome"),
            Browser::Edge => write!(f, "Microsoft Edge"),
            Browser::EdgeLegacy => write!(f, "Microsoft Edge (Legacy)"),
            Browser::Brave => write!(f, "Brave Browser"),
            Browser::Firefox => write!(f, "Mozilla Firefox"),
            Browser::InternetExplorer => write!(f, "Internet Explorer"),
            Browser::Other(name) => write!(f, "{}", name),
        }
    }
}

/// Artifact category tag
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactCategory {
    History,
    Downloads,
    Cookies,
    Logins,
    Autofill,
    Bookmarks,
    Extensions,
    Cache,
    Sessions,
    Preferences,
    #[serde(rename = "TopSites")]
    TopSites,
    // Brave-specific
    #[serde(rename = "BraveShields")]
    BraveShields,
    #[serde(rename = "BraveRewards")]
    BraveRewards,
    #[serde(rename = "BraveWallet")]
    BraveWallet,
    #[serde(rename = "BraveTor")]
    BraveTor,
    // Firefox-specific
    #[serde(rename = "FormHistory")]
    FormHistory,
    Permissions,
    // Cross-browser / system-wide
    #[serde(rename = "DnsCache")]
    DnsCache,
    Prefetch,
    #[serde(rename = "JumpLists")]
    JumpLists,
    #[serde(rename = "ZoneIdentifier")]
    ZoneIdentifier,
    #[serde(rename = "TypedURLs")]
    TypedURLs,
    Other(String),
}

impl std::fmt::Display for ArtifactCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactCategory::History => write!(f, "Browsing History"),
            ArtifactCategory::Downloads => write!(f, "Downloads"),
            ArtifactCategory::Cookies => write!(f, "Cookies"),
            ArtifactCategory::Logins => write!(f, "Login Data / Credentials"),
            ArtifactCategory::Autofill => write!(f, "Autofill / Web Data"),
            ArtifactCategory::Bookmarks => write!(f, "Bookmarks"),
            ArtifactCategory::Extensions => write!(f, "Extensions / Add-ons"),
            ArtifactCategory::Cache => write!(f, "Cache Metadata"),
            ArtifactCategory::Sessions => write!(f, "Sessions"),
            ArtifactCategory::Preferences => write!(f, "Preferences"),
            ArtifactCategory::TopSites => write!(f, "Top Sites"),
            ArtifactCategory::BraveShields => write!(f, "Brave Shields Config"),
            ArtifactCategory::BraveRewards => write!(f, "Brave Rewards / BAT"),
            ArtifactCategory::BraveWallet => write!(f, "Brave Wallet"),
            ArtifactCategory::BraveTor => write!(f, "Brave Tor"),
            ArtifactCategory::FormHistory => write!(f, "Form History"),
            ArtifactCategory::Permissions => write!(f, "Permissions"),
            ArtifactCategory::DnsCache => write!(f, "DNS Cache"),
            ArtifactCategory::Prefetch => write!(f, "Prefetch"),
            ArtifactCategory::JumpLists => write!(f, "Jump Lists"),
            ArtifactCategory::ZoneIdentifier => write!(f, "Zone.Identifier ADS"),
            ArtifactCategory::TypedURLs => write!(f, "Typed URLs"),
            ArtifactCategory::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Forensic priority level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

// ---------------------------------------------------------------------------
// Individual artifact record types
// ---------------------------------------------------------------------------

/// A single browsing-history entry (Chrome/Edge/Brave/Firefox/IE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visit_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_visit_time: Option<String>,  // ISO-8601 or original raw
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visit_type: Option<String>,       // typed, link, bookmark, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visit_duration: Option<String>,
}

/// A download record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,   // complete, interrupted, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
}

/// A cookie record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    pub host: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_access_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_httponly: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
}

/// A saved credential / login record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginEntry {
    pub origin_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_present: Option<bool>, // we don't store cleartext
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_last_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_with: Option<String>, // DPAPI, NSS, etc.
}

/// An autofill / form-history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillEntry {
    pub field_name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
}

/// A bookmark
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
}

/// A browser extension / add-on
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>, // store, sideloaded, etc.
}

/// Cache metadata entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_access_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<String>,
}

/// Session / tab entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tab_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
}

/// A preference / settings entry (key/value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceEntry {
    pub key: String,
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>, // forensic note
}

/// Top-site entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopSiteEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
}

// -- Brave-specific ----------------------------------------------------------

/// Brave Shields per-site configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraveShieldsEntry {
    pub site: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shields_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ad_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_upgrade: Option<bool>,
}

/// Brave Rewards / BAT data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraveRewardsEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custodial_partner: Option<String>, // Uphold, Gemini, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bat_balance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_month: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ad_notifications_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tips: Option<Vec<BraveTipEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraveTipEntry {
    pub publisher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_bat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// Brave Wallet record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraveWalletEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>, // Ethereum, Solana, Filecoin …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_dapps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
}

/// Brave Tor usage indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraveTorEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_urls_found: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_config_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

// -- Cross-browser / system-wide artifacts -----------------------------------

/// DNS cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub record_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Prefetch record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchEntry {
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Jump-list entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpListEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    pub target_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Zone.Identifier ADS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneIdentifierEntry {
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_url: Option<String>,
}

/// Typed-URL registry entry (IE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedUrlEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Permission entry (Firefox)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub origin: String,
    pub permission_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>, // allow, deny, prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
}

// ---------------------------------------------------------------------------
// New forensic types
// ---------------------------------------------------------------------------

/// Row recovered from SQLite WAL/journal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecoveredRow {
    pub source_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_number: Option<u32>,
    pub recovered_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>, // "url", "path", "email", "general"
}

/// Cache extracted item (from Chrome Cache_Data / Firefox cache2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheExtractedItem {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<String>,
}

/// Extension code file reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionCodeFile {
    pub extension_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_name: Option<String>,
    pub file_path: String,
    pub file_type: String, // "js", "html", "css", "json", "wasm"
    pub file_size: u64,
}

/// Unified timeline event (computed from all artifacts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String, // ISO-8601
    pub event_type: String, // "visit", "download", "cookie_created", "login_used", "bookmark_added"
    pub source_browser: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Privacy / incognito / Tor indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIndicator {
    pub browser: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub indicator_type: String, // "incognito", "private_browsing", "tor", "vpn", "privacy_mode"
    pub evidence: String,
    pub severity: String, // "critical", "high", "medium", "low"
}

// ---------------------------------------------------------------------------
// Unified artifact container
// ---------------------------------------------------------------------------

/// A single artifact collection from one browser profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCollection {
    pub browser: Browser,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<DownloadEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<CookieEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logins: Vec<LoginEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub autofill: Vec<AutofillEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bookmarks: Vec<BookmarkEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache: Vec<CacheEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<SessionEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<PreferenceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_sites: Vec<TopSiteEntry>,

    // Brave-specific
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brave_shields: Vec<BraveShieldsEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brave_rewards: Option<BraveRewardsEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brave_wallet: Vec<BraveWalletEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brave_tor: Option<BraveTorEntry>,

    // Firefox-specific
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub form_history: Vec<AutofillEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<PermissionEntry>,

    // IE-specific
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub typed_urls: Vec<TypedUrlEntry>,

    // WAL/journal recovery
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wal_recovered: Vec<WalRecoveredRow>,

    // Cache extraction
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_extracted: Vec<CacheExtractedItem>,

    // Extension code files
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_files: Vec<ExtensionCodeFile>,
}

// ---------------------------------------------------------------------------
// Top-level forensic input
// ---------------------------------------------------------------------------

/// Case metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examiner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
}

/// Root input structure the tool reads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicInput {
    #[serde(default)]
    pub case_info: Option<CaseInfo>,
    pub artifacts: Vec<ArtifactCollection>,

    // Cross-browser / system-wide
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_cache: Vec<DnsCacheEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefetch: Vec<PrefetchEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jump_lists: Vec<JumpListEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zone_identifiers: Vec<ZoneIdentifierEntry>,
}

// ---------------------------------------------------------------------------
// Output report wrapper
// ---------------------------------------------------------------------------

/// Summary statistics for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_browsers: usize,
    pub total_history_entries: usize,
    pub total_downloads: usize,
    pub total_cookies: usize,
    pub total_logins: usize,
    pub total_autofill: usize,
    pub total_bookmarks: usize,
    pub total_extensions: usize,
    pub total_cache_entries: usize,
    pub total_sessions: usize,
    pub browsers_found: Vec<String>,
    pub has_brave_wallet: bool,
    pub has_brave_tor: bool,
    pub has_dns_cache: bool,
    pub has_prefetch: bool,
    pub has_jump_lists: bool,
    pub has_zone_identifiers: bool,
    // New
    pub total_timeline_events: usize,
    pub total_wal_recovered: usize,
    pub total_cache_extracted: usize,
    pub total_extension_files: usize,
    pub total_privacy_indicators: usize,
}

/// Final JSON report output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub report_generated: String,
    pub tool_version: String,
    pub case_info: Option<CaseInfo>,
    pub summary: ReportSummary,
    pub artifacts: Vec<ArtifactCollection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<TimelineEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privacy_indicators: Vec<PrivacyIndicator>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_cache: Vec<DnsCacheEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prefetch: Vec<PrefetchEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub jump_lists: Vec<JumpListEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zone_identifiers: Vec<ZoneIdentifierEntry>,
}
