use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The core normalized event. Every data source is collapsed into this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub source: ArtifactSource,
    pub direction: Option<Direction>,
    pub protocol: Option<Protocol>,
    pub local_addr: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub username: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub hostname: Option<String>,
    pub raw_evidence: String,
    pub tags: Vec<Tag>,
    pub risk_score: u8,
}

impl NetEvent {
    pub fn new(source: ArtifactSource, raw_evidence: String) -> Self {
        Self {
            timestamp: None,
            source,
            direction: None,
            protocol: None,
            local_addr: None,
            local_port: None,
            remote_addr: None,
            remote_port: None,
            process_name: None,
            pid: None,
            username: None,
            bytes_sent: None,
            bytes_recv: None,
            hostname: None,
            raw_evidence,
            tags: Vec::new(),
            risk_score: 0,
        }
    }

    pub fn is_external(&self) -> bool {
        self.remote_addr.map_or(false, |ip| !is_private_ip(ip))
    }

    pub fn is_lateral(&self) -> bool {
        self.remote_addr.map_or(false, is_private_ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactSource {
    EventLogSecurity,
    EventLogSystem,
    EventLogRdp,
    EventLogSmb,
    EventLogBits,
    EventLogDns,
    EventLogPowerShell,
    EventLogFirewall,
    EventLogTaskScheduler,
    EventLogWinRM,
    EventLogNetworkProfile,
    Srum,
    Prefetch,
    Registry,
    BrowserHistory,
    LiveCapture,
    Mft,
    LnkFile,
    HostsFile,
    ScheduledTask,
    BitsDatabase,
    PowerShellHistory,
    IocFeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Lateral,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    SuspiciousProcess,
    KnownMaliciousPort,
    Beaconing,
    LateralMovement,
    C2Indicator,
    DataExfiltration,
    PersistenceMechanism,
    DgaDomain,
    HighEntropy,
    OffHours,
    ProcessSpoofing,
    UnsignedProcess,
    HighBytesSent,
    AdminShareAccess,
    PassTheHash,
    RdpAccess,
    BitsAbuse,
    NetworkToolExecution,
    IocMatch(String),
    Custom(String),
}

/// Severity filter threshold
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn min_score(&self) -> u8 {
        match self {
            Severity::Low => 0,
            Severity::Medium => 34,
            Severity::High => 67,
        }
    }
}

/// Determines if an IP address is in a private RFC1918 range.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 169 && v4.octets()[1] == 254 // APIPA
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Full forensic report containing all analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub metadata: ReportMetadata,
    pub summary: ExecutiveSummary,
    pub timeline: Vec<NetEvent>,
    pub flagged_events: Vec<NetEvent>,
    pub process_network_map: Vec<ProcessNetworkEntry>,
    pub lateral_movement: Vec<LateralMovementEntry>,
    pub infrastructure: Vec<InfrastructureEntry>,
    pub ioc_matches: Vec<IocMatchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub tool_version: String,
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub source_paths: SourcePaths,
    pub mode: String,
    pub total_events_parsed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcePaths {
    pub kape_path: Option<String>,
    pub evtx_path: Option<String>,
    pub live_json: Option<String>,
    pub ioc_feed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub total_connections: usize,
    pub unique_external_ips: usize,
    pub unique_internal_ips: usize,
    pub high_risk_events: usize,
    pub medium_risk_events: usize,
    pub low_risk_events: usize,
    pub top_suspicious_ips: Vec<(String, usize)>,
    pub timeline_start: Option<DateTime<Utc>>,
    pub timeline_end: Option<DateTime<Utc>>,
    pub lateral_movement_detected: bool,
    pub beaconing_detected: bool,
    pub exfiltration_indicators: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNetworkEntry {
    pub process_name: String,
    pub pid: Option<u32>,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
    pub unique_destinations: Vec<String>,
    pub connection_count: usize,
    pub suspicious: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub source_ip: String,
    pub dest_ip: String,
    pub method: String,
    pub username: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureEntry {
    pub ip_or_hostname: String,
    pub classification: IpClassification,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub seen_in_sources: Vec<ArtifactSource>,
    pub connection_count: usize,
    pub total_bytes: u64,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpClassification {
    PrivateRfc1918,
    Public,
    Loopback,
    LinkLocal,
    IocMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatchEntry {
    pub indicator: String,
    pub indicator_type: String,
    pub matched_in: ArtifactSource,
    pub event_timestamp: Option<DateTime<Utc>>,
    pub context: String,
}


