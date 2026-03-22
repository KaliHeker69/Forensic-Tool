//! Timeline builder for unified event view
//!
//! Builds a unified timeline from all parsed data and provides
//! temporal intelligence: burst detection and hot-spot scoring.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::models::{EventType, TimelineEvent, Timestamped};
use crate::parsers::ParsedData;

/// Builds a unified timeline from all parsed data
pub struct TimelineBuilder<'a> {
    data: &'a ParsedData,
}

impl<'a> TimelineBuilder<'a> {
    pub fn new(data: &'a ParsedData) -> Self {
        Self { data }
    }

    /// Build the complete timeline
    pub fn build(&self) -> Vec<TimelineEvent> {
        let mut events = Vec::new();

        self.add_process_events(&mut events);
        self.add_network_events(&mut events);
        self.add_browser_events(&mut events);
        self.add_download_events(&mut events);
        self.add_registry_events(&mut events);
        self.add_malfind_events(&mut events);
        self.add_dll_events(&mut events);
        self.add_mft_events(&mut events);
        self.add_service_events(&mut events);
        self.add_userassist_events(&mut events);
        self.add_scheduled_task_events(&mut events);

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        events
    }

    fn add_process_events(&self, events: &mut Vec<TimelineEvent>) {
        for proc in &self.data.processes {
            if let Some(ts) = proc.create_time {
                let cmdline = self
                    .data
                    .cmdlines
                    .iter()
                    .find(|c| c.pid == proc.pid)
                    .map(|c| c.args.clone());

                let is_suspicious = cmdline
                    .as_ref()
                    .map(|c| {
                        let lower = c.to_lowercase();
                        lower.contains("-enc") || lower.contains("-e ") || lower.contains("-w hidden")
                    })
                    .unwrap_or(false);

                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::ProcessCreated,
                    source_plugin: "pslist".to_string(),
                    description: format!(
                        "Process created: {} (PID:{}{})",
                        proc.name,
                        proc.pid,
                        cmdline
                            .as_ref()
                            .map(|c| format!(" cmdline: {}", truncate(c, 80)))
                            .unwrap_or_default()
                    ),
                    pid: Some(proc.pid),
                    process_name: Some(proc.name.clone()),
                    related_ips: vec![],
                    related_files: vec![],
                    risk_score: if is_suspicious { 70 } else { 10 },
                });
            }

            if let Some(ts) = proc.exit_time {
                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::ProcessTerminated,
                    source_plugin: "pslist".to_string(),
                    description: format!("Process terminated: {} (PID:{})", proc.name, proc.pid),
                    pid: Some(proc.pid),
                    process_name: Some(proc.name.clone()),
                    related_ips: vec![],
                    related_files: vec![],
                    risk_score: 5,
                });
            }
        }
    }

    fn add_network_events(&self, events: &mut Vec<TimelineEvent>) {
        for conn in &self.data.connections {
            if let Some(ts) = conn.created {
                let is_external = conn.is_external();
                let event_type = if conn.is_listening() {
                    EventType::NetworkListen
                } else {
                    EventType::NetworkConnection
                };

                let risk = self.network_event_risk(conn);

                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type,
                    source_plugin: "netscan".to_string(),
                    description: format!(
                        "{} {} {} → {}:{}{}",
                        conn.protocol,
                        conn.state.as_deref().unwrap_or(""),
                        conn.local_endpoint(),
                        conn.foreign_addr,
                        conn.foreign_port,
                        conn.owner
                            .as_ref()
                            .map(|o| format!(" ({})", o))
                            .unwrap_or_default()
                    ),
                    pid: Some(conn.pid),
                    process_name: conn.owner.clone(),
                    related_ips: vec![conn.foreign_addr.clone()],
                    related_files: vec![],
                    risk_score: risk,
                });
            }
        }
    }

    fn network_event_risk(&self, conn: &crate::models::network::NetworkConnection) -> u8 {
        let owner = conn.owner.as_deref().unwrap_or("");
        let owner_lower = owner.to_lowercase();
        let active_state = is_active_network_state(conn.state.as_deref().unwrap_or(""));

        if conn.is_suspicious_port() {
            return 75;
        }

        if !conn.is_external() {
            return if conn.is_listening() { 12 } else { 6 };
        }

        // External management/lateral movement ports are high signal.
        if matches!(conn.foreign_port, 22 | 135 | 445 | 3389 | 5985 | 5986) {
            return 65;
        }

        // Browsers making standard web connections should be low risk context.
        if conn.is_established() && conn.is_common_web_port() && is_browser_process(&owner_lower) {
            return 8;
        }

        // Common client apps making outbound web requests should stay low.
        if conn.is_established()
            && conn.is_common_web_port()
            && is_common_network_client(&owner_lower)
        {
            return 14;
        }

        // Unknown process to web ports is mildly suspicious.
        if conn.is_established() && conn.is_common_web_port() {
            return 24;
        }

        if conn.is_listening() {
            return 40;
        }

        if active_state {
            20
        } else {
            12
        }
    }

    fn add_browser_events(&self, events: &mut Vec<TimelineEvent>) {
        for history in &self.data.browser_history {
            let risk = if history.is_suspicious_url() {
                60
            } else if history.is_potential_driveby() {
                70
            } else {
                15
            };

            events.push(TimelineEvent {
                timestamp: history.timestamp,
                event_type: EventType::BrowserVisit,
                source_plugin: "browser_history".to_string(),
                description: format!(
                    "[{}] Visited: {}{}",
                    history.browser,
                    truncate(&history.url, 100),
                    history
                        .title
                        .as_ref()
                        .map(|t| format!(" - {}", truncate(t, 40)))
                        .unwrap_or_default()
                ),
                pid: None,
                process_name: Some(history.browser.clone()),
                related_ips: history.domain().map(|d| d.to_string()).into_iter().collect(),
                related_files: vec![],
                risk_score: risk,
            });
        }
    }

    fn add_download_events(&self, events: &mut Vec<TimelineEvent>) {
        for download in &self.data.downloads {
            let risk = if download.is_executable() {
                65
            } else if download.was_flagged_dangerous() {
                80
            } else {
                20
            };

            events.push(TimelineEvent {
                timestamp: download.timestamp,
                event_type: EventType::FileDownload,
                source_plugin: "download_history".to_string(),
                description: format!(
                    "[{}] Downloaded: {} → {}",
                    download.browser,
                    truncate(&download.url, 60),
                    download.filename()
                ),
                pid: None,
                process_name: Some(download.browser.clone()),
                related_ips: download.domain().map(|d| d.to_string()).into_iter().collect(),
                related_files: vec![download.target_path.clone()],
                risk_score: risk,
            });
        }
    }

    fn add_registry_events(&self, events: &mut Vec<TimelineEvent>) {
        for key in &self.data.registry_keys {
            if let Some(ts) = key.last_write {
                if key.is_persistence_key() {
                    let risk = if key.has_obfuscated_data() {
                        85
                    } else if key.has_executable_data() {
                        70
                    } else {
                        50
                    };

                    events.push(TimelineEvent {
                        timestamp: ts,
                        event_type: EventType::RegistryModification,
                        source_plugin: "printkey".to_string(),
                        description: format!(
                            "Persistence key: {} = {}",
                            key.base_name(),
                            key.data.as_deref().map(|d| truncate(d, 60)).unwrap_or_else(|| "-".to_string())
                        ),
                        pid: None,
                        process_name: None,
                        related_ips: vec![],
                        related_files: key.data.clone().into_iter().collect(),
                        risk_score: risk,
                    });
                }
            }
        }
    }

    fn add_malfind_events(&self, events: &mut Vec<TimelineEvent>) {
        for mal in &self.data.malfind {
            let risk = if mal.has_mz_header() {
                90
            } else if mal.has_shellcode_patterns() {
                85
            } else if mal.is_rwx() {
                70
            } else {
                50
            };

            // Use a synthetic timestamp (we don't have real ones for malfind)
            // In a real scenario, this would correlate with process creation time
            let ts = self
                .data
                .processes
                .iter()
                .find(|p| p.pid == mal.pid)
                .and_then(|p| p.create_time)
                .unwrap_or_else(Utc::now);

            events.push(TimelineEvent {
                timestamp: ts,
                event_type: EventType::InjectionDetected,
                source_plugin: "malfind".to_string(),
                description: format!(
                    "Code injection in {} (PID:{}): {} {} [{}]",
                    mal.process,
                    mal.pid,
                    mal.start,
                    mal.protection,
                    if mal.has_mz_header() {
                        "MZ HEADER"
                    } else if mal.has_shellcode_patterns() {
                        "SHELLCODE"
                    } else {
                        "RWX"
                    }
                ),
                pid: Some(mal.pid),
                process_name: Some(mal.process.clone()),
                related_ips: vec![],
                related_files: vec![],
                risk_score: risk,
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // New event sources added in Phase 3
    // ═══════════════════════════════════════════════════════════════════

    fn add_dll_events(&self, events: &mut Vec<TimelineEvent>) {
        for dll in &self.data.dlls {
            if let Some(ts) = dll.load_time {
                let path_lower = dll.path.to_lowercase();
                let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                                         "\\downloads\\", "\\public\\"];
                let is_suspicious = suspicious_paths.iter().any(|p| path_lower.contains(p));

                // Only include DLLs from suspicious paths or non-system paths
                // to keep timeline manageable
                if !is_suspicious && !path_lower.contains("\\programdata\\") {
                    continue;
                }

                let risk = if is_suspicious { 55 } else { 20 };

                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::DllLoaded,
                    source_plugin: "dlllist".to_string(),
                    description: format!(
                        "DLL loaded: {} by {} (PID:{})",
                        dll.name, dll.process, dll.pid
                    ),
                    pid: Some(dll.pid),
                    process_name: Some(dll.process.clone()),
                    related_ips: vec![],
                    related_files: vec![dll.path.clone()],
                    risk_score: risk,
                });
            }
        }
    }

    fn add_mft_events(&self, events: &mut Vec<TimelineEvent>) {
        for mft in &self.data.mft_entries {
            let filename = match &mft.filename {
                Some(f) => f.clone(),
                None => continue,
            };

            // Only include interesting MFT entries
            if !mft.is_executable() && !mft.is_in_suspicious_directory() && !mft.has_double_extension() {
                continue;
            }

            let risk = if mft.has_double_extension() {
                80
            } else if mft.is_executable() && mft.is_in_suspicious_directory() {
                70
            } else if mft.is_executable() {
                40
            } else {
                25
            };

            // File creation
            if let Some(ts) = mft.parse_created() {
                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::MftCreated,
                    source_plugin: "mftscan".to_string(),
                    description: format!(
                        "File created: {}{}",
                        truncate(&filename, 100),
                        if mft.is_deleted() { " [DELETED]" } else { "" }
                    ),
                    pid: None,
                    process_name: None,
                    related_ips: vec![],
                    related_files: vec![filename.clone()],
                    risk_score: risk,
                });
            }

            // File modification
            if let Some(ts) = mft.parse_modified() {
                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::MftModified,
                    source_plugin: "mftscan".to_string(),
                    description: format!(
                        "File modified: {}{}",
                        truncate(&filename, 100),
                        if mft.is_deleted() { " [DELETED]" } else { "" }
                    ),
                    pid: None,
                    process_name: None,
                    related_ips: vec![],
                    related_files: vec![filename.clone()],
                    risk_score: risk,
                });
            }
        }
    }

    fn add_service_events(&self, events: &mut Vec<TimelineEvent>) {
        // Services don't have direct timestamps, but we can correlate with
        // their hosting process's creation time
        for svc in &self.data.services {
            // Only include suspicious or notable services
            if !svc.is_suspicious_name() && !svc.has_suspicious_execution() {
                continue;
            }

            // Try to get timestamp from process that runs this service
            let pid_str = svc.pid.as_deref().unwrap_or("");
            let pid_val: Option<u32> = pid_str.parse().ok();
            let ts = pid_val
                .and_then(|pid| {
                    self.data.processes.iter().find(|p| p.pid == pid).and_then(|p| p.create_time)
                })
                .unwrap_or_else(Utc::now);

            let risk = if svc.has_suspicious_execution() { 75 } else { 55 };

            events.push(TimelineEvent {
                timestamp: ts,
                event_type: EventType::ServiceCreated,
                source_plugin: "svcscan".to_string(),
                description: format!(
                    "Suspicious service: {} ({}) [{}] → {}",
                    svc.name,
                    svc.display_name.as_deref().unwrap_or(""),
                    svc.state.as_deref().unwrap_or("?"),
                    svc.binary_path.as_deref().unwrap_or("?")
                ),
                pid: pid_val,
                process_name: Some(svc.name.clone()),
                related_ips: vec![],
                related_files: svc.binary_path.clone().into_iter().collect(),
                risk_score: risk,
            });
        }
    }

    fn add_userassist_events(&self, events: &mut Vec<TimelineEvent>) {
        for ua in &self.data.userassist {
            if let Some(ts) = ua.last_updated {
                let risk = if ua.is_executable() { 25 } else { 10 };

                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: EventType::UserAssistExecution,
                    source_plugin: "userassist".to_string(),
                    description: format!(
                        "Program executed: {} (count: {})",
                        truncate(&ua.path, 100),
                        ua.count.unwrap_or(0)
                    ),
                    pid: None,
                    process_name: None,
                    related_ips: vec![],
                    related_files: vec![ua.path.clone()],
                    risk_score: risk,
                });
            }
        }
    }

    fn add_scheduled_task_events(&self, events: &mut Vec<TimelineEvent>) {
        for record in &self.data.scheduled_task_records {
            // Parse raw JSON records for key fields
            let name = record.get("Name")
                .or_else(|| record.get("TaskName"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");

            let action = record.get("Actions")
                .or_else(|| record.get("TaskAction"))
                .or_else(|| record.get("Command"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Try to get a timestamp
            let ts_str = record.get("LastRunTime")
                .or_else(|| record.get("NextRunTime"))
                .or_else(|| record.get("Date"))
                .and_then(|v| v.as_str());

            let ts = ts_str
                .and_then(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                        .or_else(|| s.parse::<DateTime<Utc>>().ok())
                })
                .unwrap_or_else(Utc::now);

            // Risk based on action content
            let action_lower = action.to_lowercase();
            let risk = if action_lower.contains("powershell") || action_lower.contains("-enc") {
                75
            } else if action_lower.contains("cmd.exe") || action_lower.contains("wscript") {
                60
            } else if name.starts_with("\\Microsoft\\") {
                10
            } else {
                35
            };

            events.push(TimelineEvent {
                timestamp: ts,
                event_type: EventType::ScheduledTask,
                source_plugin: "scheduled_tasks".to_string(),
                description: format!(
                    "Scheduled task: {} → {}",
                    truncate(name, 60),
                    truncate(action, 80)
                ),
                pid: None,
                process_name: None,
                related_ips: vec![],
                related_files: vec![],
                risk_score: risk,
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Temporal Intelligence
// ═══════════════════════════════════════════════════════════════════════

/// A cluster of events that happened within a short time window
#[derive(Debug, Clone, serde::Serialize)]
pub struct TemporalCluster {
    /// Start of the burst window
    pub start: DateTime<Utc>,
    /// End of the burst window
    pub end: DateTime<Utc>,
    /// Number of events in this cluster
    pub event_count: usize,
    /// Events per second in this window
    pub events_per_second: f64,
    /// Maximum risk score of any event in the cluster
    pub max_risk: u8,
    /// Average risk score across events
    pub avg_risk: f64,
    /// Dominant event type in this cluster
    pub dominant_type: String,
    /// Sample descriptions from the cluster
    pub sample_events: Vec<String>,
    /// Hot-spot score (0–100) based on density + risk + diversity
    pub hotspot_score: u8,
}

/// A single time bucket for the density heatmap
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimeBucket {
    /// Bucket start time
    pub time: DateTime<Utc>,
    /// Number of events in this bucket
    pub count: usize,
    /// Average risk for events in this bucket
    pub avg_risk: f64,
    /// Whether this bucket is a hot-spot
    pub is_hotspot: bool,
}

/// Result of temporal analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct TemporalAnalysis {
    /// Detected burst clusters
    pub clusters: Vec<TemporalCluster>,
    /// Hourly density buckets for heatmap
    pub hourly_buckets: Vec<TimeBucket>,
    /// Total events analyzed
    pub total_events: usize,
    /// Time span of the timeline
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
}

/// Run temporal intelligence analysis on timeline events
pub fn analyze_temporal(events: &[TimelineEvent]) -> TemporalAnalysis {
    if events.is_empty() {
        return TemporalAnalysis {
            clusters: vec![],
            hourly_buckets: vec![],
            total_events: 0,
            earliest: None,
            latest: None,
        };
    }

    let earliest = events.first().map(|e| e.timestamp);
    let latest = events.last().map(|e| e.timestamp);

    let clusters = detect_bursts(events, 5, 10); // ≥5 events within 10 seconds
    let hourly_buckets = build_hourly_heatmap(events);

    TemporalAnalysis {
        clusters,
        hourly_buckets,
        total_events: events.len(),
        earliest,
        latest,
    }
}

/// Detect bursts of activity: ≥min_events within window_secs
fn detect_bursts(events: &[TimelineEvent], min_events: usize, window_secs: i64) -> Vec<TemporalCluster> {
    let mut clusters = Vec::new();
    let window = Duration::seconds(window_secs);
    let mut i = 0;

    while i < events.len() {
        // Sliding window: find how many events fall within window_secs of events[i]
        let start = events[i].timestamp;
        let end = start + window;

        let mut j = i;
        while j < events.len() && events[j].timestamp <= end {
            j += 1;
        }

        let count = j - i;
        if count >= min_events {
            let cluster_events = &events[i..j];
            let actual_end = cluster_events.last().map(|e| e.timestamp).unwrap_or(end);
            let duration_secs = (actual_end - start).num_milliseconds().max(1) as f64 / 1000.0;
            let events_per_second = count as f64 / duration_secs;

            let max_risk = cluster_events.iter().map(|e| e.risk_score).max().unwrap_or(0);
            let avg_risk = cluster_events.iter().map(|e| e.risk_score as f64).sum::<f64>() / count as f64;

            // Find dominant event type
            let mut type_counts: HashMap<String, usize> = HashMap::new();
            for e in cluster_events {
                *type_counts.entry(e.event_type.to_string()).or_default() += 1;
            }
            let dominant_type = type_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(t, _)| t)
                .unwrap_or_default();

            // Compute hot-spot score based on density + risk + event type diversity
            let unique_types = cluster_events.iter()
                .map(|e| std::mem::discriminant(&e.event_type))
                .collect::<std::collections::HashSet<_>>()
                .len();

            let density_score = (events_per_second * 10.0).min(40.0) as u8;
            let risk_score_component = (avg_risk as u8).min(30);
            let diversity_score = (unique_types as u8 * 5).min(30);
            let hotspot_score = (density_score + risk_score_component + diversity_score).min(100);

            let sample_events: Vec<String> = cluster_events
                .iter()
                .take(5)
                .map(|e| truncate(&e.description, 80))
                .collect();

            clusters.push(TemporalCluster {
                start,
                end: actual_end,
                event_count: count,
                events_per_second,
                max_risk,
                avg_risk,
                dominant_type,
                sample_events,
                hotspot_score,
            });

            // Skip past this cluster
            i = j;
        } else {
            i += 1;
        }
    }

    // Sort by hotspot score descending
    clusters.sort_by(|a, b| b.hotspot_score.cmp(&a.hotspot_score));
    clusters
}

/// Build hourly density heatmap
fn build_hourly_heatmap(events: &[TimelineEvent]) -> Vec<TimeBucket> {
    if events.is_empty() {
        return vec![];
    }

    let first = events.first().unwrap().timestamp;
    let last = events.last().unwrap().timestamp;

    // Build hourly buckets
    let mut buckets: Vec<TimeBucket> = Vec::new();
    let mut current = first.date_naive().and_hms_opt(first.hour() as u32, 0, 0)
        .map(|t| DateTime::<Utc>::from_naive_utc_and_offset(t, Utc))
        .unwrap_or(first);
    let hour = Duration::hours(1);

    while current <= last + hour {
        buckets.push(TimeBucket {
            time: current,
            count: 0,
            avg_risk: 0.0,
            is_hotspot: false,
        });
        current = current + hour;
    }

    // Populate counts
    for event in events {
        let bucket_idx = buckets.iter().position(|b| event.timestamp >= b.time && event.timestamp < b.time + hour);
        if let Some(idx) = bucket_idx {
            buckets[idx].count += 1;
            buckets[idx].avg_risk += event.risk_score as f64;
        }
    }

    // Finalize averages and detect hotspots
    let mean_count = if buckets.is_empty() {
        0.0
    } else {
        buckets.iter().map(|b| b.count as f64).sum::<f64>() / buckets.len() as f64
    };
    let std_dev = if buckets.len() < 2 {
        0.0
    } else {
        let variance = buckets.iter().map(|b| (b.count as f64 - mean_count).powi(2)).sum::<f64>()
            / (buckets.len() - 1) as f64;
        variance.sqrt()
    };
    let hotspot_threshold = mean_count + 2.0 * std_dev;

    for bucket in &mut buckets {
        if bucket.count > 0 {
            bucket.avg_risk /= bucket.count as f64;
        }
        bucket.is_hotspot = bucket.count as f64 > hotspot_threshold && bucket.count > 3;
    }

    // Filter out empty buckets for output efficiency
    buckets.retain(|b| b.count > 0);
    buckets
}

use chrono::Timelike;

/// Truncate a string to max length, adding ellipsis if needed
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn is_active_network_state(state: &str) -> bool {
    let state_upper = state.to_uppercase();
    state_upper.contains("ESTABLISHED")
        || state_upper.contains("CLOSE_WAIT")
        || state_upper.contains("TIME_WAIT")
        || state_upper.contains("SYN_SENT")
        || state_upper.contains("FIN_WAIT")
}

fn is_browser_process(process_lower: &str) -> bool {
    ["firefox", "chrome", "msedge", "edge", "brave", "opera", "iexplore"]
        .iter()
        .any(|p| process_lower.contains(p))
}

fn is_common_network_client(process_lower: &str) -> bool {
    [
        "firefox", "chrome", "msedge", "edge", "brave", "opera", "iexplore",
        "teams", "onedrive", "outlook", "thunderbird", "slack", "zoom", "discord",
        "svchost", "wuauclt", "usoclient", "msmpeng", "mssense", "searchapp",
        "code", "devenv", "git", "curl", "wget", "pip", "npm", "cargo",
    ]
    .iter()
    .any(|p| process_lower.contains(p))
}
