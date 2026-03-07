//! Timeline builder for unified event view

use chrono::{DateTime, Utc};

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

                let risk = if conn.is_suspicious_port() {
                    60
                } else if is_external {
                    30
                } else {
                    10
                };

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
}

/// Truncate a string to max length, adding ellipsis if needed
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
