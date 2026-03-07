//! NET004 – UnusualProcessConnectionRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unusual processes making external network connections
/// Flags processes not typically expected to have network activity
pub struct UnusualProcessConnectionRule;

impl DetectionRule for UnusualProcessConnectionRule {
    fn id(&self) -> &str {
        "NET004"
    }

    fn name(&self) -> &str {
        "Unusual Process Network Activity"
    }

    fn description(&self) -> &str {
        "Detects processes that should not typically make external network connections"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1071") // Application Layer Protocol
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();

        // Processes that SHOULD have network connections
        let expected_network_procs = [
            "svchost", "firefox", "chrome", "msedge", "opera", "brave",
            "iexplore", "teams", "onedrive", "outlook", "thunderbird",
            "system", "lsass", "dns", "dhcp", "wuauclt", "msiexec",
            "bits", "searchapp", "searchui", "msmpeng", "mssense",
            "sysmon", "splunk", "elastic", "winlogbeat", "nxlog",
            "vmtoolsd", "vmwaretray", "vboxtray",
            "spoolsv", "w3wp", "sqlservr", "postgres", "mysqld",
            "dropbox", "slack", "zoom", "skype", "discord",
            "code", "code.exe", "devenv", "idea", "rider",
            "git", "curl", "wget", "pip", "npm", "cargo",
            "windowsupdate", "usoclient", "wusa",
        ];

        // Processes that are HIGHLY suspicious if they have network connections
        let never_network_procs = [
            "notepad", "calc", "mspaint", "wordpad", "write",
            "dllhost", "consent", "fontdrvhost", "dwm",
            "taskmgr", "regedit", "mmc",
        ];

        for conn in &data.connections {
            if !conn.is_external() {
                continue;
            }

            let owner = conn.owner.as_deref().unwrap_or("?");
            let lower_owner = owner.to_lowercase();

            // Skip already-reported PIDs
            if seen.contains(&conn.pid) {
                continue;
            }

            // Check if this is an unexpected network process
            let is_expected = expected_network_procs.iter()
                .any(|p| lower_owner.contains(p));
            let is_never = never_network_procs.iter()
                .any(|p| lower_owner.contains(p));

            if is_expected && !is_never {
                continue;
            }

            seen.insert(conn.pid);

            let severity = if is_never {
                Severity::Critical
            } else {
                Severity::High
            };

            let state = conn.state.as_deref().unwrap_or("UNKNOWN");

            let mut finding = create_finding(
                self,
                format!("Unusual network activity: {} → {}:{}",
                    owner, conn.foreign_addr, conn.foreign_port),
                format!(
                    "Process '{}' (PID {}) has an external network connection to {}:{} [{}]. \
                    This process is not typically expected to have network activity, which may \
                    indicate C2 communication or data exfiltration.",
                    owner, conn.pid, conn.foreign_addr, conn.foreign_port, state
                ),
                vec![Evidence {
                    source_plugin: "netscan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("{} {}:{} → {}:{} [{}]",
                        conn.protocol, conn.local_addr, conn.local_port,
                        conn.foreign_addr, conn.foreign_port, state),
                }],
            );
            finding.severity = severity;
            finding.related_pids = vec![conn.pid];
            finding.related_ips = vec![conn.foreign_addr.clone()];
            finding.timestamp = conn.created;
            finding.confidence = if is_never { 0.95 } else { 0.75 };
            findings.push(finding);
        }

        findings
    }
}
