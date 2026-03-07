//! NET005 – ListeningPortAnalysisRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unusual listening ports that may indicate backdoors or C2 servers
pub struct ListeningPortAnalysisRule;

impl DetectionRule for ListeningPortAnalysisRule {
    fn id(&self) -> &str {
        "NET005"
    }

    fn name(&self) -> &str {
        "Listening Port Analysis"
    }

    fn description(&self) -> &str {
        "Detects unusual listening ports that may indicate backdoors or reverse shells"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1571") // Non-Standard Port
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<(u32, u16)> = HashSet::new(); // (pid, port)

        // Well-known service ports that are expected
        let expected_ports: HashSet<u16> = [
            21, 22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445,
            464, 465, 587, 636, 993, 995, 1433, 1434, 3306, 3389, 5432,
            5985, 5986, 8080, 8443, 9200, 49664, 49665, 49666, 49667,
            49668, 49669, 49670,
        ].iter().cloned().collect();

        // Known suspicious backdoor ports
        let backdoor_ports: HashSet<u16> = [
            4444, 5555, 6666, 7777, 8888, 1337, 31337, 12345, 54321,
            1234, 9999, 6667, 6668, 6669, // IRC for C2
            4443, 8443, 8880, 2222, // Alternative SSL/SSH
        ].iter().cloned().collect();

        // Processes expected to listen
        let expected_listeners = [
            "system", "svchost", "lsass", "services", "spoolsv",
            "dns", "httpd", "nginx", "apache", "iis",
            "sqlservr", "postgres", "mysqld",
            "vmtoolsd", "vmwaretray",
        ];

        for conn in &data.connections {
            if !conn.is_listening() {
                continue;
            }

            let port = conn.local_port;
            let owner = conn.owner.as_deref().unwrap_or("?");
            let lower_owner = owner.to_lowercase();

            // Skip already seen
            if seen.contains(&(conn.pid, port)) {
                continue;
            }
            seen.insert((conn.pid, port));

            // Check: is this a backdoor port?
            if backdoor_ports.contains(&port) {
                let mut finding = create_finding(
                    self,
                    format!("Suspicious listening port: {} on port {}", owner, port),
                    format!(
                        "Process '{}' (PID {}) is listening on port {} which is commonly \
                        used by backdoors and C2 frameworks.",
                        owner, conn.pid, port
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} {}:{} LISTENING", conn.protocol, conn.local_addr, port),
                    }],
                );
                finding.severity = Severity::High;
                finding.related_pids = vec![conn.pid];
                finding.confidence = 0.85;
                findings.push(finding);
                continue;
            }

            // Check: unexpected process listening on any port
            let is_expected_listener = expected_listeners.iter()
                .any(|p| lower_owner.contains(p));

            if !is_expected_listener && !expected_ports.contains(&port) {
                let mut finding = create_finding(
                    self,
                    format!("Unusual listener: {} on port {}", owner, port),
                    format!(
                        "Process '{}' (PID {}) is listening on non-standard port {}. \
                        This may indicate a backdoor, reverse shell, or unauthorized service.",
                        owner, conn.pid, port
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} {}:{} LISTENING", conn.protocol, conn.local_addr, port),
                    }],
                );
                finding.severity = Severity::Medium;
                finding.related_pids = vec![conn.pid];
                finding.confidence = 0.60;
                findings.push(finding);
            }
        }

        findings
    }
}
