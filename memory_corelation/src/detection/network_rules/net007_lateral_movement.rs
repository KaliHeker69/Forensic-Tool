//! NET007 – Lateral Movement Detection Rule
//!
//! Detects lateral movement patterns by correlating network connections with
//! processes and services. Identifies PsExec, WMI, WinRM, RDP, and SSH-based
//! lateral movement from both inbound and outbound perspectives.

use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect lateral movement indicators
pub struct LateralMovementDetectionRule;

impl DetectionRule for LateralMovementDetectionRule {
    fn id(&self) -> &str {
        "NET007"
    }

    fn name(&self) -> &str {
        "Lateral Movement Detection"
    }

    fn description(&self) -> &str {
        "Detects lateral movement patterns including PsExec, WMI, WinRM, RDP, and SSH"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1021,T1570") // Remote Services, Lateral Tool Transfer
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ── PsExec Detection ─────────────────────────────────────────
        // PsExec pattern: SMB (445) + service creation + cmd/powershell child
        self.detect_psexec(data, &mut findings);

        // ── WMI-based Execution ──────────────────────────────────────
        // WMI pattern: DCOM (135) + WmiPrvSE.exe + child processes
        self.detect_wmi_exec(data, &mut findings);

        // ── WinRM / PowerShell Remoting ──────────────────────────────
        // WinRM pattern: 5985/5986 + wsmprovhost.exe
        self.detect_winrm(data, &mut findings);

        // ── RDP Lateral Movement ─────────────────────────────────────
        // RDP from unusual processes or to/from unexpected hosts
        self.detect_rdp(data, &mut findings);

        // ── General Port-based Pattern Detection ─────────────────────
        self.detect_port_patterns(data, &mut findings);

        findings
    }
}

impl LateralMovementDetectionRule {
    fn detect_psexec(&self, data: &ParsedData, findings: &mut Vec<Finding>) {
        // Check for services.exe spawning cmd.exe/powershell (PsExec indicator)
        let services_pids: Vec<u32> = data
            .processes
            .iter()
            .filter(|p| p.name.to_lowercase() == "services.exe")
            .map(|p| p.pid)
            .collect();

        for proc in &data.processes {
            let proc_lower = proc.name.to_lowercase();
            let is_shell = proc_lower == "cmd.exe"
                || proc_lower.contains("powershell")
                || proc_lower == "psexesvc.exe";

            if !is_shell {
                continue;
            }

            // Check if parent is services.exe (dead giveaway of PsExec)
            if services_pids.contains(&proc.ppid) {
                let mut evidence = vec![Evidence {
                    source_plugin: "pslist/pstree".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "services.exe (PID:{}) → {} (PID:{})",
                        proc.ppid, proc.name, proc.pid
                    ),
                }];

                // Check for PSEXESVC service
                for svc in &data.services {
                    let svc_name = svc.name.to_lowercase();
                    if svc_name.contains("psexe") || svc_name.contains("paexe") {
                        evidence.push(Evidence {
                            source_plugin: "svcscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "PsExec service: {} ({})",
                                svc.name,
                                svc.binary_path.as_deref().unwrap_or("?")
                            ),
                        });
                    }
                }

                // Check for SMB connections
                for conn in &data.connections {
                    if conn.foreign_port == 445 || conn.local_port == 445 {
                        evidence.push(Evidence {
                            source_plugin: "netscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "SMB connection: {}:{} → {}:{}",
                                conn.local_addr, conn.local_port,
                                conn.foreign_addr, conn.foreign_port
                            ),
                        });
                    }
                }

                let mut finding = create_finding(
                    self,
                    format!("PsExec lateral movement: services.exe → {}", proc.name),
                    format!(
                        "Detected PsExec-style execution: services.exe spawned {} (PID:{}). \
                         This is a classic lateral movement pattern where a remote attacker \
                         uses PsExec to execute commands via the SCM.",
                        proc.name, proc.pid
                    ),
                    evidence,
                );
                finding.severity = Severity::Critical;
                finding.confidence = 0.95;
                finding.related_pids = vec![proc.ppid, proc.pid];
                finding.mitre_attack = Some("T1021.002,T1569.002".to_string());
                findings.push(finding);
            }
        }
    }

    fn detect_wmi_exec(&self, data: &ParsedData, findings: &mut Vec<Finding>) {
        // WMI execution: WmiPrvSE.exe spawning suspicious children
        let wmiprvse_pids: Vec<u32> = data
            .processes
            .iter()
            .filter(|p| p.name.to_lowercase().contains("wmiprvse"))
            .map(|p| p.pid)
            .collect();

        if wmiprvse_pids.is_empty() {
            return;
        }

        for proc in &data.processes {
            if !wmiprvse_pids.contains(&proc.ppid) {
                continue;
            }

            let proc_lower = proc.name.to_lowercase();
            let suspicious = proc_lower == "cmd.exe"
                || proc_lower.contains("powershell")
                || proc_lower == "mshta.exe"
                || proc_lower == "wscript.exe"
                || proc_lower == "cscript.exe"
                || proc_lower == "rundll32.exe";

            if !suspicious {
                continue;
            }

            let cmdline = data
                .cmdlines
                .iter()
                .find(|c| c.pid == proc.pid)
                .map(|c| c.args.clone());

            let mut evidence = vec![Evidence {
                source_plugin: "pslist/pstree".to_string(),
                source_file: String::new(),
                line_number: None,
                data: format!(
                    "WmiPrvSE.exe (PID:{}) → {} (PID:{})",
                    proc.ppid, proc.name, proc.pid
                ),
            }];

            if let Some(ref cmd) = cmdline {
                evidence.push(Evidence {
                    source_plugin: "cmdline".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("CmdLine: {}", cmd),
                });
            }

            // Check for DCOM connections (port 135)
            for conn in &data.connections {
                if (conn.foreign_port == 135 || conn.local_port == 135)
                    && conn.is_external()
                {
                    evidence.push(Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "DCOM connection: {}:{} → {}:{}",
                            conn.local_addr, conn.local_port,
                            conn.foreign_addr, conn.foreign_port
                        ),
                    });
                }
            }

            let mut finding = create_finding(
                self,
                format!("WMI lateral movement: WmiPrvSE → {}", proc.name),
                format!(
                    "WmiPrvSE.exe spawned suspicious child process {} (PID:{}). \
                     This indicates WMI-based remote execution, commonly used for \
                     lateral movement and remote code execution.",
                    proc.name, proc.pid
                ),
                evidence,
            );
            finding.severity = Severity::Critical;
            finding.confidence = 0.9;
            finding.related_pids = vec![proc.ppid, proc.pid];
            finding.mitre_attack = Some("T1047".to_string());
            findings.push(finding);
        }
    }

    fn detect_winrm(&self, data: &ParsedData, findings: &mut Vec<Finding>) {
        // WinRM: wsmprovhost.exe spawning shells, or connections on 5985/5986
        let wsmprov_pids: Vec<u32> = data
            .processes
            .iter()
            .filter(|p| p.name.to_lowercase().contains("wsmprovhost"))
            .map(|p| p.pid)
            .collect();

        // wsmprovhost.exe existence itself is notable
        for prov_pid in &wsmprov_pids {
            let proc = data.processes.iter().find(|p| p.pid == *prov_pid);
            if let Some(proc) = proc {
                let mut evidence = vec![Evidence {
                    source_plugin: "pslist".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("WinRM host process: {} (PID:{})", proc.name, proc.pid),
                }];

                // Check for child processes
                for child in &data.processes {
                    if child.ppid == *prov_pid {
                        evidence.push(Evidence {
                            source_plugin: "pstree".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "Child: {} (PID:{})",
                                child.name, child.pid
                            ),
                        });
                    }
                }

                let mut finding = create_finding(
                    self,
                    format!("WinRM session detected (PID:{})", prov_pid),
                    format!(
                        "Active WinRM/PowerShell remoting session detected via wsmprovhost.exe (PID:{}). \
                         This indicates remote PowerShell execution, commonly used for lateral movement.",
                        prov_pid
                    ),
                    evidence,
                );
                finding.severity = Severity::High;
                finding.confidence = 0.85;
                finding.related_pids = vec![*prov_pid];
                finding.mitre_attack = Some("T1021.006".to_string());
                findings.push(finding);
            }
        }

        // Also check for WinRM port connections from unusual processes
        for conn in &data.connections {
            if conn.foreign_port != 5985 && conn.foreign_port != 5986 {
                continue;
            }
            if !conn.is_external() {
                continue;
            }

            let process_name = conn.owner.as_deref().unwrap_or("?");

            let mut finding = create_finding(
                self,
                format!("WinRM connection: {} → {}:{}", process_name, conn.foreign_addr, conn.foreign_port),
                format!(
                    "Process {} (PID:{}) connecting to remote WinRM service at {}:{}",
                    process_name, conn.pid, conn.foreign_addr, conn.foreign_port
                ),
                vec![Evidence {
                    source_plugin: "netscan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "{} → {}:{}",
                        conn.local_endpoint(),
                        conn.foreign_addr,
                        conn.foreign_port
                    ),
                }],
            );
            finding.severity = Severity::High;
            finding.confidence = 0.8;
            finding.related_pids = vec![conn.pid];
            finding.related_ips = vec![conn.foreign_addr.clone()];
            finding.mitre_attack = Some("T1021.006".to_string());
            findings.push(finding);
        }
    }

    fn detect_rdp(&self, data: &ParsedData, findings: &mut Vec<Finding>) {
        // Check for RDP connections (3389) from non-standard processes
        for conn in &data.connections {
            if conn.foreign_port != 3389 && conn.local_port != 3389 {
                continue;
            }
            if !conn.is_external() {
                continue;
            }

            let process_name = conn.owner.as_deref().unwrap_or("?");
            let proc_lower = process_name.to_lowercase();

            // Skip known RDP processes
            if proc_lower.contains("mstsc") || proc_lower.contains("rdpclip") || proc_lower == "svchost.exe" {
                continue;
            }

            let is_inbound = conn.local_port == 3389;
            let direction = if is_inbound { "Inbound" } else { "Outbound" };

            let mut finding = create_finding(
                self,
                format!("{} RDP: {} ↔ {}:{}", direction, process_name, conn.foreign_addr, 3389),
                format!(
                    "{} RDP connection involving process {} (PID:{}) with {}. \
                     Non-standard RDP process may indicate tunneled or hijacked RDP session.",
                    direction, process_name, conn.pid, conn.foreign_addr
                ),
                vec![Evidence {
                    source_plugin: "netscan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "{} {}:{} ↔ {}:{} [PID:{}]",
                        conn.protocol, conn.local_addr, conn.local_port,
                        conn.foreign_addr, conn.foreign_port, conn.pid
                    ),
                }],
            );
            finding.severity = Severity::Medium;
            finding.confidence = 0.7;
            finding.related_pids = vec![conn.pid];
            finding.related_ips = vec![conn.foreign_addr.clone()];
            finding.mitre_attack = Some("T1021.001".to_string());
            findings.push(finding);
        }
    }

    fn detect_port_patterns(&self, data: &ParsedData, findings: &mut Vec<Finding>) {
        // Detect SSH connections from Windows processes (unusual)
        for conn in &data.connections {
            if conn.foreign_port == 22 && conn.is_external() {
                let process_name = conn.owner.as_deref().unwrap_or("?");
                let proc_lower = process_name.to_lowercase();

                // Skip known SSH clients
                if proc_lower.contains("ssh") || proc_lower.contains("putty") || proc_lower.contains("openssh") {
                    continue;
                }

                let mut finding = create_finding(
                    self,
                    format!("SSH connection from {}: → {}:22", process_name, conn.foreign_addr),
                    format!(
                        "Process {} (PID:{}) connecting to SSH service at {}:22. \
                         SSH from a non-SSH client may indicate tunneling or exfiltration.",
                        process_name, conn.pid, conn.foreign_addr
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "{} → {}:22 [PID:{}]",
                            conn.local_endpoint(), conn.foreign_addr, conn.pid
                        ),
                    }],
                );
                finding.severity = Severity::Medium;
                finding.confidence = 0.6;
                finding.related_pids = vec![conn.pid];
                finding.related_ips = vec![conn.foreign_addr.clone()];
                finding.mitre_attack = Some("T1021.004".to_string());
                findings.push(finding);
            }
        }
    }
}
