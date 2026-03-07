//! INJ006 – MalfindStringExtractionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Extract and flag suspicious strings from malfind hexdump/disassembly
pub struct MalfindStringExtractionRule;

impl DetectionRule for MalfindStringExtractionRule {
    fn id(&self) -> &str {
        "INJ006"
    }

    fn name(&self) -> &str {
        "Malfind Suspicious String Extraction"
    }

    fn description(&self) -> &str {
        "Extracts and analyzes strings from malfind memory regions for IOCs and shellcode patterns"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055") // Process Injection
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mal in &data.malfind {
            let mut iocs = Vec::new();

            // Analyze hexdump for ASCII strings
            if let Some(ref hexdump) = mal.hexdump {
                let ascii_strings = extract_ascii_from_hex(hexdump);
                for s in &ascii_strings {
                    if is_suspicious_string(s) {
                        iocs.push(format!("String: \"{}\"", s));
                    }
                }
            }

            // Analyze disassembly for suspicious instructions
            if let Some(ref disasm) = mal.disasm {
                let disasm_indicators = analyze_disasm(disasm);
                iocs.extend(disasm_indicators);
            }

            // Check Notes field for Volatility's own analysis
            // Volatility marks MZ headers, etc.
            // (already handled by other rules, but worth noting)

            if !iocs.is_empty() {
                let severity = if iocs.iter().any(|s| s.contains("API:") || s.contains("URL:")) {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let mut finding = create_finding(
                    self,
                    format!("Suspicious strings in {} (PID:{}) memory",
                        mal.process, mal.pid),
                    format!(
                        "Extracted {} suspicious indicators from injected memory in {} (PID {}) at {}:\n{}",
                        iocs.len(), mal.process, mal.pid, mal.start,
                        iocs.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
                    ),
                    vec![Evidence {
                        source_plugin: "malfind".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: iocs.iter().take(5).cloned().collect::<Vec<_>>().join(" | "),
                    }],
                );
                finding.severity = severity;
                finding.related_pids = vec![mal.pid];
                finding.confidence = 0.85;
                findings.push(finding);
            }
        }

        findings
    }
}

/// Extract printable ASCII strings from space-separated hex dump
fn extract_ascii_from_hex(hex: &str) -> Vec<String> {
    let bytes: Vec<u8> = hex.split_whitespace()
        .filter_map(|h| u8::from_str_radix(h.trim(), 16).ok())
        .collect();

    let mut strings = Vec::new();
    let mut current = String::new();

    for &b in &bytes {
        if b >= 0x20 && b < 0x7F {
            current.push(b as char);
        } else {
            if current.len() >= 4 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push(current);
    }

    strings
}

/// Check if a string extracted from memory is suspicious
fn is_suspicious_string(s: &str) -> bool {
    let lower = s.to_lowercase();

    // Windows API calls commonly used by shellcode/injectors
    let suspicious_apis = [
        "virtualalloc", "virtualprotect", "writeprocessmemory",
        "createremotethread", "ntcreatethreadex", "loadlibrary",
        "getprocaddress", "createprocess", "winexec", "shellexecute",
        "urldownloadtofile", "internetopen", "httpsendrequestw",
        "rtlcreateuserthread", "zwunmapviewofsection",
        "ntqueueapcthread", "setthreadcontext",
    ];

    // Network indicators
    let network_patterns = [
        "http://", "https://", "ftp://",
        "cmd.exe", "powershell", "wscript",
        ".onion", "pastebin", "discord",
    ];

    // Check for API calls
    if suspicious_apis.iter().any(|api| lower.contains(api)) {
        return true;
    }

    // Check for network patterns
    if network_patterns.iter().any(|p| lower.contains(p)) {
        return true;
    }

    // Check for base64-like encoded strings (long alphanumeric blocks)
    if s.len() > 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return true;
    }

    false
}

/// Analyze disassembly for suspicious instruction patterns
fn analyze_disasm(disasm: &str) -> Vec<String> {
    let mut indicators = Vec::new();

    // Common shellcode patterns in disassembly
    if disasm.contains("call") && disasm.contains("pop") {
        // GetPC technique (call $+5; pop reg)
        indicators.push("Pattern: GetPC shellcode technique (call/pop)".to_string());
    }

    // NOP sled detection
    let nop_count = disasm.matches("nop").count();
    if nop_count > 5 {
        indicators.push(format!("Pattern: NOP sled detected ({} NOPs)", nop_count));
    }

    // syscall/int 0x80 (direct system calls - evasion technique)
    if disasm.contains("syscall") || disasm.contains("int\t0x80") || disasm.contains("int\t0x2e") {
        indicators.push("Pattern: Direct syscall (evasion technique)".to_string());
    }

    indicators
}
