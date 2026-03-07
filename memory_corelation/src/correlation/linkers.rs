//! Data linking structures for correlation results

use crate::models::{
    browser::DownloadHistory,
    files::FileObject,
    network::NetworkConnection,
    process::ProcessInfo,
};

/// Link between a network connection and its owning process
#[derive(Debug, Clone)]
pub struct NetworkProcessLink {
    pub connection: NetworkConnection,
    pub process: Option<ProcessInfo>,
    pub cmdline: Option<String>,
}

impl NetworkProcessLink {
    pub fn is_suspicious(&self) -> bool {
        // Suspicious if external connection from unusual process
        let suspicious_ports = [4444, 5555, 6666, 1337, 31337];
        if suspicious_ports.contains(&self.connection.foreign_port) {
            return true;
        }

        // Suspicious if cmdline is encoded
        if let Some(ref cmd) = self.cmdline {
            let lower = cmd.to_lowercase();
            if lower.contains("-enc") || lower.contains("-e ") {
                return true;
            }
        }

        false
    }
}

/// Link between a download and files found in memory
#[derive(Debug, Clone)]
pub struct DownloadFileLink {
    pub download: DownloadHistory,
    pub matched_files: Vec<FileObject>,
}

impl DownloadFileLink {
    pub fn is_suspicious(&self) -> bool {
        // Downloaded executable that was accessed in memory
        self.download.is_executable() && !self.matched_files.is_empty()
    }

    pub fn file_count(&self) -> usize {
        self.matched_files.len()
    }
}

/// Link between a file and processes that accessed it
#[derive(Debug, Clone)]
pub struct FileProcessLink {
    pub file: FileObject,
    pub accessing_pids: Vec<u32>,
}

/// Suspicious parent-child process relationship
#[derive(Debug, Clone)]
pub struct ProcessChain {
    pub parent: ProcessInfo,
    pub child: ProcessInfo,
    pub cmdline: Option<String>,
    pub is_encoded: bool,
}

impl ProcessChain {
    pub fn description(&self) -> String {
        format!(
            "{} (PID:{}) → {} (PID:{}){}",
            self.parent.name,
            self.parent.pid,
            self.child.name,
            self.child.pid,
            if self.is_encoded { " [ENCODED]" } else { "" }
        )
    }

    pub fn severity(&self) -> u8 {
        let mut score: u8 = 50;

        // Higher severity for encoded commands
        if self.is_encoded {
            score += 30;
        }

        // Higher severity for certain child processes
        let child = self.child.name.to_lowercase();
        if child.contains("powershell") {
            score += 10;
        } else if child.contains("mshta") || child.contains("wscript") {
            score += 15;
        }

        score.min(100)
    }
}

/// C2 beaconing pattern detection
#[derive(Debug, Clone)]
pub struct BeaconingPattern {
    pub foreign_addr: String,
    pub foreign_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub connection_count: usize,
    pub avg_interval_secs: f64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

impl BeaconingPattern {
    /// Calculate likelihood this is actual beaconing (0-100)
    pub fn beaconing_score(&self) -> u8 {
        let mut score: f64 = 0.0;

        // Multiple connections to same destination
        if self.connection_count >= 3 {
            score += 20.0;
        }
        if self.connection_count >= 10 {
            score += 20.0;
        }

        // Regular interval (beacons tend to be periodic)
        // Typical beacon intervals: 30s, 60s, 300s, 3600s
        let common_intervals = [30.0, 60.0, 120.0, 300.0, 600.0, 3600.0];
        for &interval in &common_intervals {
            if (self.avg_interval_secs - interval).abs() < 10.0 {
                score += 30.0;
                break;
            }
        }

        // Long duration suggests persistent C2
        let duration = (self.last_seen - self.first_seen).num_hours();
        if duration >= 1 {
            score += 10.0;
        }
        if duration >= 24 {
            score += 10.0;
        }

        score.min(100.0) as u8
    }
}

/// Lateral movement indicator
#[derive(Debug, Clone)]
pub struct LateralMovementIndicator {
    pub source_process: String,
    pub source_pid: u32,
    pub target_ip: String,
    pub target_port: u16,
    pub indicator_type: LateralMovementType,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateralMovementType {
    PsExec,     // SMB + service creation
    WmiExec,    // WMI-based execution
    WinRM,      // PowerShell remoting
    RDP,        // Remote Desktop
    SSH,        // SSH connection
    SMBCopy,    // File copy over SMB
}

impl LateralMovementType {
    pub fn description(&self) -> &'static str {
        match self {
            LateralMovementType::PsExec => "PsExec-style execution via SMB",
            LateralMovementType::WmiExec => "WMI-based remote execution",
            LateralMovementType::WinRM => "PowerShell Remoting (WinRM)",
            LateralMovementType::RDP => "Remote Desktop Protocol",
            LateralMovementType::SSH => "SSH Connection",
            LateralMovementType::SMBCopy => "SMB File Transfer",
        }
    }

    pub fn from_port(port: u16) -> Option<Self> {
        match port {
            445 => Some(LateralMovementType::SMBCopy),
            135 => Some(LateralMovementType::WmiExec),
            5985 | 5986 => Some(LateralMovementType::WinRM),
            3389 => Some(LateralMovementType::RDP),
            22 => Some(LateralMovementType::SSH),
            _ => None,
        }
    }
}
