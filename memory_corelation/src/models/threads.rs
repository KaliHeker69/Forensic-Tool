//! Thread-related data models for thrdscan plugin

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ProcessAssociated, Timestamped};

/// Thread information from thrdscan plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Process ID owning this thread
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Thread ID
    #[serde(alias = "TID", alias = "Tid")]
    pub tid: u32,

    /// Thread creation time
    #[serde(alias = "CreateTime", alias = "create_time")]
    pub create_time: Option<DateTime<Utc>>,

    /// Thread exit time (1600 date = still active)
    #[serde(alias = "ExitTime", alias = "exit_time")]
    pub exit_time: Option<DateTime<Utc>>,

    /// Memory offset
    #[serde(alias = "Offset", alias = "offset")]
    pub offset: Option<u64>,

    /// Kernel start address
    #[serde(alias = "StartAddress", alias = "start_address")]
    pub start_address: Option<u64>,

    /// Module path for kernel start address
    #[serde(alias = "StartPath", alias = "start_path")]
    pub start_path: Option<String>,

    /// User-mode (Win32) start address
    #[serde(alias = "Win32StartAddress", alias = "win32_start_address")]
    pub win32_start_address: Option<u64>,

    /// Module path for user-mode start address
    #[serde(alias = "Win32StartPath", alias = "win32_start_path")]
    pub win32_start_path: Option<String>,
}

impl ThreadInfo {
    /// Check if thread is still active (ExitTime is 1600 epoch or null)
    pub fn is_active(&self) -> bool {
        match &self.exit_time {
            Some(exit_time) => {
                // Check if exit time is the epoch placeholder (year 1600)
                exit_time.format("%Y").to_string().starts_with("1600")
            }
            None => true,
        }
    }

    /// Check if thread has no backing module (potential shellcode/injection)
    pub fn is_orphaned(&self) -> bool {
        self.start_path.is_none() && self.win32_start_path.is_none()
    }

    /// Check if thread starts in a suspicious path
    pub fn has_suspicious_start_path(&self) -> bool {
        let suspicious_patterns = [
            "\\temp\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\downloads\\",
        ];

        let check_path = |path: &Option<String>| -> bool {
            path.as_ref()
                .map(|p| {
                    let lower = p.to_lowercase();
                    suspicious_patterns.iter().any(|pat| lower.contains(pat))
                })
                .unwrap_or(false)
        };

        check_path(&self.start_path) || check_path(&self.win32_start_path)
    }

    /// Get the effective start path (Win32 preferred over kernel)
    pub fn effective_start_path(&self) -> Option<&str> {
        self.win32_start_path
            .as_deref()
            .or(self.start_path.as_deref())
    }

    /// Check if this appears to be a system thread (PID 4)
    pub fn is_system_thread(&self) -> bool {
        self.pid == 4
    }

    /// Check if thread module matches expected Windows system DLLs
    pub fn is_standard_system_module(&self) -> bool {
        let system_modules = [
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "gdi32.dll",
            "msvcrt.dll",
            "combase.dll",
            "rpcrt4.dll",
            "sechost.dll",
            "advapi32.dll",
        ];

        self.effective_start_path()
            .map(|p| {
                let lower = p.to_lowercase();
                system_modules.iter().any(|m| lower.contains(m))
            })
            .unwrap_or(false)
    }
}

impl ProcessAssociated for ThreadInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        None // Thread doesn't store process name directly
    }
}

impl Timestamped for ThreadInfo {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.create_time
    }
}

/// Summary of thread analysis for a process
#[derive(Debug, Clone, Serialize)]
pub struct ThreadSummary {
    pub pid: u32,
    pub process_name: String,
    pub total_threads: usize,
    pub active_threads: usize,
    pub orphaned_threads: usize,
    pub suspicious_path_threads: usize,
    pub threads_in_suspicious_regions: Vec<u32>, // TIDs
    pub risk_score: u8,
}

impl ThreadSummary {
    pub fn calculate_risk_score(&mut self) {
        let mut score: u16 = 0;

        // Orphaned threads are highly suspicious
        score += (self.orphaned_threads as u16).min(5) * 25;
        
        // Suspicious path threads
        score += (self.suspicious_path_threads as u16).min(3) * 15;
        
        // Threads in suspicious memory regions
        score += (self.threads_in_suspicious_regions.len() as u16).min(3) * 30;

        self.risk_score = score.min(100) as u8;
    }
}
