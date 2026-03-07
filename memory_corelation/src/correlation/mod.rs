//! Correlation engine for linking artifacts across plugins

pub mod forensic_extractor;
pub mod linkers;
pub mod timeline;

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::models::process::ProcessTreeNode;
use crate::models::{EventType, TimelineEvent};
use crate::parsers::ParsedData;

pub use forensic_extractor::{extract_analyst_quickview, extract_system_profile, extract_user_activity};
pub use linkers::{
    DownloadFileLink, FileProcessLink, NetworkProcessLink, ProcessChain,
};
pub use timeline::TimelineBuilder;

/// Main correlation engine for linking artifacts
pub struct CorrelationEngine<'a> {
    data: &'a ParsedData,
    process_map: HashMap<u32, usize>, // PID -> index in processes
    time_window: Duration,
}

impl<'a> CorrelationEngine<'a> {
    pub fn new(data: &'a ParsedData, time_window_secs: i64) -> Self {
        let mut process_map = HashMap::new();
        for (i, proc) in data.processes.iter().enumerate() {
            process_map.insert(proc.pid, i);
        }

        Self {
            data,
            process_map,
            time_window: Duration::seconds(time_window_secs),
        }
    }

    /// Build a process tree from pslist/pstree data
    pub fn build_process_tree(&self) -> Vec<ProcessTreeNode> {
        let mut children_map: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut root_indices = Vec::new();

        // Map parent -> children
        for (idx, proc) in self.data.processes.iter().enumerate() {
            if proc.ppid == 0 || !self.process_map.contains_key(&proc.ppid) {
                root_indices.push(idx);
            } else {
                children_map.entry(proc.ppid).or_default().push(idx);
            }
        }

        // Build tree recursively
        let mut roots = Vec::new();
        for idx in root_indices {
            let node = self.build_tree_node(idx, &children_map, 0);
            roots.push(node);
        }
        roots
    }

    fn build_tree_node(
        &self,
        idx: usize,
        children_map: &HashMap<u32, Vec<usize>>,
        depth: usize,
    ) -> ProcessTreeNode {
        let proc = &self.data.processes[idx];
        let mut node = ProcessTreeNode::new(proc.clone(), depth);

        // Find cmdline for this process
        node.cmdline = self
            .data
            .cmdlines
            .iter()
            .find(|c| c.pid == proc.pid)
            .map(|c| c.args.clone());

        // Add children
        if let Some(child_indices) = children_map.get(&proc.pid) {
            for &child_idx in child_indices {
                node.children.push(self.build_tree_node(child_idx, children_map, depth + 1));
            }
        }

        node
    }

    /// Build ProcessNode instances with full genealogy information
    /// Uses deduplicated processes by PID to avoid duplicate findings
    pub fn build_process_nodes(&self) -> Vec<crate::models::process::ProcessNode> {
        use crate::models::process::ProcessNode;
        use std::collections::HashMap;

        let mut nodes = Vec::new();

        // Deduplicate processes by PID - prefer pslist source, then psscan, then pstree
        // This ensures each PID only appears once in the analysis
        let mut unique_procs: HashMap<u32, &crate::models::process::ProcessInfo> = HashMap::new();
        for proc in &self.data.processes {
            unique_procs.entry(proc.pid).or_insert(proc);
        }

        // Build PID -> name map for parent lookup
        let pid_map: HashMap<u32, String> = unique_procs
            .values()
            .map(|p| (p.pid, p.name.clone()))
            .collect();

        // Build children map (using unique PIDs)
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        for proc in unique_procs.values() {
            children_map
                .entry(proc.ppid)
                .or_default()
                .push(proc.pid);
        }
        // Deduplicate children lists
        for children in children_map.values_mut() {
            children.sort();
            children.dedup();
        }

        // Create nodes from unique processes only
        for proc in unique_procs.values() {
            let parent_name = pid_map.get(&proc.ppid).cloned();
            let mut node = ProcessNode::from_process_info(proc, parent_name);

            // Add cmdline
            node.cmdline = self
                .data
                .cmdlines
                .iter()
                .find(|c| c.pid == proc.pid)
                .map(|c| c.args.clone());

            // Add children
            if let Some(children) = children_map.get(&proc.pid) {
                node.children_pids = children.clone();
            }

            // Calculate depth (simplified - just count to root)
            node.depth = self.calculate_depth(proc.pid, &pid_map, 0);

            nodes.push(node);
        }

        nodes
    }

    fn calculate_depth(&self, pid: u32, pid_map: &HashMap<u32, String>, current_depth: usize) -> usize {
        if current_depth > 50 {
            // Prevent infinite loops in broken trees
            return current_depth;
        }

        if let Some(&idx) = self.process_map.get(&pid) {
            let proc = &self.data.processes[idx];
            if proc.ppid == 0 || !self.process_map.contains_key(&proc.ppid) {
                return current_depth;
            }
            return self.calculate_depth(proc.ppid, pid_map, current_depth + 1);
        }
        current_depth
    }


    /// Find hidden processes (in psscan but not pslist)
    /// Requires separate parsing of psscan output
    pub fn find_orphaned_processes(&self) -> Vec<&crate::models::process::ProcessInfo> {
        self.data
            .processes
            .iter()
            .filter(|p| {
                p.ppid != 0 && p.ppid != 4 && !self.process_map.contains_key(&p.ppid)
            })
            .collect()
    }

    /// Correlate network connections with processes
    pub fn network_process_correlation(&self) -> Vec<NetworkProcessLink> {
        self.data
            .connections
            .iter()
            .filter(|conn| conn.is_external())
            .filter_map(|conn| {
                let proc = self.process_map.get(&conn.pid).map(|&i| &self.data.processes[i]);
                let cmdline = self.data.cmdlines.iter().find(|c| c.pid == conn.pid);

                Some(NetworkProcessLink {
                    connection: conn.clone(),
                    process: proc.cloned(),
                    cmdline: cmdline.map(|c| c.args.clone()),
                })
            })
            .collect()
    }

    /// Match browser downloads with filescan entries
    pub fn download_file_correlation(&self) -> Vec<DownloadFileLink> {
        let mut links = Vec::new();

        for download in &self.data.downloads {
            let filename = download.filename().to_lowercase();

            // Find matching files
            let matched_files: Vec<_> = self
                .data
                .files
                .iter()
                .filter(|f| f.filename().to_lowercase() == filename)
                .collect();

            if !matched_files.is_empty() {
                links.push(DownloadFileLink {
                    download: download.clone(),
                    matched_files: matched_files.into_iter().cloned().collect(),
                });
            }
        }

        links
    }

    /// Find browser visits followed by network connections (within time window)
    pub fn browser_network_correlation(&self) -> Vec<TimelineEvent> {
        let mut events = Vec::new();

        for history in &self.data.browser_history {
            if let Some(domain) = history.domain() {
                // Find network connections close in time to this visit
                for conn in &self.data.connections {
                    if let Some(conn_time) = conn.created {
                        let time_diff = (conn_time - history.timestamp).num_seconds().abs();
                        
                        if time_diff <= self.time_window.num_seconds() {
                            // Check if foreign address matches the domain
                            if conn.foreign_addr.contains(domain) || domain.contains(&conn.foreign_addr) {
                                events.push(TimelineEvent {
                                    timestamp: history.timestamp,
                                    event_type: EventType::BrowserVisit,
                                    source_plugin: "browser_history+netscan".to_string(),
                                    description: format!(
                                        "Browser visit to {} followed by connection to {}:{} (Δ{}s)",
                                        domain,
                                        conn.foreign_addr,
                                        conn.foreign_port,
                                        time_diff
                                    ),
                                    pid: Some(conn.pid),
                                    process_name: conn.owner.clone(),
                                    related_ips: vec![conn.foreign_addr.clone()],
                                    related_files: vec![],
                                    risk_score: if history.is_suspicious_url() { 70 } else { 30 },
                                });
                            }
                        }
                    }
                }
            }
        }

        events
    }

    /// Find suspicious parent-child relationships
    pub fn find_suspicious_parent_child(&self) -> Vec<ProcessChain> {
        let mut chains = Vec::new();

        // Define suspicious parent-child patterns
        let suspicious_parents = [
            ("winword.exe", vec!["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
            ("excel.exe", vec!["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
            ("outlook.exe", vec!["cmd.exe", "powershell.exe"]),
            ("powerpoint.exe", vec!["cmd.exe", "powershell.exe"]),
            ("explorer.exe", vec!["mshta.exe", "rundll32.exe"]),
        ];

        for proc in &self.data.processes {
            let proc_name_lower = proc.name.to_lowercase();
            
            if let Some(&parent_idx) = self.process_map.get(&proc.ppid) {
                let parent = &self.data.processes[parent_idx];
                let parent_name_lower = parent.name.to_lowercase();

                for (sus_parent, sus_children) in &suspicious_parents {
                    if parent_name_lower.contains(sus_parent) {
                        if sus_children.iter().any(|c| proc_name_lower.contains(c)) {
                            let cmdline = self
                                .data
                                .cmdlines
                                .iter()
                                .find(|c| c.pid == proc.pid)
                                .map(|c| c.args.clone());

                            chains.push(ProcessChain {
                                parent: parent.clone(),
                                child: proc.clone(),
                                cmdline,
                                is_encoded: self
                                    .data
                                    .cmdlines
                                    .iter()
                                    .find(|c| c.pid == proc.pid)
                                    .map(|c| c.is_encoded())
                                    .unwrap_or(false),
                            });
                        }
                    }
                }
            }
        }

        chains
    }

    /// Find processes with encoded command lines
    pub fn find_encoded_cmdlines(&self) -> Vec<&crate::models::process::CommandLine> {
        self.data
            .cmdlines
            .iter()
            .filter(|c| c.is_encoded() || c.has_suspicious_flags())
            .collect()
    }

    /// Correlate malfind results with process info
    pub fn injection_analysis(&self) -> Vec<crate::models::malware::InjectionSummary> {
        use crate::models::malware::InjectionSummary;
        use std::collections::HashMap;

        let mut by_pid: HashMap<u32, Vec<_>> = HashMap::new();
        for mal in &self.data.malfind {
            by_pid.entry(mal.pid).or_default().push(mal);
        }

        let mut summaries = Vec::new();
        for (pid, malfind_results) in by_pid {
            let process_name = malfind_results
                .first()
                .map(|m| m.process.clone())
                .unwrap_or_default();

            let rwx_count = malfind_results.iter().filter(|m| m.is_rwx()).count();
            let mz_count = malfind_results.iter().filter(|m| m.has_mz_header()).count();
            let shellcode_count = malfind_results.iter().filter(|m| m.has_shellcode_patterns()).count();

            // Count suspicious VADs for this PID
            let sus_vads = self
                .data
                .vads
                .iter()
                .filter(|v| v.pid == pid && v.is_potential_injection())
                .count();

            // Get YARA matches
            let yara: Vec<_> = self
                .data
                .yara_matches
                .iter()
                .filter(|y| {
                    y.owner
                        .as_ref()
                        .map(|o| o.to_lowercase().contains(&process_name.to_lowercase()))
                        .unwrap_or(false)
                })
                .map(|y| y.rule.clone())
                .collect();

            let mut summary = InjectionSummary {
                pid,
                process_name,
                malfind_count: malfind_results.len(),
                rwx_regions: rwx_count,
                mz_headers_found: mz_count,
                shellcode_patterns: shellcode_count,
                suspicious_vads: sus_vads,
                yara_matches: yara,
                risk_score: 0,
            };
            summary.calculate_risk_score();
            summaries.push(summary);
        }

        summaries.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        summaries
    }

    /// Find persistence mechanisms in registry
    /// Returns keys that are persistence-related, including keys from user hives
    /// that indicate Run key presence (even without data values from printkey)
    pub fn find_persistence_keys(&self) -> Vec<&crate::models::registry::RegistryKey> {
        self.data
            .registry_keys
            .iter()
            .filter(|k| {
                if !k.is_persistence_key() {
                    return false;
                }
                // Always include keys with executable or obfuscated data
                if k.has_executable_data() || k.has_obfuscated_data() {
                    return true;
                }
                // Also include Run keys from user hives (ntuser.dat) even without data,
                // because printkey may only return key existence
                let key_lower = k.key.to_lowercase();
                if key_lower.contains("ntuser.dat") || key_lower.contains("usrclass.dat") {
                    // User hive with persistence key = worth reporting
                    return key_lower.contains("\\run");
                }
                false
            })
            .collect()
    }

    /// Build unified timeline of all events
    pub fn build_timeline(&self) -> Vec<TimelineEvent> {
        TimelineBuilder::new(self.data).build()
    }
}

/// Helper to check if two timestamps are within a window
pub fn within_time_window(t1: DateTime<Utc>, t2: DateTime<Utc>, window: Duration) -> bool {
    (t1 - t2).num_seconds().abs() <= window.num_seconds()
}
