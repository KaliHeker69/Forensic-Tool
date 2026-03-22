//! Unified Artifact Graph Engine
//!
//! Builds a single connected graph where every forensic artifact (process, connection,
//! file, registry key, DLL, service, etc.) is a node and relationships are weighted edges.
//! Enables Axiom-style multi-hop correlation: given any artifact, traverse the graph to
//! find all related artifacts within N hops.

use std::collections::{HashMap, HashSet};

use petgraph::graph::{Graph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Undirected;
use serde::Serialize;

use crate::parsers::ParsedData;

// ─── Node Types ─────────────────────────────────────────────────────────

/// A node in the artifact graph
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactNode {
    pub id: String,
    pub label: String,
    pub artifact_type: ArtifactType,
    pub risk_score: u8,
    pub details: Vec<(String, String)>,
}

/// Types of artifacts in the graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactType {
    Process,
    Connection,
    File,
    Registry,
    Dll,
    Service,
    Thread,
    Handle,
    Injection,
    Browser,
    Download,
    MftEntry,
}

impl ArtifactType {
    pub fn color(&self) -> &'static str {
        match self {
            ArtifactType::Process => "#58a6ff",
            ArtifactType::Connection => "#39d353",
            ArtifactType::File => "#ffa657",
            ArtifactType::Registry => "#f0883e",
            ArtifactType::Dll => "#a371f7",
            ArtifactType::Service => "#f78166",
            ArtifactType::Thread => "#79c0ff",
            ArtifactType::Handle => "#8b949e",
            ArtifactType::Injection => "#ff7b72",
            ArtifactType::Browser => "#d2a8ff",
            ArtifactType::Download => "#7ee787",
            ArtifactType::MftEntry => "#ffc680",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ArtifactType::Process => "Process",
            ArtifactType::Connection => "Network",
            ArtifactType::File => "File",
            ArtifactType::Registry => "Registry",
            ArtifactType::Dll => "DLL",
            ArtifactType::Service => "Service",
            ArtifactType::Thread => "Thread",
            ArtifactType::Handle => "Handle",
            ArtifactType::Injection => "Injection",
            ArtifactType::Browser => "Browser",
            ArtifactType::Download => "Download",
            ArtifactType::MftEntry => "MFT",
        }
    }
}

// ─── Edge Types ─────────────────────────────────────────────────────────

/// A relationship edge in the artifact graph
#[derive(Debug, Clone, Serialize)]
pub struct Relationship {
    pub rel_type: RelationshipType,
    pub weight: f32,
    pub description: String,
}

/// Types of relationships between artifacts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Process spawned another process
    Spawned,
    /// Process loaded a DLL
    LoadedDll,
    /// Process owns a network connection
    ConnectedTo,
    /// Process accessed/opened a file
    AccessedFile,
    /// Process accessed a registry key
    AccessedRegistry,
    /// Process has a handle to another object
    OwnsHandle,
    /// Process owns a thread
    OwnsThread,
    /// Injection detected in process
    InjectedInto,
    /// Process runs as a service
    RunsAsService,
    /// Download originated from browser visit
    DownloadedFrom,
    /// File created by download
    CreatedFile,
    /// File referenced in registry data
    ReferencesFile,
    /// Temporal proximity (events close in time)
    TemporalLink,
}

impl RelationshipType {
    pub fn label(&self) -> &'static str {
        match self {
            RelationshipType::Spawned => "spawned",
            RelationshipType::LoadedDll => "loaded",
            RelationshipType::ConnectedTo => "connected_to",
            RelationshipType::AccessedFile => "accessed",
            RelationshipType::AccessedRegistry => "accessed_reg",
            RelationshipType::OwnsHandle => "has_handle",
            RelationshipType::OwnsThread => "owns_thread",
            RelationshipType::InjectedInto => "injected",
            RelationshipType::RunsAsService => "runs_as",
            RelationshipType::DownloadedFrom => "downloaded",
            RelationshipType::CreatedFile => "created",
            RelationshipType::ReferencesFile => "references",
            RelationshipType::TemporalLink => "temporal",
        }
    }

    pub fn base_weight(&self) -> f32 {
        match self {
            RelationshipType::Spawned => 0.9,
            RelationshipType::InjectedInto => 1.0,
            RelationshipType::ConnectedTo => 0.8,
            RelationshipType::LoadedDll => 0.5,
            RelationshipType::AccessedFile => 0.6,
            RelationshipType::AccessedRegistry => 0.6,
            RelationshipType::OwnsHandle => 0.4,
            RelationshipType::OwnsThread => 0.5,
            RelationshipType::RunsAsService => 0.7,
            RelationshipType::DownloadedFrom => 0.8,
            RelationshipType::CreatedFile => 0.7,
            RelationshipType::ReferencesFile => 0.5,
            RelationshipType::TemporalLink => 0.3,
        }
    }
}

// ─── Graph Builder ──────────────────────────────────────────────────────

/// The unified artifact graph
pub struct ArtifactGraph {
    graph: Graph<ArtifactNode, Relationship, Undirected>,
    /// Lookup: artifact ID string → node index
    index_map: HashMap<String, NodeIndex>,
}

impl ArtifactGraph {
    /// Build the artifact graph from parsed Volatility3 data
    pub fn build(data: &ParsedData) -> Self {
        let mut graph = Graph::new_undirected();
        let mut index_map = HashMap::new();

        let mut builder = GraphBuilder {
            graph: &mut graph,
            index_map: &mut index_map,
        };

        // Phase 1: Add all artifact nodes
        builder.add_processes(data);
        builder.add_connections(data);
        builder.add_files(data);
        builder.add_registry_keys(data);
        builder.add_dlls(data);
        builder.add_services(data);
        builder.add_threads(data);
        builder.add_malfind(data);
        builder.add_browser_history(data);
        builder.add_downloads(data);

        // Phase 2: Add relationship edges
        builder.link_process_tree(data);
        builder.link_process_connections(data);
        builder.link_process_dlls(data);
        builder.link_process_threads(data);
        builder.link_process_injections(data);
        builder.link_process_handles(data);
        builder.link_process_services(data);
        builder.link_browser_downloads(data);
        builder.link_download_files(data);
        builder.link_registry_file_references(data);

        Self { graph, index_map }
    }

    /// Query: find all artifacts related to a given artifact within N hops
    pub fn related_artifacts(&self, artifact_id: &str, max_hops: usize) -> Vec<&ArtifactNode> {
        let Some(&start) = self.index_map.get(artifact_id) else {
            return Vec::new();
        };

        let mut visited = HashSet::new();
        let mut frontier = vec![start];
        visited.insert(start);

        for _ in 0..max_hops {
            let mut next_frontier = Vec::new();
            for node in &frontier {
                for neighbor in self.graph.neighbors(*node) {
                    if visited.insert(neighbor) {
                        next_frontier.push(neighbor);
                    }
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }

        visited
            .iter()
            .filter(|&&idx| idx != start)
            .filter_map(|idx| self.graph.node_weight(*idx))
            .collect()
    }

    /// Find connected components (clusters of related activity)
    pub fn connected_components(&self) -> Vec<Vec<&ArtifactNode>> {
        let components = petgraph::algo::kosaraju_scc(&self.graph);
        let mut result: Vec<Vec<&ArtifactNode>> = components
            .into_iter()
            .map(|comp| {
                comp.iter()
                    .filter_map(|idx| self.graph.node_weight(*idx))
                    .collect()
            })
            .filter(|c: &Vec<&ArtifactNode>| c.len() > 1)
            .collect();

        // Sort by size (largest first)
        result.sort_by(|a, b| b.len().cmp(&a.len()));
        result
    }

    /// Find the highest-risk subgraph (nodes with risk_score > threshold and their neighbors)
    pub fn suspicious_subgraph(&self, risk_threshold: u8) -> Vec<(&ArtifactNode, Vec<(&ArtifactNode, &Relationship)>)> {
        let mut result = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            if node.risk_score >= risk_threshold {
                let neighbors: Vec<_> = self
                    .graph
                    .edges(idx)
                    .filter_map(|edge| {
                        let other = if edge.source() == idx {
                            edge.target()
                        } else {
                            edge.source()
                        };
                        Some((&self.graph[other], edge.weight()))
                    })
                    .collect();
                result.push((node, neighbors));
            }
        }

        result.sort_by(|a, b| b.0.risk_score.cmp(&a.0.risk_score));
        result
    }

    /// Get statistics about the graph
    pub fn stats(&self) -> GraphStats {
        let mut type_counts: HashMap<ArtifactType, usize> = HashMap::new();
        let mut edge_type_counts: HashMap<RelationshipType, usize> = HashMap::new();

        for node in self.graph.node_weights() {
            *type_counts.entry(node.artifact_type).or_default() += 1;
        }

        for edge in self.graph.edge_weights() {
            *edge_type_counts.entry(edge.rel_type).or_default() += 1;
        }

        let components = petgraph::algo::kosaraju_scc(&self.graph);
        let multi_components = components.iter().filter(|c| c.len() > 1).count();

        GraphStats {
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            node_type_counts: type_counts,
            edge_type_counts,
            connected_clusters: multi_components,
        }
    }

    /// Serialize the graph to a D3.js-compatible JSON format for visualization
    pub fn to_d3_json(&self) -> String {
        let mut nodes: Vec<D3Node> = Vec::new();
        let mut links: Vec<D3Link> = Vec::new();
        let mut idx_to_pos: HashMap<NodeIndex, usize> = HashMap::new();

        // Limit graph size for rendering. If the graph is huge, only include
        // nodes with risk >= 10 OR nodes connected to high-risk nodes.
        let total = self.graph.node_count();
        let max_nodes = 300;

        let include_all = total <= max_nodes;

        // First pass: find high-risk node set
        let high_risk_indices: HashSet<NodeIndex> = if include_all {
            self.graph.node_indices().collect()
        } else {
            let mut selected = HashSet::new();
            // Include all nodes with risk > 0
            for idx in self.graph.node_indices() {
                if self.graph[idx].risk_score > 0 {
                    selected.insert(idx);
                    // Include their 1-hop neighbors
                    for neighbor in self.graph.neighbors(idx) {
                        selected.insert(neighbor);
                    }
                }
            }

            // If still too many, raise threshold
            if selected.len() > max_nodes {
                selected.clear();
                for idx in self.graph.node_indices() {
                    if self.graph[idx].risk_score >= 30 {
                        selected.insert(idx);
                        for neighbor in self.graph.neighbors(idx) {
                            selected.insert(neighbor);
                        }
                    }
                }
            }

            // If *still* too many, just take top N by risk
            if selected.len() > max_nodes {
                let mut scored: Vec<_> = self
                    .graph
                    .node_indices()
                    .map(|i| (i, self.graph[i].risk_score))
                    .collect();
                scored.sort_by(|a, b| b.1.cmp(&a.1));
                scored.truncate(max_nodes);
                selected = scored.into_iter().map(|(i, _)| i).collect();
            }

            selected
        };

        // Build nodes
        for idx in self.graph.node_indices() {
            if !high_risk_indices.contains(&idx) {
                continue;
            }
            let node = &self.graph[idx];
            let pos = nodes.len();
            idx_to_pos.insert(idx, pos);

            nodes.push(D3Node {
                id: node.id.clone(),
                label: truncate_label(&node.label, 60),
                group: node.artifact_type.display_name().to_string(),
                color: node.artifact_type.color().to_string(),
                risk: node.risk_score,
                size: 4 + (node.risk_score as usize / 10).min(12),
            });
        }

        // Build links
        for edge_ref in self.graph.edge_references() {
            let src = edge_ref.source();
            let tgt = edge_ref.target();
            if let (Some(&src_pos), Some(&tgt_pos)) = (idx_to_pos.get(&src), idx_to_pos.get(&tgt))
            {
                let rel = edge_ref.weight();
                links.push(D3Link {
                    source: src_pos,
                    target: tgt_pos,
                    label: rel.rel_type.label().to_string(),
                    weight: rel.weight,
                });
            }
        }

        serde_json::to_string(&D3Graph { nodes, links }).unwrap_or_default()
    }
}

// ─── D3 Serialization Types ────────────────────────────────────────────

#[derive(Serialize)]
struct D3Graph {
    nodes: Vec<D3Node>,
    links: Vec<D3Link>,
}

#[derive(Serialize)]
struct D3Node {
    id: String,
    label: String,
    group: String,
    color: String,
    risk: u8,
    size: usize,
}

#[derive(Serialize)]
struct D3Link {
    source: usize,
    target: usize,
    label: String,
    weight: f32,
}

/// Graph statistics
#[derive(Debug)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub node_type_counts: HashMap<ArtifactType, usize>,
    pub edge_type_counts: HashMap<RelationshipType, usize>,
    pub connected_clusters: usize,
}

// ─── Internal Builder ───────────────────────────────────────────────────

struct GraphBuilder<'a> {
    graph: &'a mut Graph<ArtifactNode, Relationship, Undirected>,
    index_map: &'a mut HashMap<String, NodeIndex>,
}

impl<'a> GraphBuilder<'a> {
    fn add_node(&mut self, node: ArtifactNode) -> NodeIndex {
        let id = node.id.clone();
        if let Some(&existing) = self.index_map.get(&id) {
            return existing;
        }
        let idx = self.graph.add_node(node);
        self.index_map.insert(id, idx);
        idx
    }

    fn add_edge(&mut self, from: &str, to: &str, rel: Relationship) {
        if let (Some(&src), Some(&tgt)) = (self.index_map.get(from), self.index_map.get(to)) {
            if src != tgt {
                self.graph.add_edge(src, tgt, rel);
            }
        }
    }

    // ── Node adders ─────────────────────────────────────────────────────

    fn add_processes(&mut self, data: &ParsedData) {
        let mut seen_pids = HashSet::new();
        for proc in &data.processes {
            if !seen_pids.insert(proc.pid) {
                continue; // Deduplicate by PID
            }

            let cmdline = data
                .cmdlines
                .iter()
                .find(|c| c.pid == proc.pid)
                .map(|c| c.args.clone());

            let is_suspicious = cmdline
                .as_ref()
                .map(|c| {
                    let l = c.to_lowercase();
                    l.contains("-enc") || l.contains("-e ") || l.contains("-w hidden")
                })
                .unwrap_or(false);

            let risk = if is_suspicious { 60 } else { 0 };
            let mut details = vec![
                ("PID".into(), proc.pid.to_string()),
                ("PPID".into(), proc.ppid.to_string()),
            ];
            if let Some(ref cmd) = cmdline {
                details.push(("CmdLine".into(), truncate_label(cmd, 120)));
            }
            if let Some(ref ct) = proc.create_time {
                details.push(("Created".into(), ct.to_string()));
            }

            self.add_node(ArtifactNode {
                id: format!("proc_{}", proc.pid),
                label: format!("{} ({})", proc.name, proc.pid),
                artifact_type: ArtifactType::Process,
                risk_score: risk,
                details,
            });
        }
    }

    fn add_connections(&mut self, data: &ParsedData) {
        for (i, conn) in data.connections.iter().enumerate() {
            let risk = Self::connection_risk(conn);

            let state = conn.state.as_deref().unwrap_or("?");
            self.add_node(ArtifactNode {
                id: format!("conn_{}", i),
                label: format!(
                    "{}:{}→{}:{} [{}]",
                    conn.local_addr, conn.local_port, conn.foreign_addr, conn.foreign_port, state
                ),
                artifact_type: ArtifactType::Connection,
                risk_score: risk,
                details: vec![
                    ("Protocol".into(), conn.protocol.clone()),
                    (
                        "Local".into(),
                        format!("{}:{}", conn.local_addr, conn.local_port),
                    ),
                    (
                        "Remote".into(),
                        format!("{}:{}", conn.foreign_addr, conn.foreign_port),
                    ),
                    ("State".into(), state.to_string()),
                    ("PID".into(), conn.pid.to_string()),
                ],
            });
        }
    }

    fn connection_risk(conn: &crate::models::network::NetworkConnection) -> u8 {
        let owner_lower = conn.owner.as_deref().unwrap_or("").to_lowercase();

        if conn.is_suspicious_port() {
            return 70;
        }

        if !conn.is_external() {
            return if conn.is_listening() { 10 } else { 0 };
        }

        if matches!(conn.foreign_port, 22 | 135 | 445 | 3389 | 5985 | 5986) {
            return 60;
        }

        if conn.is_established()
            && conn.is_common_web_port()
            && ["firefox", "chrome", "msedge", "edge", "brave", "opera", "iexplore"]
                .iter()
                .any(|p| owner_lower.contains(p))
        {
            return 8;
        }

        if conn.is_established() && conn.is_common_web_port() {
            return 20;
        }

        if conn.is_listening() {
            35
        } else {
            15
        }
    }

    fn add_files(&mut self, data: &ParsedData) {
        // Only include files in interesting locations to keep graph manageable
        for (i, file) in data.files.iter().enumerate() {
            let lower = file.name.to_lowercase();
            let interesting = lower.contains("\\temp\\")
                || lower.contains("\\downloads\\")
                || lower.contains("\\appdata\\")
                || lower.contains("\\public\\")
                || lower.contains("\\programdata\\")
                || file.is_executable()
                || file.is_staging_pattern();

            if !interesting && data.files.len() > 200 {
                continue; // Skip noise for large datasets
            }

            let risk = if file.is_staging_pattern() {
                50
            } else if file.is_executable()
                && (lower.contains("\\temp\\") || lower.contains("\\downloads\\"))
            {
                40
            } else {
                0
            };

            self.add_node(ArtifactNode {
                id: format!("file_{}", i),
                label: file.filename().to_string(),
                artifact_type: ArtifactType::File,
                risk_score: risk,
                details: vec![("Path".into(), file.name.clone())],
            });
        }
    }

    fn add_registry_keys(&mut self, data: &ParsedData) {
        for (i, key) in data.registry_keys.iter().enumerate() {
            let risk = if key.has_obfuscated_data() {
                80
            } else if key.has_executable_data() {
                60
            } else if key.is_persistence_key() {
                40
            } else {
                0
            };

            // Only include interesting registry keys
            if risk == 0 && data.registry_keys.len() > 100 {
                continue;
            }

            self.add_node(ArtifactNode {
                id: format!("reg_{}", i),
                label: key.base_name().to_string(),
                artifact_type: ArtifactType::Registry,
                risk_score: risk,
                details: vec![
                    ("Key".into(), key.key.clone()),
                    (
                        "Name".into(),
                        key.name.clone().unwrap_or_else(|| "-".into()),
                    ),
                    (
                        "Data".into(),
                        key.data
                            .as_deref()
                            .map(|d| truncate_label(d, 100))
                            .unwrap_or_else(|| "-".into()),
                    ),
                ],
            });
        }
    }

    fn add_dlls(&mut self, data: &ParsedData) {
        // Only add suspicious DLLs to avoid graph explosion
        let mut seen = HashSet::new();
        for dll in &data.dlls {
            let path_lower = dll.path.to_lowercase();
            let suspicious = path_lower.contains("\\temp\\")
                || path_lower.contains("\\appdata\\")
                || path_lower.contains("\\downloads\\")
                || path_lower.contains("\\public\\")
                || (!path_lower.contains("\\windows\\")
                    && !path_lower.contains("\\program files")
                    && !path_lower.contains("\\winsxs\\")
                    && !path_lower.is_empty());

            if !suspicious && data.dlls.len() > 100 {
                continue;
            }

            let key = format!("{}:{}", dll.pid, dll.path);
            if !seen.insert(key) {
                continue;
            }

            let risk = if path_lower.contains("\\temp\\") || path_lower.contains("\\downloads\\") {
                40
            } else if suspicious {
                20
            } else {
                0
            };

            let dll_id = format!("dll_{}_{}", dll.pid, sanitize_id(&dll.name));

            self.add_node(ArtifactNode {
                id: dll_id,
                label: format!("{} (PID:{})", dll.name, dll.pid),
                artifact_type: ArtifactType::Dll,
                risk_score: risk,
                details: vec![
                    ("Name".into(), dll.name.clone()),
                    ("Path".into(), dll.path.clone()),
                    ("PID".into(), dll.pid.to_string()),
                    ("Base".into(), dll.base.clone()),
                ],
            });
        }
    }

    fn add_services(&mut self, data: &ParsedData) {
        for (i, svc) in data.services.iter().enumerate() {
            let risk = if svc.is_suspicious_name() || svc.has_suspicious_execution() { 50 } else { 0 };

            self.add_node(ArtifactNode {
                id: format!("svc_{}", i),
                label: svc.name.clone(),
                artifact_type: ArtifactType::Service,
                risk_score: risk,
                details: vec![
                    ("Name".into(), svc.name.clone()),
                    (
                        "Display".into(),
                        svc.display_name.clone().unwrap_or_default(),
                    ),
                    (
                        "Binary".into(),
                        svc.binary_path.clone().unwrap_or_default(),
                    ),
                    ("State".into(), svc.state.clone().unwrap_or_default()),
                    ("Start".into(), svc.start_type.clone().unwrap_or_default()),
                ],
            });
        }
    }

    fn add_threads(&mut self, data: &ParsedData) {
        // Only add suspicious threads
        for (i, thread) in data.threads.iter().enumerate() {
            let risk = if thread.is_orphaned() {
                50
            } else if thread.has_suspicious_start_path() {
                40
            } else {
                continue; // Skip normal threads
            };

            self.add_node(ArtifactNode {
                id: format!("thrd_{}", i),
                label: format!("TID:{} (PID:{})", thread.tid, thread.pid),
                artifact_type: ArtifactType::Thread,
                risk_score: risk,
                details: vec![
                    ("TID".into(), thread.tid.to_string()),
                    ("PID".into(), thread.pid.to_string()),
                    (
                        "StartAddr".into(),
                        thread.start_address.map(|a| format!("0x{:x}", a)).unwrap_or_default(),
                    ),
                ],
            });
        }
    }

    fn add_malfind(&mut self, data: &ParsedData) {
        for (i, mal) in data.malfind.iter().enumerate() {
            let risk = if mal.has_mz_header() {
                90
            } else if mal.has_shellcode_patterns() {
                80
            } else if mal.is_rwx() {
                60
            } else {
                40
            };

            self.add_node(ArtifactNode {
                id: format!("malf_{}", i),
                label: format!("{} {} (PID:{})", mal.process, mal.protection, mal.pid),
                artifact_type: ArtifactType::Injection,
                risk_score: risk,
                details: vec![
                    ("Process".into(), mal.process.clone()),
                    ("PID".into(), mal.pid.to_string()),
                    ("Address".into(), mal.start.clone()),
                    ("Protection".into(), mal.protection.clone()),
                    (
                        "Type".into(),
                        if mal.has_mz_header() {
                            "MZ Header"
                        } else if mal.has_shellcode_patterns() {
                            "Shellcode"
                        } else {
                            "RWX Region"
                        }
                        .to_string(),
                    ),
                ],
            });
        }
    }

    fn add_browser_history(&mut self, data: &ParsedData) {
        // Only suspicious URLs
        for (i, hist) in data.browser_history.iter().enumerate() {
            let risk = if hist.is_potential_driveby() {
                70
            } else if hist.is_suspicious_url() {
                50
            } else {
                continue; // Skip normal browsing
            };

            self.add_node(ArtifactNode {
                id: format!("browser_{}", i),
                label: format!(
                    "[{}] {}",
                    hist.browser,
                    truncate_label(&hist.url, 50)
                ),
                artifact_type: ArtifactType::Browser,
                risk_score: risk,
                details: vec![
                    ("URL".into(), hist.url.clone()),
                    ("Browser".into(), hist.browser.clone()),
                    (
                        "Title".into(),
                        hist.title.clone().unwrap_or_default(),
                    ),
                    (
                        "Timestamp".into(),
                        hist.timestamp.to_string(),
                    ),
                ],
            });
        }
    }

    fn add_downloads(&mut self, data: &ParsedData) {
        for (i, dl) in data.downloads.iter().enumerate() {
            let risk = if dl.was_flagged_dangerous() {
                80
            } else if dl.is_executable() {
                60
            } else {
                15
            };

            self.add_node(ArtifactNode {
                id: format!("dl_{}", i),
                label: format!("[{}] {}", dl.browser, dl.filename()),
                artifact_type: ArtifactType::Download,
                risk_score: risk,
                details: vec![
                    ("URL".into(), dl.url.clone()),
                    ("File".into(), dl.target_path.clone()),
                    ("Browser".into(), dl.browser.clone()),
                    ("Timestamp".into(), dl.timestamp.to_string()),
                ],
            });
        }
    }

    // ── Edge linkers ────────────────────────────────────────────────────

    fn link_process_tree(&mut self, data: &ParsedData) {
        let mut seen_pids = HashSet::new();
        for proc in &data.processes {
            if !seen_pids.insert(proc.pid) {
                continue;
            }
            let parent_id = format!("proc_{}", proc.ppid);
            let child_id = format!("proc_{}", proc.pid);

            if self.index_map.contains_key(&parent_id) && self.index_map.contains_key(&child_id) {
                self.add_edge(
                    &parent_id,
                    &child_id,
                    Relationship {
                        rel_type: RelationshipType::Spawned,
                        weight: RelationshipType::Spawned.base_weight(),
                        description: format!("PID {} spawned PID {}", proc.ppid, proc.pid),
                    },
                );
            }
        }
    }

    fn link_process_connections(&mut self, data: &ParsedData) {
        for (i, conn) in data.connections.iter().enumerate() {
            let proc_id = format!("proc_{}", conn.pid);
            let conn_id = format!("conn_{}", i);

            if self.index_map.contains_key(&proc_id) && self.index_map.contains_key(&conn_id) {
                let weight = if conn.is_external() {
                    RelationshipType::ConnectedTo.base_weight()
                } else {
                    RelationshipType::ConnectedTo.base_weight() * 0.5
                };

                self.add_edge(
                    &proc_id,
                    &conn_id,
                    Relationship {
                        rel_type: RelationshipType::ConnectedTo,
                        weight,
                        description: format!(
                            "{} → {}:{}",
                            conn.owner.as_deref().unwrap_or("?"),
                            conn.foreign_addr,
                            conn.foreign_port
                        ),
                    },
                );
            }
        }
    }

    fn link_process_dlls(&mut self, data: &ParsedData) {
        let mut seen = HashSet::new();
        for dll in &data.dlls {
            let proc_id = format!("proc_{}", dll.pid);
            let dll_id = format!("dll_{}_{}", dll.pid, sanitize_id(&dll.name));

            let key = format!("{}→{}", proc_id, dll_id);
            if !seen.insert(key) {
                continue;
            }

            if self.index_map.contains_key(&proc_id) && self.index_map.contains_key(&dll_id) {
                self.add_edge(
                    &proc_id,
                    &dll_id,
                    Relationship {
                        rel_type: RelationshipType::LoadedDll,
                        weight: RelationshipType::LoadedDll.base_weight(),
                        description: format!("Loaded {}", dll.name),
                    },
                );
            }
        }
    }

    fn link_process_threads(&mut self, data: &ParsedData) {
        for (i, thread) in data.threads.iter().enumerate() {
            let proc_id = format!("proc_{}", thread.pid);
            let thrd_id = format!("thrd_{}", i);

            if self.index_map.contains_key(&proc_id) && self.index_map.contains_key(&thrd_id) {
                self.add_edge(
                    &proc_id,
                    &thrd_id,
                    Relationship {
                        rel_type: RelationshipType::OwnsThread,
                        weight: RelationshipType::OwnsThread.base_weight(),
                        description: format!("Thread TID:{}", thread.tid),
                    },
                );
            }
        }
    }

    fn link_process_injections(&mut self, data: &ParsedData) {
        for (i, mal) in data.malfind.iter().enumerate() {
            let proc_id = format!("proc_{}", mal.pid);
            let malf_id = format!("malf_{}", i);

            if self.index_map.contains_key(&proc_id) && self.index_map.contains_key(&malf_id) {
                self.add_edge(
                    &proc_id,
                    &malf_id,
                    Relationship {
                        rel_type: RelationshipType::InjectedInto,
                        weight: RelationshipType::InjectedInto.base_weight(),
                        description: format!(
                            "Injection in {} at {}",
                            mal.process, mal.start
                        ),
                    },
                );
            }
        }
    }

    fn link_process_handles(&mut self, data: &ParsedData) {
        // Link handles that reference files we have in the graph
        for handle in &data.handles {
            let handle_name = handle.name.as_deref().unwrap_or("");
            if handle_name.is_empty() {
                continue;
            }

            let proc_id = format!("proc_{}", handle.pid);
            if !self.index_map.contains_key(&proc_id) {
                continue;
            }

            let handle_lower = handle_name.to_lowercase();
            let handle_type_lower = handle.handle_type.to_lowercase();

            // Link to matching files
            if handle_type_lower == "file" {
                for (i, file) in data.files.iter().enumerate() {
                    let file_id = format!("file_{}", i);
                    if !self.index_map.contains_key(&file_id) {
                        continue;
                    }
                    if file.name.to_lowercase().contains(&handle_lower)
                        || handle_lower.contains(&file.name.to_lowercase())
                    {
                        self.add_edge(
                            &proc_id,
                            &file_id,
                            Relationship {
                                rel_type: RelationshipType::AccessedFile,
                                weight: RelationshipType::AccessedFile.base_weight(),
                                description: format!("Handle to {}", handle_name),
                            },
                        );
                        break; // One match is enough
                    }
                }
            }

            // Link to registry keys
            if handle_type_lower == "key" {
                for (i, key) in data.registry_keys.iter().enumerate() {
                    let reg_id = format!("reg_{}", i);
                    if !self.index_map.contains_key(&reg_id) {
                        continue;
                    }
                    if key.key.to_lowercase().contains(&handle_lower) {
                        self.add_edge(
                            &proc_id,
                            &reg_id,
                            Relationship {
                                rel_type: RelationshipType::AccessedRegistry,
                                weight: RelationshipType::AccessedRegistry.base_weight(),
                                description: format!("Handle to {}", handle_name),
                            },
                        );
                        break;
                    }
                }
            }
        }
    }

    fn link_process_services(&mut self, data: &ParsedData) {
        for (i, svc) in data.services.iter().enumerate() {
            let svc_id = format!("svc_{}", i);
            if !self.index_map.contains_key(&svc_id) {
                continue;
            }

            let svc_binary = svc.binary_path.as_deref().unwrap_or("").to_lowercase();
            if svc_binary.is_empty() {
                continue;
            }

            // Match service binary to a process
            for proc in &data.processes {
                let proc_name_lower = proc.name.to_lowercase();
                if svc_binary.contains(&proc_name_lower) || proc_name_lower.contains(&svc.name.to_lowercase()) {
                    let proc_id = format!("proc_{}", proc.pid);
                    if self.index_map.contains_key(&proc_id) {
                        self.add_edge(
                            &proc_id,
                            &svc_id,
                            Relationship {
                                rel_type: RelationshipType::RunsAsService,
                                weight: RelationshipType::RunsAsService.base_weight(),
                                description: format!("Service: {}", svc.name),
                            },
                        );
                        break;
                    }
                }
            }
        }
    }

    fn link_browser_downloads(&mut self, data: &ParsedData) {
        for (di, dl) in data.downloads.iter().enumerate() {
            let dl_id = format!("dl_{}", di);
            if !self.index_map.contains_key(&dl_id) {
                continue;
            }

            // Find browser history URL that matches the download domain
            let dl_domain = dl.domain().unwrap_or("");
            for (hi, hist) in data.browser_history.iter().enumerate() {
                let hist_id = format!("browser_{}", hi);
                if !self.index_map.contains_key(&hist_id) {
                    continue;
                }

                let hist_domain = hist.domain().unwrap_or("");
                if !dl_domain.is_empty() && dl_domain == hist_domain {
                    self.add_edge(
                        &hist_id,
                        &dl_id,
                        Relationship {
                            rel_type: RelationshipType::DownloadedFrom,
                            weight: RelationshipType::DownloadedFrom.base_weight(),
                            description: format!("Download from {}", dl_domain),
                        },
                    );
                    break;
                }
            }
        }
    }

    fn link_download_files(&mut self, data: &ParsedData) {
        for (di, dl) in data.downloads.iter().enumerate() {
            let dl_id = format!("dl_{}", di);
            if !self.index_map.contains_key(&dl_id) {
                continue;
            }

            let dl_filename = dl.filename().to_lowercase();
            for (fi, file) in data.files.iter().enumerate() {
                let file_id = format!("file_{}", fi);
                if !self.index_map.contains_key(&file_id) {
                    continue;
                }

                if file.filename().to_lowercase() == dl_filename {
                    self.add_edge(
                        &dl_id,
                        &file_id,
                        Relationship {
                            rel_type: RelationshipType::CreatedFile,
                            weight: RelationshipType::CreatedFile.base_weight(),
                            description: format!("Downloaded file: {}", dl_filename),
                        },
                    );
                    break;
                }
            }
        }
    }

    fn link_registry_file_references(&mut self, data: &ParsedData) {
        for (ri, key) in data.registry_keys.iter().enumerate() {
            let reg_id = format!("reg_{}", ri);
            if !self.index_map.contains_key(&reg_id) {
                continue;
            }

            // If registry data contains a file path, link to matching files
            if let Some(ref data_val) = key.data {
                let data_lower = data_val.to_lowercase();
                if data_lower.contains(".exe")
                    || data_lower.contains(".dll")
                    || data_lower.contains(".bat")
                    || data_lower.contains(".ps1")
                    || data_lower.contains(".vbs")
                {
                    for (fi, file) in data.files.iter().enumerate() {
                        let file_id = format!("file_{}", fi);
                        if !self.index_map.contains_key(&file_id) {
                            continue;
                        }

                        let file_lower = file.name.to_lowercase();
                        // Check if the registry data references this file path
                        if data_lower.contains(&file_lower)
                            || file_lower.contains(&data_lower)
                        {
                            self.add_edge(
                                &reg_id,
                                &file_id,
                                Relationship {
                                    rel_type: RelationshipType::ReferencesFile,
                                    weight: RelationshipType::ReferencesFile.base_weight(),
                                    description: format!(
                                        "Registry references file"
                                    ),
                                },
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn truncate_label(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}
