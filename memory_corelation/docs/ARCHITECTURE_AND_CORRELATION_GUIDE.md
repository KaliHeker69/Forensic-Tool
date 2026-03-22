# Memory Correlation Tool Documentation

## 1. Overview

vol3-correlate is a Rust-based memory forensics correlation engine that ingests Volatility 3 outputs (JSONL/JSON), normalizes them into typed artifacts, runs detection rules, performs correlation and temporal analysis, enriches findings with threat intelligence, and emits analyst-ready outputs (CLI, JSON, HTML).

The tool is designed for high-signal incident triage in memory images with:
- cross-plugin artifact linking
- multi-category detection rules
- timeline and temporal hotspot analysis
- IOC extraction and attack progression mapping
- interactive report output

## 2. Core Architecture

### 2.1 Architectural Layers

1. Input Layer
- Reads Volatility output files from an input directory.
- Detects plugin type by filename pattern.
- Supports both JSONL and JSON records.

2. Parsing and Normalization Layer
- Parses plugin output into strongly typed Rust models.
- Aggregates all parsed artifacts into a unified ParsedData container.
- Tracks plugin coverage and non-fatal parse warnings.

3. Correlation Layer
- Builds process genealogy and cross-artifact links.
- Generates timeline events from multiple artifact families.
- Computes temporal clusters/hotspots.
- Builds a unified artifact graph for relationship exploration.
- Extracts IOC entities from artifacts and findings.

4. Detection Layer
- Executes a broad rule set (process/network/injection/persistence/etc.).
- Applies MITRE ATT&CK mapping when missing.
- Deduplicates overlapping findings.
- Filters by user-selected minimum severity.

5. Enrichment Layer (Optional)
- Calls AbuseIPDB, VirusTotal, and urlscan.io.
- Attaches TI context to network findings.
- Elevates severity if known-malicious infrastructure is detected.

6. Reporting Layer
- Produces CLI summary, JSON report, and rich HTML report.
- Includes forensic metadata, quick views, timelines, graph data, IOCs, and kill-chain interpretation.

### 2.2 High-Level Data Flow

1. Parse CLI arguments.
2. Parse all supported Volatility outputs into ParsedData.
3. Construct CorrelationEngine with time window.
4. Run DetectionEngine default rules.
5. Optionally enrich network findings with threat intel.
6. Build timeline and temporal analysis.
7. Extract forensic metadata and analyst quick-view.
8. Build artifact graph and IOC report.
9. Compute kill-chain progression.
10. Build AnalysisResults and write selected outputs.

## 3. Input and Parsing Mechanics

### 3.1 Plugin Detection

Plugin detection is filename-driven with tolerant matching for common naming variants.
Examples:
- pslist, psscan, pstree
- netscan, netstat
- malfind, vadinfo
- handles, dlllist, envars
- printkey, hivelist, hivescan, userassist
- mftscan, filescan, dumpfiles
- privileges, getsids, certificates
- cmdscan, consoles, cachedump

Unknown filenames are ignored as Unknown plugin type.

### 3.2 ParsedData Model

ParsedData is the central in-memory artifact container. It stores:
- process artifacts: processes, cmdlines, dlls, envars
- thread artifacts
- network artifacts
- filesystem artifacts (filescan, dumpfiles, mft)
- registry artifacts
- injection/malware artifacts (malfind, VAD, yara)
- service/driver/kernel callback artifacts
- security artifacts (privileges, SIDs, certificates)
- browser and download history
- raw plugin records for plugins not yet fully typed
- plugin usage set and parse errors

This design lets correlation and detection run over one unified data object.

## 4. Correlation Engine Internals

### 4.1 Process Correlation

The engine builds:
- process map: PID to process index
- process tree roots and child relations
- process nodes with parent names, child PIDs, and derived depth

It deduplicates process records by PID to reduce repeated findings from overlapping sources.

### 4.2 Cross-Artifact Correlation Primitives

Implemented linkers include:
- network to process correlation
- browser visit to network connection temporal correlation
- download to filescan matching by filename
- process genealogy traversal

These primitives support both direct detections and timeline context generation.

### 4.3 Timeline Builder

TimelineBuilder merges events from multiple sources, including:
- process creation/termination
- network connection/listening events
- browser visits and downloads
- registry persistence modifications
- injection events from malfind
- additional events from DLL, MFT, services, UserAssist, and scheduled tasks

Each event receives:
- timestamp
- source plugin
- event type
- human-readable description
- optional PID/process/IP/file associations
- risk_score

The timeline is sorted chronologically and later used by temporal analysis and reporting.

### 4.4 Network Risk Heuristics in Timeline

Network timeline scoring is context-aware:
- suspicious/C2-style ports: high
- external management/lateral ports (22/135/445/3389/5985/5986): elevated
- browser established web traffic on common web ports: low context
- common client applications using web ports: low to moderate context
- unknown process on web ports: mild suspicion
- internal/listening-only patterns: lower base risk

This behavior intentionally suppresses benign web-noise while preserving high-risk lateral/C2 indicators.

### 4.5 Temporal Intelligence

The temporal analyzer computes:
- burst clusters (dense event windows)
- hourly buckets (distribution heat)
- hotspot scoring and dominant event typing

This helps identify automated attack bursts and pivot windows for deeper investigation.

## 5. Detection Engine and Rule Mechanics

### 5.1 Rule Execution Model

Each detection rule implements:
- id
- name
- description
- base severity
- optional MITRE technique
- detect(data, engine) -> findings

The DetectionEngine:
1. runs all registered rules
2. applies MITRE mapping when missing
3. deduplicates by rule + PID context + title hash prefix
4. sorts by severity and timestamp
5. filters by configured minimum severity

### 5.2 Rule Families

Default rules cover:
- process anomalies
- parent-child misuse
- network anomalies
- injection and memory abuse
- persistence mechanisms
- signature integrity
- hidden artifact integrity checks
- credential access
- chain detections
- thread anomalies
- privilege abuse
- certificate anomalies
- MFT/filesystem anomalies
- cross-plugin correlation rules
- SID/integrity-level anomalies

### 5.3 Network False-Positive Control Mechanisms

Recent network tuning introduces three major controls:

1. Centralized allowlists/watchlists
- driven by config/network_tuning.json
- no longer scattered hardcoded arrays across rules

2. Role and subnet-aware exclusions
- host_role profiles (workstation/server/domain_controller)
- expected process and listener behavior varies by role
- allowlisted IPs and CIDR subnets reduce environment-specific noise

3. Multi-attribute gating
- NET001/NET004/NET005 require corroborating signals before medium/high
- single weak signals remain low/context or suppressed

Result: benign browser HTTPS and expected client/server baseline traffic are less likely to trigger medium/high findings.

## 6. Forensic Metadata and Analyst Context Extraction

### 6.1 System Profile Extraction

System profile is inferred from environment variables and process census:
- hostname/domain
- architecture/processor count/system root
- active users
- observed security tooling

### 6.2 User Activity Evidence

The tool extracts:
- environment summaries by process
- session metadata
- interesting handle triage

Handle triage now classifies by:
- signal_level: high, medium, context
- category: process_access, persistence_key, execution_artifact, suspicious_mutex, suspicious_file

Noise controls include:
- deduplication
- suppression of common benign Windows mutexes
- suppression of expected LSASS accessors
- emphasis on persistence and execution-relevant registry keys

### 6.3 Analyst Quick-View

Pre-extracted quick panels include:
- commands
- notable network connections
- registry keys
- interesting files
- services
- program execution history (UserAssist)
- suspicious DLLs

This is pre-shaped for report rendering, minimizing analyst time-to-signal.

## 7. Unified Artifact Graph

The artifact graph is an undirected relationship graph where:
- each artifact is a node with type, label, details, and risk_score
- each relationship is an edge with relationship type and weight

Node families include process, connection, file, registry, DLL, service, thread, handle, injection, browser, download, and MFT entry.

Relationship families include spawned, connected_to, loaded, accessed, injected, runs_as, downloaded, references, and temporal links.

Capabilities:
- N-hop related artifact queries
- connected component discovery (activity clusters)
- suspicious subgraph extraction above risk threshold
- D3-compatible JSON export for HTML visualization

## 8. IOC Extraction and Correlation

IOC extraction scans both parsed artifacts and finalized findings.

Supported IOC types include:
- IPv4/IPv6
- domains and URLs
- file paths
- registry keys
- mutex names
- hashes
- email addresses
- user agents
- process identifiers/names

Collector behavior:
- type/value deduplication
- source tracking
- PID association
- context tagging
- high-confidence summary counts
- finding-level IOC marking

This enables direct export, pivoting, and threat-intel handoff workflows.

## 9. Kill Chain and ATT&CK Progression

Kill chain analysis maps findings to:
- MITRE ATT&CK tactics
- Lockheed Martin kill chain stages

It computes:
- stage-wise finding distribution
- matrix cells by technique and tactic
- max stage reached
- unique tactics/techniques
- progression score (0 to 100)
- executive narrative summary

When MITRE is absent, category-based fallback mapping is used.

## 10. Threat Intelligence Enrichment

When enabled, the tool:
- loads API keys from config/api_keys.json or environment variables
- checks unique external IPs from network findings
- enriches findings with AbuseIPDB, VirusTotal, and urlscan context
- marks malicious indicators based on confidence/detection thresholds
- can elevate finding severity and confidence for malicious infrastructure

Private IPs are skipped, and a cache avoids repeated lookups.

## 11. Reporting Architecture

### 11.1 AnalysisResults Container

AnalysisResults aggregates:
- findings and summary metrics
- timeline and process nodes
- plugin metadata and analysis timestamps
- chain of custody and system profile
- user activity and quick-view
- optional parsed data, artifact graph JSON, IOC report, temporal analysis, and kill-chain analysis

### 11.2 Output Formats

- CLI: terminal-oriented triage output
- JSON: machine-consumable report
- HTML: interactive analyst report with advanced sections

### 11.3 Findings Rendering Notes

Findings now include per-alert timestamp display in HTML:
- formatted UTC timestamp when available
- fallback to Not available when not present

This improves forensic sequence reconstruction in the report UI.

## 12. Configuration System

### 12.1 Config Files

- config/whitelist.json
- config/blacklist.json
- config/network_tuning.json
- config/api_keys.json (sensitive)

### 12.2 Network Tuning Keys

network_tuning.json supports:
- host_role
- allowlisted_processes
- browser_processes
- common_client_processes
- expected_listener_processes
- never_network_processes
- expected_listener_ports
- suspicious_ports
- high_risk_remote_ports
- allowlisted_ips
- allowlisted_subnets

These values are consumed centrally by network rules and matching helpers.

## 13. Pipeline Module System (Available, Not Main CLI Path)

The codebase also includes a 9-module weighted pipeline engine:
1. allowlist
2. process_integrity
3. registry_integrity
4. cmdline_analysis
5. injection_dll
6. persistence
7. handle_network
8. chain_detection
9. scoring

Pipeline behavior:
- accumulates weighted evidence per PID
- tracks chain tags and cross-module bonus logic
- maps final score to severity thresholds
- dismisses low/no-score entities

Note: current main CLI execution path uses DetectionEngine directly. The pipeline module system is present and extensible but is not the default path in main.rs.

## 14. Extending the Tool

### 14.1 Add a New Parser

1. Add model type in src/models.
2. Extend parser routing in src/parsers/mod.rs.
3. Update plugin detection in src/parsers/plugin_detection.rs.
4. Insert into ParsedData and summary counts.
5. Add tests for JSON/JSONL variants.

### 14.2 Add a New Detection Rule

1. Create rule file in src/detection/<family>.
2. Implement DetectionRule.
3. Register rule in DetectionEngine::with_default_rules.
4. Add MITRE ID where applicable.
5. Add dedupe-safe finding title/evidence patterns.
6. Validate severity/confidence and false-positive behavior with representative data.

### 14.3 Add Report Section

1. Extend AnalysisResults with required payload.
2. Populate in main flow.
3. Add rendering section in src/output/html.rs and/or JSON serializer.
4. Keep output robust when section data is absent.

## 15. Operational Usage

### 15.1 Typical Run

cargo run -- \
  --input ./jsonl \
  --output all \
  --output-dir ./reports \
  --severity low \
  --time-window 5

### 15.2 With Threat Intel

cargo run -- \
  --input ./jsonl \
  --output html \
  --output-dir ./reports \
  --threat-intel \
  --api-keys ./config/api_keys.json

### 15.3 Timeline Export

cargo run -- \
  --input ./jsonl \
  --output html \
  --output-dir ./reports \
  --timeline-csv ./reports/timeline.csv \
  --timeline-json ./reports/timeline.json \
  --case-name incident-001

## 16. Current Strengths and Practical Limits

### Strengths
- broad plugin and rule coverage
- strong cross-artifact and timeline correlation
- centralized network tuning for FP control
- IOC and kill-chain outputs suitable for triage and reporting
- forensic metadata integration for case context

### Limits
- no native multi-image/cross-host case correlation in one run
- some plugin families are still represented as raw records before full typing
- environment-specific tuning is still required for best precision
- threat intel quality depends on API coverage and rate limits

## 17. Summary

vol3-correlate implements a layered memory analysis architecture that combines deterministic rule detection, cross-artifact correlation, temporal intelligence, IOC extraction, and rich reporting. Its current design balances practical SOC/DFIR usability with extensibility:
- centralized configuration for noise control
- composable correlation primitives
- explicit rule-driven detections with ATT&CK alignment
- analyst-oriented outputs that preserve raw evidence traceability

For production DFIR use, the most important operating principle is to tune network and environment baselines (host role, allowlists, expected listeners) while preserving high-signal multi-attribute detections for lateral movement, C2, credential access, and persistence behaviors.
