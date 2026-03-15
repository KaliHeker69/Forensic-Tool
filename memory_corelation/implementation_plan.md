# Axiom-Level Memory Analysis & Correlation — Gap Analysis and Implementation Plan

## Current State Summary

**vol3-correlate** is a Rust CLI tool that ingests Volatility3 JSONL/JSON outputs and produces forensic reports. It currently has:

| Area | What exists |
|---|---|
| **Parsers** | 30+ Vol3 plugin types (pslist, psscan, pstree, cmdline, netscan, malfind, vadinfo, filescan, mftscan, handles, dlllist, svcscan, registry, certificates, privileges, getsids, threads, userassist, etc.) |
| **Detection** | 63 rules in 15 categories (process, network, injection, persistence, credential, chain, thread, privilege, certificate, MFT, integrity, SID, signature, cross-correlation) |
| **Correlation** | Process tree building, network↔process linking, browser↔network temporal correlation, download↔file matching, injection analysis (malfind+VAD+YARA), persistence key detection, C2 beaconing patterns, lateral movement indicators |
| **Pipeline** | 9-module ordered pipeline (allowlist → process integrity → registry → cmdline → injection/DLL → persistence → handle/network → chain detection → scoring) |
| **Output** | CLI, JSON, HTML report with forensic metadata, chain of custody, system profile, analyst quick-view |
| **Threat Intel** | AbuseIPDB, VirusTotal, urlscan.io integration |

---

## Magnet Axiom Capabilities vs. Your Tool — Gap Analysis

Magnet Axiom is the industry gold standard for forensic analysis and correlation. Below is a category-by-category comparison. Items marked ✅ are already present, ⚠️ are partial, and ❌ are missing.

### 1. Artifact Correlation Engine

| Axiom Feature | Your Tool | Gap |
|---|---|---|
| Cross-artifact linking (process → network → file → registry) | ⚠️ Partial — links exist but are separate (network↔process, download↔file, etc.) | ❌ **Unified Artifact Graph** — Axiom builds a single connected graph where every artifact is a node and relationships are edges, enabling multi-hop traversal (e.g., "find all files touched by processes connected to malicious IPs") |
| Bi-directional navigation | ❌ | ❌ Need ability to navigate from any artifact to all related artifacts |
| Relationship scoring | ⚠️ Risk scores exist per finding | ❌ Axiom weights relationships themselves — a connection from a suspicious process to an external IP is weighted differently than from svchost.exe |
| Temporal proximity clustering | ⚠️ Time window for browser↔network only | ❌ Need automatic temporal clustering across ALL artifact types |

### 2. Timeline Analysis

| Axiom Feature | Your Tool | Gap |
|---|---|---|
| Unified timeline from all sources | ✅ [TimelineBuilder](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/timeline.rs#9-12) covers processes, network, browser, downloads, registry, malfind | ⚠️ Missing MFT timestamps, service creation times, handle creation times, DLL load times, scheduled task times, UserAssist timestamps |
| Timeline filtering/search | ❌ | ❌ CLI output only — no interactive filtering, search, or zoom |
| Temporal clustering / hot-spot detection | ❌ | ❌ Axiom auto-detects "bursts" of activity — e.g., 15 events in 2 seconds indicates automation |
| Timeline export (CSV, ICS, super timeline format) | ❌ | ❌ No standalone timeline export |

### 3. Artifact Categories

| Axiom Artifact | Your Tool | Gap |
|---|---|---|
| Process Analysis | ✅ Comprehensive | — |
| Network Analysis | ✅ Good | ⚠️ Missing DNS cache analysis, ARP cache |
| Memory Injection | ✅ malfind + VAD + YARA | — |
| Registry Analysis | ✅ Persistence keys, printkey | ⚠️ No shimcache, amcache, BAM/DAM, ShellBags parsing |
| File System | ✅ filescan + MFT | ⚠️ No NTFS journal ($UsnJrnl), prefetch, recycle bin |
| Browser Artifacts | ✅ History + downloads | ⚠️ No cookies, cached pages, autofill, bookmarks |
| User Activity | ✅ UserAssist, envars, handles | ⚠️ No shellbags, recent docs, jump lists, LNK files |
| Scheduled Tasks | ⚠️ Raw JSON records only | ❌ No structured parsing or analysis |
| WMI Persistence | ❌ | ❌ No WMI event subscription analysis |
| PowerShell Artifacts | ⚠️ Command line decode only | ❌ No PowerShell script block logging, transcript analysis |
| Event Log Analysis | ❌ | ❌ No Windows Event Log (EVTX) from memory extraction |
| Prefetch Files | ❌ | ❌ No prefetch file analysis for program execution history |

### 4. Correlation Intelligence

| Axiom Feature | Your Tool | Gap |
|---|---|---|
| Process Execution Chain | ⚠️ Parent-child only | ❌ **Full execution chain** — Axiom traces complete execution chains across process generations (grandparent → parent → child → network → file) with confidence scoring at each hop |
| Lateral Movement Detection | ✅ Structures exist in [linkers.rs](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/linkers.rs) | ⚠️ LateralMovementIndicator is defined but not populated by any detection rule |
| C2 Beaconing Detection | ✅ [BeaconingPattern](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/linkers.rs#106-116) with scoring | ⚠️ Structure exists but not populated — no rule produces beaconing findings |
| MITRE ATT&CK Mapping | ✅ Optional per rule | ⚠️ Only some rules have MITRE IDs — Axiom maps every finding to specific techniques |
| Kill Chain Visualization | ❌ | ❌ Axiom visualizes the complete attack lifecycle across Cyber Kill Chain stages |
| IOC Auto-Extraction | ❌ | ❌ Axiom auto-extracts IPs, domains, hashes, file paths, registry keys as IOCs |
| Case-level Correlation | ❌ | ❌ No ability to correlate across multiple memory images (e.g., host A vs. host B) |

### 5. Report & Export

| Axiom Feature | Your Tool | Gap |
|---|---|---|
| Interactive HTML report | ✅ Comprehensive HTML output | ⚠️ Requires more interactivity (filter, search, drill-down) |
| PDF/DOCX export | ❌ | ❌ Court-ready PDF reports |
| Executive summary | ⚠️ Risk score + summary stats | ❌ Need narrative executive summary with key findings |
| Evidence bookmarks & tags | ❌ | ❌ Analyst tagging/bookmarking system |
| STIX/OpenIOC export | ❌ | ❌ Threat intelligence sharing formats |

### 6. Analysis Automation

| Axiom Feature | Your Tool | Gap |
|---|---|---|
| Automatic artifact classification | ✅ Via detection rules | — |
| Machine learning anomaly detection | ❌ | ❌ Axiom uses ML for anomaly detection on process behavior |
| Baseline comparison | ❌ | ❌ Compare against known-good baselines |
| Custom rule authoring | ❌ | ❌ Rules are hardcoded in Rust — need YAML/TOML rule files |
| Profile-based analysis (Axiom Examine vs. Cyber) | ❌ | ❌ Analysis profiles for different scenarios |

---

## User Review Required

> [!IMPORTANT]
> This is a **massive** undertaking. The full set of changes to reach true Axiom parity would be months of work. I recommend implementing changes in **priority phases**, starting with the highest-impact, lowest-effort improvements.
>
> Please review the phased plan below and tell me:
> 1. Which phase(s) do you want to tackle first?
> 2. Are there specific Axiom features you care about most?
> 3. Any features you want to deprioritize or skip?

---

## Proposed Changes — Phased Implementation

### Phase 1: Unified Artifact Graph & Enhanced Correlation (Highest Impact)

This is the **single biggest gap** — Axiom's power comes from its artifact graph. Currently your correlations are siloed.

#### [NEW] `src/correlation/artifact_graph.rs`
- **Artifact Graph Engine**: A graph data structure where every forensic artifact (process, connection, file, registry key, DLL, service, thread, handle) is a node, and relationships are edges with types and weights
- Edge types: `Spawned`, `LoadedDll`, `OpenedHandle`, `ConnectedTo`, `AccessedFile`, `WroteRegistry`, `InjectedInto`, `SameTimestamp`, etc.
- Graph queries: "Given process X, find all related artifacts within N hops"
- Uses `petgraph` crate for efficient graph operations
- Populates from existing [ParsedData](file:///Users/kali/Codes/wsl/memory_corelation/src/parsers/mod.rs#30-90) automatically

#### [MODIFY] [src/correlation/mod.rs](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/mod.rs)
- Integrate `ArtifactGraph` into [CorrelationEngine](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/mod.rs#22-27)
- Add `build_artifact_graph()` method
- Add `query_related_artifacts(artifact_id, max_hops)` method
- Add `find_connected_components()` to auto-cluster related activity

#### [MODIFY] [src/output/html.rs](file:///Users/kali/Codes/wsl/memory_corelation/src/output/html.rs)
- Add interactive artifact graph visualization (D3.js force-directed graph or Cytoscape.js)
- Click-to-expand node relationships
- Filter by artifact type, severity, time range

---

### Phase 2: Populate Missing Detections & IOC Extraction

#### [MODIFY] Various detection files
- **C2 Beaconing**: Wire up [BeaconingPattern](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/linkers.rs#106-116) in `network_rules/` — analyze connection timestamps for periodicity
- **Lateral Movement**: Wire up [LateralMovementIndicator](file:///Users/kali/Codes/wsl/memory_corelation/src/correlation/linkers.rs#155-163) — detect PsExec (SMB + service creation), WMI, WinRM patterns from process + network + service data
- **Complete MITRE ATT&CK**: Add MITRE technique IDs to all 63 rules

#### [NEW] `src/correlation/ioc_extractor.rs`
- Auto-extract IOCs from findings: IPs, domains, hashes, file paths, registry keys, mutex names
- Deduplication and classification
- STIX 2.1 bundle output

#### [MODIFY] [src/parsers/mod.rs](file:///Users/kali/Codes/wsl/memory_corelation/src/parsers/mod.rs) + `src/models/`
- **Structured scheduled task parsing** — parse `scheduled_task_records` into typed `ScheduledTask` model
- **DLL load time** inclusion in timeline
- **Service creation time** inclusion in timeline
- **UserAssist timestamp** inclusion in timeline

---

### Phase 3: Enhanced Timeline & Temporal Intelligence

#### [MODIFY] `src/correlation/timeline.rs`
- Add MFT, DLL load, service, scheduled task, and UserAssist events to timeline
- Add **temporal clustering**: detect bursts of activity (≥N events within T seconds)
- Add **hot-spot scoring**: automatically flag time windows with unusual density

#### [NEW] `src/output/timeline_export.rs`
- CSV export in Plaso/log2timeline super timeline format
- JSON timeline export for external visualization tools

#### [MODIFY] `src/output/html.rs`
- Interactive timeline visualization with zoom/filter/search
- Heatmap overlay showing event density over time
- Click timeline event → drill into artifact graph

---

### Phase 4: Kill Chain Visualization & Narrative Reporting

#### [NEW] `src/correlation/kill_chain.rs`
- Map findings to Cyber Kill Chain stages (Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions)
- Map findings to MITRE ATT&CK matrix view
- Compute attack progression score

#### [MODIFY] `src/output/html.rs`
- Kill Chain stage visualization with findings mapped to stages
- MITRE ATT&CK Navigator-style matrix heatmap
- Executive summary narrative auto-generation

#### [NEW] `src/output/pdf.rs`
- Court-ready PDF report generation using `printpdf` or `genpdf` crate
- Professional formatting with cover page, table of contents, executive summary

---

### Phase 5: Custom YAML Rules & Analysis Profiles

#### [NEW] `src/detection/yaml_rules.rs`
- YAML-based custom detection rule engine
- Sigma-compatible rule format
- Dynamic rule loading from `rules/` directory

#### [NEW] `src/config/profiles.rs`
- Analysis profiles (e.g., "Malware Triage", "Insider Threat", "Full Analysis")
- Each profile enables/disables rule sets and sets thresholds
- CLI flag: `--profile malware-triage`

---

### Phase 6: Advanced Artifact Parsing

#### [NEW] Various new parsers and models
- **Shimcache/Amcache**: Parse from registry data for program execution evidence
- **BAM/DAM**: Background Activity Moderator for program execution with timestamps
- **ShellBags**: Registry-based folder access history
- **Prefetch**: Program execution with timestamps and loaded DLLs
- **WMI Persistence**: EventConsumer/EventFilter subscription analysis
- **DNS Cache**: Resolved domain analysis

---

## Dependency Changes

#### [MODIFY] `Cargo.toml`
```toml
# Phase 1 — Artifact Graph
petgraph = "0.7"

# Phase 4 — PDF reports
genpdf = "0.2"

# Phase 5 — YAML rules
serde_yaml = "0.9"
```

---

## Verification Plan

### Automated Tests
- Each new module should have unit tests in `#[cfg(test)]` blocks
- Existing test infrastructure: `cargo test` (current tests use `tempfile` dev dependency)
- Run: `cargo test` to verify no regressions
- Run: `cargo build --release` to verify compilation

### Manual Verification
- Generate JSONL from a memory image using `generate_vol3_jsonl.sh`
- Run `vol3-correlate --input ./jsonl --output html` and inspect the HTML report
- Verify artifact graph visualization renders correctly
- Verify new timeline events appear in timeline section
- Verify IOC extraction output

---

## Recommended Starting Point

> [!TIP]
> I recommend starting with **Phase 1** (Artifact Graph) as it provides the single largest leap in correlation capability — this is what makes Axiom feel "magical". followed by **Phase 2** (wiring up unused detection structures + IOC extraction) which gives you immediate wins with minimal new code.
