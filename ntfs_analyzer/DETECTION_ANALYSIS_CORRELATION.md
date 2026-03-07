# NTFS Forensic Analyzer — Detection, Analysis & Correlation Guide

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Analysis Pipeline](#2-analysis-pipeline)
3. [Input Data Model](#3-input-data-model)
4. [Detection Engine](#4-detection-engine)
   - 4.1 [Timestomping Detection (TS-001 – TS-004)](#41-timestomping-detection)
   - 4.2 [Mass File Operation Detection (MO-001 – MO-005)](#42-mass-file-operation-detection)
   - 4.3 [Suspicious Location Detection (SL-001 – SL-004)](#43-suspicious-location-detection)
   - 4.4 [Alternate Data Stream Anomalies (ADS-001 – ADS-004)](#44-alternate-data-stream-anomalies)
   - 4.5 [Deleted File Analysis (DF-001 – DF-003)](#45-deleted-file-analysis)
   - 4.6 [Temporal Anomaly Detection (TA-001 – TA-004)](#46-temporal-anomaly-detection)
   - 4.7 [Known Tool Detection (KT-001 – KT-002)](#47-known-tool-detection)
5. [Cross-Artifact Correlation Engine](#5-cross-artifact-correlation-engine)
6. [Timeline Generation](#6-timeline-generation)
7. [Rule Engine & Configuration](#7-rule-engine--configuration)
8. [Report Generation](#8-report-generation)
9. [Severity Model](#9-severity-model)
10. [Data Flow Diagram](#10-data-flow-diagram)

---

## 1. Architecture Overview

The NTFS Forensic Analyzer is a modular, high-performance Rust binary designed to ingest pre-parsed NTFS artifact data in JSON format and produce forensic intelligence through rule-based detection, multi-source correlation, and unified timeline construction.

### Core Modules

| Module | File | Purpose |
|---|---|---|
| **Models** | `src/models.rs` | All data structures — input schemas, findings, timeline events, reports |
| **Parser** | `src/parser.rs` | JSON input loading and structural validation |
| **Rule Engine** | `src/rules.rs` | TOML-based detection rule loader and query interface |
| **Correlation Engine** | `src/correlation.rs` | All detection logic and cross-artifact correlation chain builder |
| **Timeline Generator** | `src/timeline.rs` | Unified timeline from all NTFS sources with filtering and export |
| **Report Generator** | `src/report.rs` | Statistical aggregation and multi-format report output |
| **CLI** | `src/main.rs` | Command-line interface orchestrating the full pipeline |

### Design Principles

- **Separation of rules from logic** — Detection rules live in `rules/default_rules.toml` with tunable thresholds, not hardcoded in Rust.
- **Multi-source correlation** — Findings from one artifact source (e.g., MFT) are cross-referenced against others (USN, LogFile, I30) to build evidence chains.
- **Non-destructive analysis** — The tool operates on pre-parsed JSON data, never touching raw disk images.
- **Deterministic output** — Same input + same rules = same findings (except report UUIDs and generation timestamps).

---

## 2. Analysis Pipeline

When the `analyze` command runs, the following five-stage pipeline executes sequentially:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌──────────────┐    ┌────────────────┐
│ 1. LOAD     │───▶│ 2. RULES    │───▶│ 3. CORRELATE    │───▶│ 4. TIMELINE  │───▶│ 5. REPORT      │
│ Parse JSON  │    │ Load TOML   │    │ Run detections  │    │ Build events │    │ Export results │
│ Validate    │    │ rules file  │    │ Build chains    │    │ Sort/filter  │    │ JSON/TXT/HTML  │
└─────────────┘    └─────────────┘    └─────────────────┘    └──────────────┘    └────────────────┘
```

### Stage Details

1. **Load** — The parser reads a single JSON file or a directory of split files (`mft.json`, `usn.json`, `logfile.json`, `i30.json`, `case_info.json`). Validation ensures at least one artifact source has data.

2. **Rules** — The rule engine loads `rules/default_rules.toml` (or a user-specified TOML file). Falls back to minimal embedded defaults if the file is absent. Each rule has an ID, category, severity, enabled flag, and a `parameters` table for tunable thresholds.

3. **Correlate** — The correlation engine runs seven detection categories in sequence. Each detector iterates over the relevant artifact data, evaluates each applicable rule, and emits `Finding` structs when conditions are met. After all detectors complete, the cross-artifact correlation chain builder links related findings.

4. **Timeline** — All timestamps from all sources are extracted into a unified `TimelineEvent` list with consistent fields. Events are sorted chronologically and optionally filtered by date range.

5. **Report** — Statistics are computed, and the full `AnalysisReport` structure is assembled. It is then exported in the requested formats (JSON, text, HTML) with optional CSV/bodyfile timeline exports.

---

## 3. Input Data Model

The tool expects a JSON structure with the following top-level fields:

```json
{
  "case_info": { ... },       // Optional case metadata
  "volume_info": { ... },     // Optional NTFS volume information
  "mft_entries": [ ... ],     // Array of parsed MFT records
  "usn_records": [ ... ],     // Array of USN Journal change records
  "logfile_records": [ ... ], // Array of $LogFile transaction records
  "i30_entries": [ ... ]      // Array of $I30 directory index entries
}
```

### MFT Entry

Each MFT entry contains:
- **`standard_info`** — The `$STANDARD_INFORMATION` attribute (0x10): four MACB timestamps (modified, accessed, mft_modified, created), file attribute flags, and USN.
- **`file_names`** — One or more `$FILE_NAME` attributes (0x30): kernel-managed timestamps, filename, namespace (WIN32/DOS/POSIX), parent reference.
- **`data_streams`** — Default `$DATA` and any Alternate Data Streams (ADS): name, size, residency, content preview, data run list.
- **`flags`** — `in_use` (allocated vs. deleted) and `is_directory`.

### USN Journal Record

Each record captures a file system change event:
- **`reason_flags`** — Bitmask (e.g., `0x100` = FILE_CREATE, `0x200` = FILE_DELETE, `0x8000` = BASIC_INFO_CHANGE, `0x80000000` = CLOSE).
- **`reason_decoded`** — Human-readable strings for the bitmask.
- **`mft_entry_id`** — Links back to the MFT entry that changed.
- **`timestamp`** — When the change occurred.

### LogFile Record

Transaction-level changes from `$LogFile`:
- **`redo_operation` / `undo_operation`** — e.g., `InitializeFileRecordSegment`, `UpdateResidentValue`, `DeallocateFileRecordSegment`.
- **`target_mft_entry`** — Which MFT record was modified.
- **`target_attribute`** — Attribute type being changed (0x10 = $SI, 0x30 = $FN, 0x80 = $DATA).

### I30 Entry

Directory index entries including slack space recoveries:
- **`from_slack`** — Boolean indicating if this entry was carved from index node slack space (proves a deleted file existed in this directory).
- Standard MACB timestamps, filename, file/parent MFT references.

---

## 4. Detection Engine

The detection engine (`src/correlation.rs`) implements seven independent detector categories. Each detector:
1. Queries the rule engine for enabled rules in its category
2. Iterates over the relevant input artifacts
3. Evaluates rule-specific conditions using configurable thresholds from `[rules.parameters]`
4. Emits `Finding` structs with severity, evidence maps, affected paths, and investigative recommendations

### 4.1 Timestomping Detection

**Background:** NTFS stores two independent sets of four MACB timestamps per file. `$STANDARD_INFORMATION` (0x10) timestamps are modifiable by user-mode tools (SetFileTime API). `$FILE_NAME` (0x30) timestamps are kernel-managed and only updated by specific kernel operations (file creation, rename, content modification). Comparing these two sets is a primary anti-forensic detection technique.

#### Rule TS-001: SI Created Before FN Created
- **Logic:** For each MFT entry, compare `$SI.created` with `$FN.created`. If `$SI.created` is earlier than `$FN.created` by more than `min_difference_seconds` (default: 60s), flag it.
- **Rationale:** The `$FN` creation timestamp is set by the kernel when the file entry is created on this volume. The `$SI` creation time should never predate `$FN` unless it was manually backdated (timestomped).
- **Key distinction:** Small differences (<60s) can occur legitimately during cross-volume moves, hence the configurable threshold.

#### Rule TS-002: Zero Nanosecond Precision
- **Logic:** Count how many of the 4 `$SI` timestamps have zero sub-second (nanosecond) components. If ≥ `min_zero_timestamps` (default: 2) have zero sub-seconds AND the `$FN` timestamps have natural (non-zero) sub-second precision, flag it.
- **Rationale:** NTFS stores timestamps at 100-nanosecond resolution. Natural file operations produce effectively random sub-second values. Timestomping tools often use second-level precision only (e.g., SetFileTime from a tool that copies only seconds), leaving `.0000000` as a statistical anomaly.
- **Key distinction:** Only flags when `$FN` has natural precision — the differential confirms the zero precision comes from manipulation, not a system-wide clock quirk.

#### Rule TS-003: SI Timestamps Match Known System File Dates
- **Logic:** Compares `$SI` timestamp date portions against a list of known Windows system file dates (e.g., `2023-05-24`, `2022-05-10`).
- **Rationale:** Attackers frequently copy timestamps from legitimate system files (`kernel32.dll`, `ntdll.dll`) onto malware to blend into the OS directory.

#### Rule TS-004: USN BASIC_INFO_CHANGE With Old Timestamps
- **Logic:** Pre-builds a HashMap of `mft_entry_id → [USN records with BASIC_INFO_CHANGE flag (0x8000)]`. For each MFT entry with a BASIC_INFO_CHANGE event, compares the USN event timestamp to `$SI.created`. If the `$SI` creation date is more than `max_age_difference_days` (default: 30) older than the BASIC_INFO_CHANGE event, flag it.
- **Rationale:** The BASIC_INFO_CHANGE reason code fires when file attributes or timestamps are explicitly modified via the SetFileInfo API. If a file appears old but has a recent BASIC_INFO_CHANGE, someone deliberately set the timestamps to an old value.
- **Cross-artifact power:** This rule inherently correlates MFT and USN Journal data, providing stronger evidence than either source alone.

### 4.2 Mass File Operation Detection

**Background:** Certain attack patterns (ransomware encryption, evidence destruction, data staging) produce characteristic bursts of homogeneous file operations visible in the USN Journal.

#### Sliding Window Algorithm

All mass operation rules (MO-001 through MO-005) use a **sliding window detector**:

```
Input:  Sorted list of timestamped USN records filtered by operation type
Method: Two-pointer sliding window over timestamps

for each end pointer:
    advance start pointer while (window > time_window_seconds)
    window_count = end - start + 1
    track the maximum window_count and its boundaries

if max_window_count >= min_threshold:
    emit finding with the densest window as evidence
```

This efficiently finds the densest cluster of operations within the configured time window, running in O(n) time.

#### Rule MO-001: Mass File Rename (Ransomware Indicator)
- **Filter:** USN records with `RENAME_NEW_NAME` flag (0x2000)
- **Defaults:** 50+ renames within 60 seconds
- **Indicator:** Ransomware encryption characteristically renames files with new extensions (`.docx` → `.encrypted`)
- **Severity:** Critical

#### Rule MO-002: Mass File Deletion
- **Filter:** USN records with `FILE_DELETE` flag (0x200)
- **Defaults:** 50+ deletions within 120 seconds
- **Indicator:** Evidence destruction or ransomware post-encryption cleanup
- **Severity:** High

#### Rule MO-003: Mass File Creation
- **Filter:** USN records with `FILE_CREATE` flag (0x100)
- **Defaults:** 100+ creations within 120 seconds
- **Indicator:** Malware deployment, archive extraction, data staging
- **Severity:** Medium

#### Rule MO-005: Mass Extension Change
- **Logic:** Tracks rename pairs (RENAME_OLD_NAME → RENAME_NEW_NAME for same `mft_entry_id`). Extracts file extensions before/after. Groups by new extension and checks if a single extension gained ≥ `min_changes` (default: 20) files within the time window.
- **Indicator:** Strongest ransomware signal — many files with different original extensions all renamed to the same new extension (e.g., `.locked`).
- **Severity:** Critical

### 4.3 Suspicious Location Detection

**Background:** Malware and attack tools have predictable filesystem placement patterns. Detecting executables in unexpected locations provides rapid triage indicators.

#### Rule SL-001: Executable in Temp Directory
- **Logic:** For allocated MFT entries, checks if the filename has an executable extension AND the full path contains a temp directory pattern (`\Temp\`, `\AppData\Local\Temp\`, `\Windows\Temp\`).
- **Configurable:** Both the extension list and path patterns are tunable in the rule parameters.

#### Rule SL-004: Executable Masquerading as System File
- **Logic:** Checks if the filename matches a known Windows system process name (`svchost.exe`, `csrss.exe`, `lsass.exe`, etc.) but the file path does NOT contain the legitimate locations (`\Windows\System32\`, `\Windows\SysWOW64\`).
- **Rationale:** Process masquerading is one of the most common malware evasion techniques. A `svchost.exe` outside System32 is almost certainly malicious.
- **Severity:** High

### 4.4 Alternate Data Stream Anomalies

**Background:** NTFS supports multiple named data streams per file. The default unnamed `$DATA` stream holds the file's content. Additional named streams (ADS) are invisible to standard directory listings and can hide arbitrary data.

#### Rule ADS-001: Non-Standard ADS
- **Logic:** For every named data stream on every MFT entry, checks against a whitelist of known safe stream names (`Zone.Identifier`, `encryptable`, `SummaryInformation`, `DocumentSummaryInformation`, `favicon`).
- **Any stream not in the safe list is flagged.**

#### Rule ADS-002: Large ADS
- **Logic:** Flags streams exceeding `size_threshold_bytes` (default: 10,240 bytes / 10KB).
- **Rationale:** Legitimate ADS (e.g., Zone.Identifier) are typically <1KB. Large streams may contain hidden executables, archives, or exfiltrated data.

#### Rule ADS-003: Executable Content in ADS
- **Logic:** If the ADS has captured content (resident data), checks whether it begins with known executable signatures: `MZ` (PE executable), `TVqQ` (base64-encoded PE), `#!/` (script shebang), `powershell`, `cmd /c`, `<script`, `<?xml`.
- **Severity:** Critical — an executable payload hidden in an ADS is a strong malware indicator.

#### Rule ADS-004: Zone.Identifier Internet Download
- **Logic:** Detects Zone.Identifier ADS with ZoneId=3 (Internet) or ZoneId=4 (Restricted Sites).
- **Severity:** Info — marks files as internet-sourced, valuable for tracing intrusion origin.

### 4.5 Deleted File Analysis

**Background:** When a file is deleted in NTFS, its MFT record is marked as unallocated (flag: `in_use = false`) but the metadata typically persists until the record is reused. Additionally, directory index (`$I30`) entries may persist in slack space. The USN Journal records deletion events.

#### Rule DF-001: Recently Deleted Executables
- **Logic:** Iterates over unallocated (`in_use = false`) MFT entries. If the filename has an executable extension, flag it.
- **Rationale:** Attackers commonly delete tools after use. Even without file content, the metadata (timestamps, size, path) proves the tool existed.

#### Rule DF-002: I30 Slack Space Recoveries
- **Logic:** Counts I30 entries with `from_slack = true` and reports them as a batch finding.
- **Rationale:** I30 slack recoveries prove file existence in a directory even when the MFT entry has been reused, providing evidence that survives longer than MFT-based recovery.

#### Rule DF-003: Deleted Archives/Containers
- **Logic:** Flags deleted files with archive extensions (`.zip`, `.7z`, `.rar`, `.tar.gz`) or encrypted container extensions (`.tc`, `.hc`, `.vhd`, `.vhdx`).
- **Rationale:** Data exfiltration pattern: collect files into archive → transfer → delete archive to cover tracks.

### 4.6 Temporal Anomaly Detection

**Background:** Temporal patterns in filesystem activity reveal anomalous behavior that may not be caught by content-based analysis.

#### Rule TA-001: Off-Hours File Activity
- **Logic:** Counts USN Journal events where the timestamp hour falls outside configurable business hours (default: 07:00–19:00 UTC). If count ≥ `min_off_hours_events` (default: 20), flags with sample events.
- **Recommendation:** Correlate with Windows Security Event Log Event ID 4624 (logon events) to identify who was active.

#### Rule TA-002: Activity Gap (Log Deletion)
- **Logic:** Sorts all USN Journal timestamps. Scans consecutive pairs for gaps exceeding `min_gap_hours` (default: 4 hours). Each gap generates a finding.
- **Rationale:** Gaps may indicate: USN Journal tampering/deletion, system offline period, or deliberate log clearing. Cross-referencing with `$LogFile` and Windows Event Logs (startup/shutdown Event IDs 6005/6006) disambiguates.

#### Rule TA-003: Future Timestamps
- **Logic:** Checks all four `$SI` timestamps against the current UTC time. Any timestamp in the future is flagged.
- **Rationale:** Nearly always indicates timestamp manipulation or system clock tampering.

#### Rule TA-004: Accessed Before Created
- **Logic:** Compares `$SI.accessed` with `$SI.created`. If accessed < created, flag as a causality violation.
- **Rationale:** A file cannot be accessed before it was created. This indicates metadata corruption or deliberate manipulation.

### 4.7 Known Tool Detection

**Background:** The presence of known offensive security tools — even deleted — constitutes forensic evidence of attacker activity. This detector searches across all artifact sources.

#### Rule KT-001: Known Attack Tools
- **Logic:**
  1. Collects filenames from three sources: active MFT entries, deleted MFT entries, I30 slack space recoveries, and USN Journal FILE_DELETE records.
  2. For each collected filename, compares the lowercased name and stem against a configurable list of 100+ known attack tool names (`mimikatz`, `procdump`, `psexec`, `bloodhound`, `cobalt`, `meterpreter`, `lazagne`, etc.).
  3. Each match generates a finding stating the tool name, filename, source, and state (active/deleted).
- **Multi-source coverage:** By scanning MFT active, MFT deleted, I30 slack, AND USN deletion records, the detector finds tools even if the attacker:
  - Deleted the file (still in MFT unallocated)
  - Deleted and the MFT entry was reused (still in I30 slack)
  - I30 was overwritten (still in USN Journal deletion event)
- **Severity:** Critical

#### Rule KT-002: Known Wiping Tools
- **Logic:** Same methodology as KT-001 but with a separate list of known anti-forensic/wiping tools (`eraser`, `sdelete`, `bleachbit`, `ccleaner`, `cipher`, etc.).
- **Rationale:** Presence of wiping tools demonstrates intent to destroy evidence, which is itself forensically significant.
- **Severity:** High

---

## 5. Cross-Artifact Correlation Engine

After all seven detectors complete, the **correlation chain builder** (`build_correlation_chains()`) creates structured evidence narratives by linking findings across artifact sources.

### What Is a Correlation Chain?

A `CorrelationChain` is an ordered sequence of `CorrelationEvent`s from different artifact sources (MFT, USN Journal, LogFile, I30) that together tell a coherent forensic story. Each chain has:
- **chain_id** — Unique identifier (e.g., `CHAIN-001`)
- **description** — What the chain describes
- **severity** — Highest severity among constituent events
- **events** — Ordered list of correlated events with timestamps, sources, and evidence
- **conclusion** — Human-readable forensic conclusion drawn from the chain

### Chain Type 1: Timestomping Correlation

**Trigger:** Any finding in the `timestomping` category with an `affected_entry_id`.

**Construction:**
1. Start with the timestomping finding from MFT analysis (e.g., TS-001 $SI/$FN discrepancy)
2. Query USN Journal for ALL records matching the same `mft_entry_id`
3. Add each related USN event as a `CorrelationEvent` with its reason codes
4. Sort all events chronologically
5. Generate a conclusion that quantifies the corroborating evidence

**Example narrative:**
```
CHAIN-001: Timestomping correlation for MFT#39
  1. [MFT]         02:47:11 — $SI/$FN timestamp discrepancy (985 days)
  2. [USN Journal]  02:47:11 — FILE_CREATE (svchost.exe)
  3. [USN Journal]  02:47:12 — DATA_EXTEND
  4. [USN Journal]  02:47:12 — BASIC_INFO_CHANGE ← proves timestamp was explicitly set
  5. [USN Journal]  02:47:12 — CLOSE

  CONCLUSION: File MFT#39 shows timestamp manipulation corroborated by 4 USN Journal
  events. The combination of $SI/$FN discrepancy and USN activity confirms deliberate
  anti-forensic modification.
```

**Why it matters:** The MFT finding alone shows *what* happened (timestamps differ). The USN chain shows *when* and *how* — the BASIC_INFO_CHANGE event proves the timestamps were explicitly manipulated, not just a side effect of a file copy.

### Chain Type 2: Multiple Attack Tools

**Trigger:** Two or more findings in the `known_tools` category.

**Construction:**
1. Collects all known tool findings
2. Groups them into a single chain with all evidence
3. Lists the distinct tool names found

**Example:**
```
CHAIN-006: Multiple attack tools detected on system
  1. mimikatz.exe   (deleted, MFT)    — credential dumping tool
  2. procdump64.exe (deleted, MFT)    — memory dump tool for LSASS
  3. lazagne.exe    (deleted, I30 slack) — password recovery tool

  CONCLUSION: Multiple known attack tools detected: [mimikatz, procdump, lazagne].
  The presence of multiple offensive tools strongly suggests this system was compromised
  and used as a staging point for further attacks.
```

### How Correlation Adds Value

| Evidence Source Alone | Correlation Value |
|---|---|
| MFT shows old timestamp | Could be legitimate |
| MFT old timestamp + USN BASIC_INFO_CHANGE | Confirms deliberate manipulation |
| USN shows FILE_DELETE for mimikatz | Tool existed |
| I30 slack also has mimikatz + MFT has procdump | Proves multi-tool attack campaign |
| LogFile shows $SI modification + USN BASIC_INFO_CHANGE | Triple-source confirmation of timestomping |

---

## 6. Timeline Generation

The timeline generator (`src/timeline.rs`) creates a unified chronological view of all NTFS activities from every artifact source.

### Sources and Events Per Source

| Source | Tag | Events Generated Per Record |
|---|---|---|
| MFT `$STANDARD_INFORMATION` | `MFT_SI` | 4 (CREATED, MODIFIED, ACCESSED, MFT_MODIFIED) |
| MFT `$FILE_NAME` | `MFT_FN` | 4 per namespace (CREATED, MODIFIED, ACCESSED, MFT_MODIFIED) |
| USN Journal | `USN` | 1 per record (event type = decoded reason flags joined by `\|`) |
| `$LogFile` | `LOGFILE` | 1 per record (event type = redo operation) |
| `$I30` Index (active) | `I30` | 4 (CREATED, MODIFIED, ACCESSED, MFT_MODIFIED) |
| `$I30` Index (slack) | `I30_SLACK` | 4 (CREATED, MODIFIED, ACCESSED, MFT_MODIFIED) |

### Timeline Event Structure

Every event is normalized to a common format:
```
{
  timestamp:    DateTime<Utc>,     // Normalized UTC timestamp
  source:       "MFT_SI",          // Which artifact produced this event
  event_type:   "CREATED",         // What type of event
  path:         "\\path\\to\\file", // File path (with [DELETED] tag if applicable)
  entry_id:     Some(39),          // MFT entry reference
  description:  "[$SI] File created (MFT#39)",
  metadata:     { "entry_id": "39", "deleted": "true", ... }
}
```

### Filtering

- **Date Range:** Optional `--start-date` and `--end-date` parameters (YYYY-MM-DD). Events outside the range are excluded during generation (not post-filtered), preserving performance.
- Events are sorted chronologically after all sources are merged.

### Export Formats

- **CSV:** Standard comma-separated with header: `Timestamp,Source,EventType,Path,EntryID,Description`
- **Bodyfile:** Sleuth Kit-compatible format: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` — directly usable with `mactime` for timeline analysis.
- **JSON:** Serialized `Vec<TimelineEvent>` (via the `timeline` subcommand with `--format json`).

---

## 7. Rule Engine & Configuration

### Rule File Format (TOML)

```toml
[metadata]
version = "1.0.0"
author = "NTFS Forensic Analyzer"
description = "Default detection rules"

[[rules]]
id = "TS-001"                    # Unique rule ID
name = "SI Created Before FN"    # Human-readable name
category = "timestomping"        # Detection category
description = "..."              # Detailed description
severity = "High"                # Info | Low | Medium | High | Critical
enabled = true                   # Can be disabled without removing

[rules.parameters]               # Rule-specific thresholds
min_difference_seconds = 60      # Tunable per-environment
```

### Rule Categories

| Category | Rule IDs | Count | Purpose |
|---|---|---|---|
| `timestomping` | TS-001 – TS-004 | 4 | Anti-forensic timestamp manipulation |
| `mass_operation` | MO-001 – MO-005 | 5 | Ransomware, wiping, staging patterns |
| `suspicious_location` | SL-001 – SL-004 | 4 | Files in unexpected directories |
| `ads_anomaly` | ADS-001 – ADS-004 | 4 | Hidden/malicious alternate data streams |
| `deleted_files` | DF-001 – DF-003 | 3 | Deleted file metadata analysis |
| `temporal_anomaly` | TA-001 – TA-004 | 4 | Timing-based behavioral anomalies |
| `known_tools` | KT-001 – KT-002 | 2 | Attack tool and wiping tool detection |

### Rule Loading Priority

1. User-specified file (`--rules path/to/custom.toml`)
2. Default file discovery (relative to executable, then CWD): `rules/default_rules.toml`
3. Embedded fallback — minimal hardcoded rules (TS-001, TS-002, MO-001, MO-002) compiled into the binary

### Customization

To tune for your environment:
- **Reduce false positives:** Increase thresholds (e.g., `min_renames = 100`, `min_off_hours_events = 50`)
- **Add context:** Extend `known_safe_streams` for legitimate ADS in your environment
- **Custom business hours:** Adjust `business_hours_start` and `business_hours_end` for your timezone
- **Disable rules:** Set `enabled = false` for rules that don't apply
- **Add known system file dates:** Extend `known_system_dates` for your OS version/patch level

---

## 8. Report Generation

### Report Structure

The `AnalysisReport` contains:

| Section | Content |
|---|---|
| **Header** | Report UUID, generation timestamp, tool version |
| **Case Info** | Case ID, examiner, description, image hashes |
| **Volume Info** | Volume label, serial number, cluster size |
| **Statistics** | Counts for all artifact types, findings by severity, timeline events |
| **Findings** | Ordered list of all findings (Critical first), each with rule ID, evidence, recommendation |
| **Correlation Chains** | Multi-source evidence narratives with conclusions |
| **Deleted Files Inventory** | Every deleted file with MFT#, filename, size, deletion timestamp, recovery source |
| **ADS Inventory** | Every alternate data stream with suspicion status and content preview |
| **Timeline** | Full chronological event list |

### Output Formats

| Format | File | Use Case |
|---|---|---|
| **JSON** | `report.json` | Machine-readable, import into SIEM/SOAR, programmatic analysis |
| **Text** | `report.txt` | Human-readable terminal output with ANSI color codes stripped |
| **HTML** | `report.html` | Standalone dark-themed report for browser viewing and sharing |
| **CSV** | `timeline.csv` | Timeline import into spreadsheet or timeline analysis tools |
| **Bodyfile** | `timeline.bodyfile` | Sleuth Kit `mactime` compatible format |

### Statistics Computed

- Total MFT entries (allocated vs. deleted, files vs. directories)
- Resident data files (content stored inside MFT record itself)
- USN Journal, LogFile, and I30 record counts (with I30 slack breakdown)
- Findings by severity (Critical, High, Medium, Low, Info)
- Total timeline events generated
- Files with detected timestomping
- Deleted files with recoverable metadata
- Total ADS found (with suspicious count)

---

## 9. Severity Model

Findings are classified using a 5-level severity model:

| Level | Color | Meaning | Example Rules |
|---|---|---|---|
| **Critical** | Red background | Immediate threat indicator, requires urgent action | KT-001 (attack tools), MO-001 (ransomware renames), ADS-003 (executable in ADS) |
| **High** | Red text | Strong indicator of compromise or anti-forensics | TS-001 (timestomping), SL-004 (masquerading), DF-003 (deleted archives) |
| **Medium** | Yellow | Suspicious activity warranting investigation | TS-002 (zero nanoseconds), SL-001 (exe in temp), ADS-001 (unknown ADS) |
| **Low** | Blue | Informational finding with potential relevance | DF-002 (I30 slack entries), TA-001 (off-hours activity) |
| **Info** | Gray | Contextual information for the investigation record | ADS-004 (Zone.Identifier download marker) |

Findings in the report are **sorted by severity** (Critical first, Info last), ensuring investigators see the most urgent items immediately.

---

## 10. Data Flow Diagram

```
                           ┌──────────────────────┐
                           │   JSON Input File     │
                           │                       │
                           │  ┌── mft_entries[]    │
                           │  ├── usn_records[]    │
                           │  ├── logfile_records[] │
                           │  └── i30_entries[]    │
                           └──────────┬───────────┘
                                      │
                              ┌───────▼───────┐
                              │  Parser       │
                              │  (parser.rs)  │
                              │  Validate &   │
                              │  Deserialize  │
                              └───────┬───────┘
                                      │
                                      ▼
                     ┌─────────────────────────────────┐
                     │        NtfsInput (in memory)     │
                     │                                  │
                     │   Vec<MftEntry>                  │
                     │   Vec<UsnRecord>                 │
                     │   Vec<LogFileRecord>             │
                     │   Vec<I30Entry>                  │
                     └──────────┬──────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                  │
              ▼                 ▼                  ▼
    ┌─────────────────┐ ┌────────────────┐ ┌──────────────┐
    │  Rule Engine     │ │  Correlation   │ │  Timeline    │
    │  (rules.rs)      │ │  Engine        │ │  Generator   │
    │                  │ │  (correlation  │ │  (timeline   │
    │  Load TOML       │ │  .rs)          │ │  .rs)        │
    │  Parse rules     │ │                │ │              │
    │  Index by        │ │  7 Detectors   │ │  Merge all   │
    │  category        │ │  + Chain       │ │  timestamps  │
    │                  │ │  Builder       │ │  Sort chrono  │
    └────────┬────────┘ └───────┬────────┘ └──────┬───────┘
             │                  │                  │
             └──────────────────┼──────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Report Builder     │
                    │    (report.rs)        │
                    │                      │
                    │  Compute statistics  │
                    │  Assemble report     │
                    │  Export formats       │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                  ▼
        report.json       report.txt         report.html
                   timeline.csv  timeline.bodyfile
```

### Detection Flow Within Correlation Engine

```
run_correlation()
    │
    ├── detect_timestomping()        ──▶ TS-001, TS-002, TS-003, TS-004
    │       Read: MFT entries + USN records (pre-indexed by BASIC_INFO_CHANGE)
    │
    ├── detect_mass_operations()     ──▶ MO-001, MO-002, MO-003, MO-005
    │       Read: USN records (sorted by timestamp, sliding window)
    │
    ├── detect_suspicious_locations() ──▶ SL-001, SL-002, SL-003, SL-004
    │       Read: Allocated MFT entries
    │
    ├── detect_ads_anomalies()       ──▶ ADS-001, ADS-002, ADS-003, ADS-004
    │       Read: MFT entries → data_streams (non-default)
    │
    ├── detect_deleted_file_anomalies() ──▶ DF-001, DF-002, DF-003
    │       Read: Unallocated MFT entries + I30 slack entries
    │
    ├── detect_temporal_anomalies()  ──▶ TA-001, TA-002, TA-003, TA-004
    │       Read: USN records (hour analysis, gap detection) + MFT entries
    │
    ├── detect_known_tools()         ──▶ KT-001, KT-002
    │       Read: MFT (active+deleted) + I30 slack + USN (FILE_DELETE)
    │
    └── build_correlation_chains()
            Read: All findings + USN records
            Output: CorrelationChain[]
```

---

## Appendix: USN Journal Reason Code Reference

The following bitmask values are decoded by the tool:

| Hex Value | Name | Forensic Significance |
|---|---|---|
| `0x00000001` | DATA_OVERWRITE | File content was overwritten |
| `0x00000002` | DATA_EXTEND | File grew in size |
| `0x00000004` | DATA_TRUNCATION | File was truncated |
| `0x00000010` | NAMED_DATA_OVERWRITE | ADS content overwritten |
| `0x00000020` | NAMED_DATA_EXTEND | ADS grew in size |
| `0x00000040` | NAMED_DATA_TRUNCATION | ADS was truncated |
| `0x00000100` | FILE_CREATE | New file created |
| `0x00000200` | FILE_DELETE | File deleted |
| `0x00000400` | EA_CHANGE | Extended attributes changed |
| `0x00000800` | SECURITY_CHANGE | ACL/permissions modified |
| `0x00001000` | RENAME_OLD_NAME | Rename: old name recorded |
| `0x00002000` | RENAME_NEW_NAME | Rename: new name recorded |
| `0x00004000` | INDEXABLE_CHANGE | Content indexing flag changed |
| `0x00008000` | BASIC_INFO_CHANGE | Timestamps/attributes explicitly modified |
| `0x00010000` | HARD_LINK_CHANGE | Hard link added/removed |
| `0x00020000` | COMPRESSION_CHANGE | Compression state changed |
| `0x00040000` | ENCRYPTION_CHANGE | Encryption state changed |
| `0x00080000` | OBJECT_ID_CHANGE | Object ID assigned/changed |
| `0x00100000` | REPARSE_POINT_CHANGE | Reparse point (junction/symlink) changed |
| `0x00200000` | STREAM_CHANGE | Data stream added/removed |
| `0x80000000` | CLOSE | File handle closed (final event in sequence) |
