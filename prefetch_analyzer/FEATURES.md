# Prefetch Analyzer — Feature Reference

**Version:** 1.0.0  
**Author:** kaliHeker  
**Language:** Rust (2021 edition)  
**Build:** `cargo build --release` (LTO · opt-level=3 · binary-strip)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Input Format](#3-input-format)
4. [CLI Usage](#4-cli-usage)
5. [Detection Engine](#5-detection-engine)
   - 5.1 [Rule Categories](#51-rule-categories)
   - 5.2 [Per-Entry Checks](#52-per-entry-checks)
   - 5.3 [Cross-Entry Pattern Analysis](#53-cross-entry-pattern-analysis)
6. [Severity Model](#6-severity-model)
7. [Output Formats](#7-output-formats)
8. [HTML Report Sections](#8-html-report-sections)
9. [Visual Analytics — Charts](#9-visual-analytics--charts)
   - 9.1 [Run Count Distribution Histogram](#91-run-count-distribution-histogram)
   - 9.2 [Execution Timeline](#92-execution-timeline)
   - 9.3 [Execution Burst Scatter Plot](#93-execution-burst-scatter-plot)
   - 9.4 [File Path Treemap](#94-file-path-treemap)
   - 9.5 [DLL Load Graph (Radial)](#95-dll-load-graph-radial)
10. [False Positive Suppression](#10-false-positive-suppression)
11. [rules.yaml Reference](#11-rulesyaml-reference)
12. [Source File Map](#12-source-file-map)
13. [Performance Notes](#13-performance-notes)

---

## 1. Overview

`prefetch_analyzer` is a **Windows Prefetch forensic analysis tool** that consumes NDJSON output produced by Eric Zimmermann's [PECmd](https://github.com/EricZimmermann/PECmd) and generates a comprehensive, analyst-ready report.

It is designed for:
- Incident response triage on Windows systems
- Threat hunting across historical execution artefacts
- Timeline reconstruction from execution timestamps
- Detection of LOLBins, malicious tools, ransomware staging, and DLL-based attacks

The full output is a **self-contained single-file HTML report** — no internet connection required, no external CSS or JS dependencies. All charts and styles are embedded inline.

---

## 2. Architecture

```
main.rs
  └─ parser.rs          NDJSON → Vec<PrefetchEntry>
  └─ analyzer.rs        Detection engine — per-entry + cross-entry
       └─ rules.rs      rules.yaml loader + matching helpers
  └─ reporter.rs        HTML / Markdown / JSON output generators
  └─ models.rs          Shared data types (PrefetchEntry, Finding, AnalysisReport)
```

**Parallel analysis:** per-entry detection runs across a Rayon thread pool, making analysis of large datasets (1000+ entries) fast without sacrificing accuracy.

---

## 3. Input Format

Input must be **NDJSON** (newline-delimited JSON) — one JSON object per line — as produced by PECmd with the `-j` / `--json` flag:

```bash
PECmd.exe -d C:\Windows\prefetch --json prefetch_out.json
```

Key fields consumed per entry:

| PECmd Field | Description |
|---|---|
| `filename` | Full path to the `.pf` file |
| `executable_name` | Executable name (e.g. `CMD.EXE`) |
| `run_times` | Dictionary of `"Run N" → timestamp` |
| `num_files` | File reference count |
| `files` | Dictionary of `"File N" → path` |
| `volume_information` | Volume serial/label info |

---

## 4. CLI Usage

```
Usage: prefetch_analyzer [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>    Input JSON file (PECmd NDJSON output)
  -o, --output <OUTPUT>  Output report file
  -f, --format <FORMAT>  Output format: html | markdown | json  [default: html]
  -r, --rules <RULES>    Path to custom rules.yaml file
  -v, --verbose          Enable verbose output
  -q, --quiet            Quiet mode — minimal output
  -h, --help             Print help
  -V, --version          Print version
```

**Exit codes:**
- `0` — analysis complete, no critical findings
- `1` — one or more **Critical** severity findings detected

**Quick examples:**

```bash
# Standard HTML report
./prefetch_analyzer -i full.json -o report.html

# Quiet mode (CI/pipeline use)
./prefetch_analyzer -i full.json -o report.html -f html -q

# JSON output for downstream tooling
./prefetch_analyzer -i full.json -o findings.json -f json

# Custom rules file
./prefetch_analyzer -i full.json -o report.html -r /opt/custom_rules.yaml
```

---

## 5. Detection Engine

### 5.1 Rule Categories

Rules are loaded at runtime from `rules.yaml` (1309 lines, 104 named rules across executable categories plus 25 path/DLL pattern rules).

| Rule Section | Count | Severity Range | Purpose |
|---|---|---|---|
| `malicious_tools` | 53 rules | High–Critical | Known offensive tools: Mimikatz, Cobalt Strike, PsExec, etc. |
| `lolbins` | 42 rules | Medium–High | Living-off-the-land binaries: certutil, mshta, regsvr32, wmic, etc. |
| `ransomware_tools` | 9 rules | High–Critical | Ransomware-associated executables and staging tools |
| `suspicious_paths` | 25 patterns | Low–High | Execution from `\Temp\`, `\AppData\`, `\Downloads\`, `\Public\`, etc. |
| `suspicious_dlls` | 25 patterns | Medium–High | Hook DLLs, injection libraries, known malicious DLL names |
| `whitelist` | — | — | Safe executable/path exclusions to suppress noise |
| `installer_executables` | — | — | Known installer processes (VCREDIST, msiexec, setup.exe, etc.) |
| `installer_dll_patterns` | — | — | DLL patterns to skip during DLL scanning for installer processes |

Each rule optionally includes:
- `mitre_id` + `mitre_name` — ATT&CK technique reference
- `category` — human-readable sub-category label
- `description` — shown in the finding card

### 5.2 Per-Entry Checks

Every prefetch entry is evaluated independently across 5 checks (runs in parallel via Rayon):

#### Malicious Tool Detection
Matches `executable_name` against all `malicious_tools` rules. On match, a finding is created with:
- Full MITRE ATT&CK reference
- Execution path (resolved from the files dictionary)
- Run count and last-seen timestamp
- Rule category context string

#### LOLBin Detection
Matches against `lolbins` rules. Applies additional logic:
- If the executable is in a **whitelisted system path** AND severity ≤ Medium, the finding is suppressed (reduces noise for legitimate system use of `cmd.exe`, `powershell.exe`, etc. from `System32`)

#### Ransomware Indicator Detection
Matches against `ransomware_tools` rules. Produces High/Critical findings unconditionally (no whitelist suppression for ransomware).

#### Suspicious Path Detection
Checks the resolved execution path against all `suspicious_paths` patterns.  
Special handling is applied automatically:
- **VCREDIST/VC_REDIST installer detection** — paths matching `\WINDOWS\TEMP\{GUID}\.CR\` or `\.BE\` sub-directories are recognised as standard Microsoft Visual C++ Redistributable self-extraction staging. These are:
  - Annotated with a green "LIKELY BENIGN" card
  - Downgraded from High → **Low** severity
  - Flagged with `likely_benign_installer = true` for separate report rendering

#### Suspicious DLL Detection
Scans all loaded file references in `files` dictionary against `suspicious_dlls` patterns. Produces findings with:
- **Full DLL filename and complete file path** (not truncated)
- **Rule name and pattern** that triggered the match
- **Contextual explanations:**
  - *VMware context* — if the process is `VMTOOLSD.EXE` / `VMTOOLS*`, a note explains that VMware Tools legitimately loads hook/intercept DLLs and directs the analyst to verify path and digital signature
  - *Generic hook context* — if the matched pattern contains `HOOK`, an explanation of API hooking techniques and legitimate use cases (AV/EDR, accessibility tools) is added
- **Up to 20 non-system loaded files** attached as supporting evidence panel (paths outside `\Windows\System32\` and `\Windows\SysWOW64\`)
- Installer executables are fully skipped (no DLL scanning for known MSI/setup processes)

#### Single Execution Check
If `run_count == 1` **and** the execution path matches a suspicious path pattern **and** the executable is not whitelisted, a Medium-severity finding is generated. One-shot execution from suspicious paths is a common indicator for attack tools that are deployed, used once, and deleted.

### 5.3 Cross-Entry Pattern Analysis

After per-entry analysis completes, three cross-entry pattern detectors run against the full entry set:

#### Masquerading Detection (`T1036.003`)
Groups entries by executable name. Checks known system executables (`SVCHOST.EXE`, `RUNDLL32.EXE`, `CMD.EXE`, `POWERSHELL.EXE`) for multiple distinct execution paths. If any path falls outside whitelisted system directories, a **High** severity `Masquerading` finding is generated.

#### Multi-Path Execution / Hash Diversity Detection (`T1036`)
Windows prefetch filenames embed an 8-character hex hash computed from the full execution path (e.g., `DWM.EXE-314E93C5.pf`). Two `.pf` files for the same executable with **different hashes** prove the binary ran from at least two different directories.

This check:
- Groups all entries by normalised executable name
- Extracts the prefetch hash from each filename via `extract_prefetch_hash()`
- Any executable with ≥ 2 distinct hashes generates a `MultiPathExecution` finding
- Severity is **Medium** (or **Info** for whitelisted executables)
- Finding description includes all hashes with their corresponding paths
- MITRE reference: T1036 (Masquerading)

On real data (173 entries): **21 MultiPathExecution findings** were detected, covering tools like `REGSVR32.EXE`, `SCHTASKS.EXE`, and others run from multiple staging directories.

#### Rapid Execution Burst Detection (`TimelineAnomaly`)
Collects all execution timestamps across all entries and sorts them globally. If **5 or more unique processes** executed within a **5-minute window**, a Medium-severity `TimelineAnomaly` finding is produced, listing the processes and the burst start time. This pattern indicates automated tooling, scripted attacks, or ransomware staging chains.

---

## 6. Severity Model

| Level | Value | Typical Use |
|---|---|---|
| **Critical** | 5 | Confirmed offensive tool (Mimikatz, Cobalt Strike beacons, ransomware) |
| **High** | 4 | Malicious tool, ransomware indicator, process masquerading |
| **Medium** | 3 | LOLBin, multi-path execution, rapid burst, suspicious DLL |
| **Low** | 2 | Suspicious path (especially installer temp paths), single execution in suspicious location |
| **Info** | 1 | Whitelisted executable with hash diversity, informational context |

Exit code `1` is returned when any Critical finding is present, enabling automated pipeline alerting.

---

## 7. Output Formats

### HTML (default)
A fully self-contained single-file report (~838 KB for 173 entries). Contains:
- Interactive navigation bar with section anchors
- Finding cards with collapsible evidence panels
- Five interactive canvas/SVG charts
- Full-entry tables with all execution timestamps
- Chronological timeline table
- No external dependencies — works offline

### Markdown
Human-readable `.md` format, suitable for inclusion in incident response wikis, GitHub issues, or ticketing systems.

### JSON
Structured `AnalysisReport` output. Suitable for ingestion by downstream tooling (SIEM, case management, custom scripts). The `raw_entries` field is omitted from JSON output (`#[serde(skip)]`) to avoid duplication with the input data.

---

## 8. HTML Report Sections

The report is divided into anchored sections accessible from the top navigation bar:

| Section | Anchor | Content |
|---|---|---|
| Analytics | `#section-charts` | Five interactive visual charts (see §9) |
| Critical & High Findings | `#section-findings` | Detailed finding cards with MITRE refs, context, and evidence |
| All Findings | `#section-all-findings` | Condensed table of every finding, all severity levels |
| All Prefetch Entries | `#section-entry-table` | Every parsed `.pf` file: hash, executable, run count, first/last run, file load count, execution path |
| Execution Timestamps | `#section-timestamps` | All recorded timestamps per executable, grouped and sorted newest first |
| Full Timeline | `#section-timeline` | All execution events across all entries in strict chronological order |

### Critical/High Finding Cards
Each card includes:
- Severity badge + category label
- MITRE ATT&CK technique ID and name (linked to ATT&CK)
- Executable name and resolved execution path
- Run count and last-seen timestamp
- **Green "LIKELY BENIGN" annotation** when `likely_benign_installer = true`
- **Grey "ANALYST CONTEXT" block** — rule explanation, VMware notes, hooking context
- **Collapsible "Non-system loaded files / DLLs" panel** — up to 20 non-`System32` file paths as supporting evidence

### Analyst Context Section (Medium/Low)
A dedicated section renders full-detail context cards for Medium/Low findings that contain analyst notes (e.g., the VCREDIST installer findings with downgraded severity, or VMTOOLSD with its DLL evidence panel). This ensures no contextual detail is lost even for lower-severity findings.

### Complete Prefetch Entry Table
Every entry is listed with:
- Prefetch filename
- **8-character prefetch hash** (extracted from filename)
- Executable name
- Run count
- First run / Last run timestamps
- Loaded file count
- Resolved execution path

### Execution Timestamps
All `run_times` values per entry, one row per timestamp, sorted newest-first. Shows the complete historical activity record for each executable — not just first/last.

### Full Timeline
A unified chronological event log. Every recorded execution event across all 173 entries is sorted by actual timestamp and indexed, providing a global view of system activity in execution order.

---

## 9. Visual Analytics — Charts

All five charts are rendered in pure **vanilla JavaScript** using **HTML Canvas** and **inline SVG**. There are no CDN dependencies, no external libraries, and no network requests. Charts are fully functional offline and adapt to window resize events (debounced at 180ms).

Each chart uses a colour scheme tied to finding severity:
- 🔴 **Critical** — `#e74c3c`
- 🟠 **High** — `#e67e22`
- 🟡 **Medium** — `#f1c40f`
- 🔵 **Low** — `#3498db`
- ⚪ **Info / None** — `#95a5a6`

Chart data is injected once as a `const CHART_DATA = {...}` JSON block embedded in the page — no repeated DOM queries or re-computation on resize.

---

### 9.1 Run Count Distribution Histogram

**Type:** Bar chart (Canvas)  
**Purpose:** Shows how many executables fall into each execution-frequency bucket, revealing patterns in one-off tool deployment vs. persistent activity.

**Buckets:**
| Bucket | Range | Forensic Significance |
|---|---|---|
| `1×` | Exactly 1 run | Highest suspicion — potential one-shot attack tools |
| `2–5×` | 2–5 runs | Potentially recurring use or scripted invocations |
| `6–10×` | 6–10 runs | Regular usage or automated tasks |
| `11×+` | 11 or more runs | Persistent/scheduled processes |

**Visual encoding:**
- Each bar is coloured by the **highest severity finding** among all executables in that bucket (Critical → red, High → orange, etc.)
- Hovering a bar shows a scrollable tooltip listing every executable in the bucket, sorted by severity (critical-first), with run count and max severity label
- Bar height is proportional to total executable count in the bucket

**Data example (173 entries):** 68 single-run executables (18 flagged), 52 in 2–5× bucket (10 flagged), 53 in 6–10× bucket (8 flagged).

---

### 9.2 Execution Timeline

**Type:** Multi-lane dot plot (Canvas)  
**Purpose:** Provides a visual event stream showing when each executable ran over the entire date range, making clustering, co-occurrence, and dormancy periods immediately visible.

**Layout:**
- One horizontal **lane per unique executable**
- X-axis is absolute calendar time, spanning the full dataset date range
- Each dot represents one recorded execution event
- Dots are coloured by the **highest severity finding** associated with that executable (grey = no findings)
- Canvas height auto-scales to accommodate all lanes (typically 10–12 px per lane)
- Lanes are sorted by first-execution timestamp

**Interaction:**
- Hovering a dot shows a tooltip with: ISO timestamp, executable name, prefetch hash
- The canvas redraws with correct scale on window resize

**Data example:** 614 events across 173 executables spanning 2023-03-07 to 2024-09-23.

---

### 9.3 Execution Burst Scatter Plot

**Type:** Time-series area chart with threshold line (Canvas)  
**Purpose:** Detects abnormal execution density — moments where many processes ran within a short time window, which is a hallmark of automated attack chains, ransomware staging, or scripted enumeration.

**Algorithm:**
- For each execution event, counts the number of **unique processes** active in a rolling **60-second window** centred on that event
- Plots unique-process-count on the Y-axis against absolute time on the X-axis

**Visual encoding:**
- Area below the alert threshold (5 processes) is filled in **pale blue**
- Area above the threshold is filled in **pale red**
- A **dashed red line** marks the alert threshold at Y=5
- **Red dots** are plotted at burst peaks (local maxima above threshold)
- Hovering any point snaps to the nearest X position and shows: timestamp, unique process count

**Data example:** Peak burst of **27 unique processes** at `2024-09-23 05:17:33`.

---

### 9.4 File Path Treemap

**Type:** Nested-rectangle treemap (Canvas, slice-and-dice algorithm)  
**Purpose:** Visualises the directory distribution of all executed files. Makes it immediately clear how execution is distributed across the filesystem, and highlights unusual or unexpected directories.

**Layout:**
- Each rectangle represents a **directory** (parent path of executed files)
- Rectangle area is proportional to **total run count** from that directory
- Directories are partitioned using the slice-and-dice algorithm (alternating horizontal/vertical splits for child grouping)
- Labels are rendered when the box is ≥ 60×20 px

**Colour coding:**
- Directories containing executables with **Critical/High findings** → red-tinted border and background
- Directories flagged by **suspicious path rules** → orange-tinted
- All other directories → neutral grey-blue

**Hover tooltip:** Shows full directory path and lists all executables from that path with their run counts.

**Data example:** 53 distinct directories across 173 entries.

---

### 9.5 DLL Load Graph (Radial)

**Type:** Radial/ring diagram per executable (inline SVG)  
**Purpose:** For each executable that generated a **High or Critical finding** or triggered a `SuspiciousDll` detection, renders a visual map of all DLLs it loaded, classified by type, with suspicious DLLs prominently highlighted.

**Layout (per executable):**
- A **centre circle** coloured by the executable's max severity
- An **inner ring** of segments for non-system and suspicious DLLs (outside `\Windows\System32\` and `\Windows\SysWOW64\`)
- An **outer ring** of smaller segments for system `\System32\` / `\SysWOW64\` DLLs

**Colour classification:**
| Colour | Meaning |
|---|---|
| 🔴 Red + glow filter | Suspicious DLL — matched a `suspicious_dlls` rule |
| 🟡 Yellow | Non-system DLL — loaded from outside system directories |
| ⚫ Grey | System DLL — from `\System32\` or `\SysWOW64\` |

**Interaction:**
- Each segment has a hover tooltip (positioned fixed, follows cursor) showing: full DLL path and classification
- Segments too small to label individually are still accessible via hover

**Rendering:** Pure inline SVG generated at report time. One SVG element per flagged executable. Rendered in a responsive two-per-row grid.

**Data example (real data):**
| Executable | Suspicious DLLs | Non-System DLLs | System DLLs |
|---|---|---|---|
| REGSVR32.EXE (entry 1) | 0 | — | — |
| REGSVR32.EXE (entry 2) | 0 | — | — |
| VMTOOLSD.EXE | **1** | 17 | 42 |
| SCHTASKS.EXE | 0 | — | — |

---

## 10. False Positive Suppression

The tool includes several mechanisms to reduce analyst fatigue from noise:

### VCREDIST Installer Temp Paths
Microsoft Visual C++ Redistributable packages self-extract to `\WINDOWS\TEMP\{GUID}\.CR\` or `\{GUID}\.BE\` during installation. Without context, these paths match high-severity suspicious path rules.

Detection logic (`is_vcredist_temp_path()`):
1. Scans all `{` characters in the executable path
2. Validates GUID format: `{8-4-4-4-12}` hex digits with closing `}`
3. Confirms location under `\WINDOWS\TEMP\` or `\TEMP\`

On match:
- Severity is downgraded **High → Low**
- `likely_benign_installer = true` is set on the finding
- A detailed "LIKELY BENIGN" annotation is injected into the finding card

### Path Whitelist
The `whitelist.paths` section in `rules.yaml` lists known-safe execution paths. LOLBin findings with severity ≤ Medium are suppressed when the execution path is whitelisted.

### Executable Whitelist
The `whitelist.executables` section suppresses SingleExecution findings for common system utilities. `check_hash_diversity()` produces **Info** instead of **Medium** for whitelisted executables with multiple prefetch hashes.

### Installer DLL Exemption
Executables in `installer_executables` (e.g., `VCREDIST_X64.EXE`, `MSIEXEC.EXE`) are entirely skipped during `check_suspicious_dlls()`. DLL names matching `installer_dll_patterns` are skipped individually for all processes.

---

## 11. rules.yaml Reference

The rules file is loaded at startup. If it cannot be found, the tool falls back to embedded empty defaults (analysis will still run but with no detections).

Custom search order:
1. Path specified via `-r` / `--rules` flag
2. `rules.yaml` in the same directory as the binary
3. `rules.yaml` in the current working directory

**Rule schema (executable rules):**
```yaml
malicious_tools:
  - name: "mimikatz"
    description: "Mimikatz credential dumping tool detected"
    mitre_id: "T1003"
    mitre_name: "OS Credential Dumping"
    category: "Credential Access"
    severity: "critical"
    match_type: "contains"   # exact | contains | starts_with | ends_with | regex
    value: "mimikatz"
```

**Rule schema (path/DLL rules):**
```yaml
suspicious_paths:
  - name: "temp_execution"
    description: "Execution from TEMP directory"
    severity: "high"
    pattern: "\\TEMP\\"

suspicious_dlls:
  - name: "hook_dll"
    description: "Potential API hooking DLL"
    severity: "medium"
    pattern: "HOOK.DLL"
```

---

## 12. Source File Map

| File | Lines | Purpose |
|---|---|---|
| `src/main.rs` | 201 | CLI argument parsing, orchestration, banner, progress bar, exit codes |
| `src/models.rs` | 432 | All data types: `PrefetchEntry`, `Finding`, `AnalysisReport`, `Severity`, `FindingCategory` |
| `src/analyzer.rs` | 573 | Detection engine — 7 checks + cross-entry pattern analysis |
| `src/parser.rs` | 79 | NDJSON parser — one `PrefetchEntry` per line |
| `src/rules.rs` | 301 | `rules.yaml` loader, `RulesConfig`, matching helpers |
| `src/reporter.rs` | 2055 | HTML/Markdown/JSON report generators, all chart code |
| `rules.yaml` | 1309 | Detection rules (104 named executable rules, 25 path/DLL patterns) |

---

## 13. Performance Notes

- **Parallel analysis:** per-entry detection runs via Rayon across all available CPU cores. Analysis of 173 entries completes in under 1 second on modern hardware.
- **Release build:** compiled with LTO (link-time optimisation), `opt-level=3`, and binary stripping. The binary is portable and has no runtime dependencies beyond the `rules.yaml` file.
- **Memory:** all entries are held in memory during analysis. For very large datasets (10,000+ entries), memory usage scales linearly with the number of entries and their file reference lists. A 173-entry dataset uses ~10 MB peak.
- **Output size:** the HTML report for 173 entries with all charts is ~838 KB. For 1000+ entry datasets, the entry table and timeline sections scale linearly and the report may exceed 5 MB.
- **Chart data:** all five chart datasets are serialised once at report generation time and embedded as a single `const CHART_DATA` JSON block. Charts render client-side on page load in under 100ms.
