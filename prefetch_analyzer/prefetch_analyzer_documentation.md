# Windows Prefetch Analyzer Tool Documentation

## Overview

This tool analyzes Windows Prefetch files using the **CSV/JSON output from Eric Zimmerman's PECmd tool** to generate detailed forensic reports. It automates the detection of suspicious execution patterns, malware indicators, and provides actionable intelligence for incident response.

---

## What Are Prefetch Files?

Windows Prefetch is a performance optimization mechanism introduced in Windows XP that tracks application execution. Each time a program runs, Windows creates or updates a corresponding `.pf` file in `%SystemRoot%\Prefetch`.

### Forensic Value

| Attribute | Description |
|-----------|-------------|
| **Location** | `C:\Windows\Prefetch\` |
| **File Format** | `<EXECUTABLE_NAME>-<HASH>.pf` |
| **Evidence Type** | Proof of Execution |
| **Windows Support** | XP SP3, Vista, 7, 8, 8.1, 10, 11, Server editions |

### Information Stored in Prefetch Files

- **Executable Name** — Name of the executed program
- **Run Count** — Total number of executions
- **Last Run Time** — Most recent execution timestamp
- **Previous Run Times** — Up to 8 timestamps (Windows 8+)
- **Files Loaded** — DLLs, data files accessed during first 10 seconds
- **Directories Referenced** — Paths accessed by the executable
- **Volume Information** — Source volume details

---

## PECmd Tool Overview

**PECmd** (Prefetch Explorer Command Line) is part of Eric Zimmerman's forensic toolkit. It parses prefetch files and exports structured data.

### PECmd Command Examples

```powershell
# Parse single file
PECmd.exe -f "C:\Windows\Prefetch\CMD.EXE-89305D47.pf"

# Parse entire prefetch directory to CSV
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Output" --csvf prefetch_output.csv

# Parse with JSON output
PECmd.exe -d "C:\Windows\Prefetch" --json "C:\Output"

# Timeline CSV output
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Output" -q

# Keyword highlighting
PECmd.exe -d "C:\Windows\Prefetch" -k "temp,tmp,downloads"
```

### PECmd Output Files

When processing a directory, PECmd generates:

1. **Main CSV** — `prefetch_output.csv` (parsed entries)
2. **Timeline CSV** — `prefetch_output_Timeline.csv` (execution timeline)

---

## PECmd CSV Output Schema

### Primary Output Columns

| Column Name | Description | Forensic Relevance |
|-------------|-------------|-------------------|
| `SourceFilename` | Prefetch file name | Evidence tracking |
| `SourceCreated` | Prefetch file creation time | First execution indicator |
| `SourceModified` | Prefetch file modification time | Last execution indicator |
| `SourceAccessed` | Prefetch file access time | Recent activity |
| `ExecutableName` | Name of executed program | Primary evidence |
| `Hash` | Prefetch hash (path-based) | Unique execution context |
| `Size` | Executable size | Anomaly detection |
| `Version` | Prefetch version | Windows version identification |
| `RunCount` | Total execution count | Usage frequency |
| `LastRun` | Most recent execution | Timeline reconstruction |
| `PreviousRun0` - `PreviousRun7` | Previous 8 execution times | Execution history |
| `FilesLoaded` | Tab-separated list of files | DLL/dependency analysis |
| `FilesLoadedCount` | Number of files loaded | Complexity indicator |
| `DirectoriesReferenced` | Paths accessed | Directory access patterns |
| `DirectoriesReferencedCount` | Number of directories | Scope indicator |
| `VolumeGuid` | Volume GUID | Source identification |
| `VolumeCreated` | Volume creation time | System timeline |
| `VolumeSerialNumber` | Volume serial | Hardware correlation |

### Timeline Output Columns

| Column Name | Description |
|-------------|-------------|
| `ExecutionTime` | Specific execution timestamp |
| `ExecutableName` | Program name |
| `SourceFile` | Prefetch file reference |

---

## Analysis Rules & Detection Logic

### 1. Suspicious Execution Locations

Flag executables launched from atypical paths:

```yaml
suspicious_paths:
  - pattern: "\\Users\\*\\Downloads\\"
    severity: MEDIUM
    description: "Execution from Downloads folder"
    
  - pattern: "\\Users\\*\\AppData\\Local\\Temp\\"
    severity: HIGH
    description: "Execution from Temp directory"
    
  - pattern: "\\Users\\Public\\"
    severity: HIGH
    description: "Execution from Public folder"
    
  - pattern: "\\Windows\\Temp\\"
    severity: HIGH
    description: "Execution from Windows Temp"
    
  - pattern: "\\ProgramData\\"
    severity: MEDIUM
    description: "Execution from ProgramData (non-installer)"
    
  - pattern: "\\$Recycle.Bin\\"
    severity: CRITICAL
    description: "Execution from Recycle Bin"
    
  - pattern: "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
    severity: HIGH
    description: "Startup folder persistence"
```

### 2. Known Malicious/Suspicious Tools

Detect execution of commonly abused utilities:

```yaml
malicious_tools:
  # Credential Dumping
  - executable: "MIMIKATZ"
    severity: CRITICAL
    category: "Credential Theft"
    mitre_att&ck: "T1003"
    
  - executable: "PROCDUMP"
    severity: HIGH
    category: "Memory Dumping"
    mitre_att&ck: "T1003.001"
    
  - executable: "LAZAGNE"
    severity: CRITICAL
    category: "Credential Theft"
    mitre_att&ck: "T1555"

  # Remote Access / Lateral Movement
  - executable: "PSEXEC"
    severity: HIGH
    category: "Lateral Movement"
    mitre_att&ck: "T1570"
    
  - executable: "PSEXESVC"
    severity: HIGH
    category: "PsExec Service"
    mitre_att&ck: "T1570"
    
  - executable: "WMIC"
    severity: MEDIUM
    category: "Remote Execution"
    mitre_att&ck: "T1047"

  # Data Exfiltration
  - executable: "RCLONE"
    severity: HIGH
    category: "Data Exfiltration"
    mitre_att&ck: "T1567"
    
  - executable: "MEGASYNC"
    severity: HIGH
    category: "Cloud Exfiltration"
    mitre_att&ck: "T1567.002"

  # Archiving (Ransomware Toolchain)
  - executable: "7Z"
    severity: MEDIUM
    category: "Archive Creation"
    mitre_att&ck: "T1560.001"
    
  - executable: "7ZA"
    severity: MEDIUM
    category: "Archive Creation"
    mitre_att&ck: "T1560.001"
    
  - executable: "RAR"
    severity: MEDIUM
    category: "Archive Creation"
    mitre_att&ck: "T1560.001"
    
  - executable: "WINRAR"
    severity: MEDIUM
    category: "Archive Creation"
    mitre_att&ck: "T1560.001"

  # Anti-Forensics
  - executable: "CCLEANER"
    severity: HIGH
    category: "Anti-Forensics"
    mitre_att&ck: "T1070"
    
  - executable: "SDELETE"
    severity: CRITICAL
    category: "Secure Deletion"
    mitre_att&ck: "T1070.004"
    
  - executable: "CIPHER"
    severity: HIGH
    category: "Secure Deletion"
    mitre_att&ck: "T1070.004"
    
  - executable: "ERASER"
    severity: HIGH
    category: "Secure Deletion"
    mitre_att&ck: "T1070.004"

  # Network Reconnaissance
  - executable: "NMAP"
    severity: HIGH
    category: "Network Scanning"
    mitre_att&ck: "T1046"
    
  - executable: "MASSCAN"
    severity: HIGH
    category: "Network Scanning"
    mitre_att&ck: "T1046"
    
  - executable: "ANGRY IP SCANNER"
    severity: MEDIUM
    category: "Network Scanning"
    mitre_att&ck: "T1046"
    
  - executable: "ADVANCED_IP_SCANNER"
    severity: MEDIUM
    category: "Network Scanning"
    mitre_att&ck: "T1046"
    
  - executable: "ADVANCED IP SCANNER"
    severity: MEDIUM
    category: "Network Scanning"
    mitre_att&ck: "T1046"

  # Remote Access Tools
  - executable: "ANYDESK"
    severity: MEDIUM
    category: "Remote Access"
    mitre_att&ck: "T1219"
    
  - executable: "TEAMVIEWER"
    severity: MEDIUM
    category: "Remote Access"
    mitre_att&ck: "T1219"
    
  - executable: "SCREENCONNECT"
    severity: MEDIUM
    category: "Remote Access"
    mitre_att&ck: "T1219"
    
  - executable: "CONNECTWISE"
    severity: MEDIUM
    category: "Remote Access"
    mitre_att&ck: "T1219"
    
  - executable: "SPLASHTOP"
    severity: MEDIUM
    category: "Remote Access"
    mitre_att&ck: "T1219"

  # Exploitation Tools
  - executable: "COBALTSTRIKE"
    severity: CRITICAL
    category: "C2 Framework"
    mitre_att&ck: "T1071"
    
  - executable: "BEACON"
    severity: CRITICAL
    category: "C2 Beacon"
    mitre_att&ck: "T1071"
    
  - executable: "SLIVER"
    severity: CRITICAL
    category: "C2 Framework"
    mitre_att&ck: "T1071"
    
  - executable: "BRUTERATEL"
    severity: CRITICAL
    category: "C2 Framework"
    mitre_att&ck: "T1071"
```

### 3. DLL Loading Analysis

Detect suspicious DLLs in `FilesLoaded`:

```yaml
suspicious_dlls:
  - pattern: "\\TEMP\\*.DLL"
    severity: CRITICAL
    description: "DLL loaded from Temp directory"
    
  - pattern: "\\DOWNLOADS\\*.DLL"
    severity: HIGH
    description: "DLL loaded from Downloads"
    
  - pattern: "MIMILIB.DLL"
    severity: CRITICAL
    description: "Mimikatz library detected"
    
  - pattern: "POWERSPLOIT"
    severity: CRITICAL
    description: "PowerSploit framework detected"
    
  - pattern: "INVOKE-MIMIKATZ"
    severity: CRITICAL
    description: "PowerShell Mimikatz detected"
```

### 4. Execution Frequency Anomalies

```yaml
frequency_rules:
  - condition: "RunCount == 1"
    severity: INFO
    description: "Single execution - potential one-time tool"
    
  - condition: "RunCount > 100 AND ExecutableCategory == 'System Tool'"
    severity: LOW
    description: "High frequency system tool usage"
    
  - condition: "RunCount > 50 AND ExecutableCategory == 'Archive Tool'"
    severity: HIGH
    description: "Unusually high archive tool usage"
    
  - condition: "Multiple executions within 5 minutes"
    severity: MEDIUM
    description: "Rapid sequential execution - possible automation"
```

### 5. LOLBin (Living Off The Land Binaries) Detection

```yaml
lolbins:
  # Script Engines
  - executable: "POWERSHELL"
    severity: MEDIUM
    context_check: true
    description: "PowerShell execution"
    mitre_att&ck: "T1059.001"
    
  - executable: "PWSH"
    severity: MEDIUM
    context_check: true
    description: "PowerShell Core execution"
    mitre_att&ck: "T1059.001"
    
  - executable: "CSCRIPT"
    severity: MEDIUM
    description: "Windows Script Host"
    mitre_att&ck: "T1059.005"
    
  - executable: "WSCRIPT"
    severity: MEDIUM
    description: "Windows Script Host"
    mitre_att&ck: "T1059.005"
    
  - executable: "MSHTA"
    severity: HIGH
    description: "HTML Application Host"
    mitre_att&ck: "T1218.005"

  # Download/Execute
  - executable: "CERTUTIL"
    severity: HIGH
    description: "Certificate utility (can download files)"
    mitre_att&ck: "T1140"
    
  - executable: "BITSADMIN"
    severity: HIGH
    description: "BITS download utility"
    mitre_att&ck: "T1197"
    
  - executable: "CURL"
    severity: MEDIUM
    description: "URL transfer tool"
    mitre_att&ck: "T1105"

  # Code Execution
  - executable: "REGSVR32"
    severity: HIGH
    description: "Registry server - script execution"
    mitre_att&ck: "T1218.010"
    
  - executable: "RUNDLL32"
    severity: MEDIUM
    context_check: true
    description: "DLL execution"
    mitre_att&ck: "T1218.011"
    
  - executable: "MSIEXEC"
    severity: MEDIUM
    description: "MSI installer"
    mitre_att&ck: "T1218.007"
    
  - executable: "INSTALLUTIL"
    severity: HIGH
    description: ".NET installer utility"
    mitre_att&ck: "T1218.004"

  # Scheduled Tasks / Persistence
  - executable: "SCHTASKS"
    severity: HIGH
    description: "Scheduled task utility"
    mitre_att&ck: "T1053.005"
    
  - executable: "AT"
    severity: HIGH
    description: "Legacy task scheduler"
    mitre_att&ck: "T1053.002"

  # Network Tools
  - executable: "NET"
    severity: MEDIUM
    description: "Network utility"
    mitre_att&ck: "T1087"
    
  - executable: "NET1"
    severity: MEDIUM
    description: "Network utility"
    mitre_att&ck: "T1087"
    
  - executable: "NETSH"
    severity: MEDIUM
    description: "Network shell"
    mitre_att&ck: "T1562.004"
    
  - executable: "NLTEST"
    severity: HIGH
    description: "Domain trust enumeration"
    mitre_att&ck: "T1482"
```

### 6. Ransomware Indicators

```yaml
ransomware_patterns:
  # Common Ransomware Tools
  - executable: "VSSADMIN"
    severity: CRITICAL
    description: "Shadow copy manipulation"
    mitre_att&ck: "T1490"
    
  - executable: "WBADMIN"
    severity: CRITICAL
    description: "Backup manipulation"
    mitre_att&ck: "T1490"
    
  - executable: "BCDEDIT"
    severity: CRITICAL
    description: "Boot configuration edit"
    mitre_att&ck: "T1490"
    
  - executable: "DISKSHADOW"
    severity: CRITICAL
    description: "Volume shadow copy manipulation"
    mitre_att&ck: "T1490"

  # Encryption Indicators
  - pattern: "RunCount > 10 AND ExecutableName contains 'CRYPT'"
    severity: CRITICAL
    description: "Potential encryption activity"
    
  - pattern: "Mass file access in FilesLoaded"
    severity: HIGH
    description: "Mass file modification pattern"
```

### 7. Multiple Prefetch Entries Analysis

Detect potential process masquerading:

```yaml
masquerading_detection:
  - condition: "Multiple prefetch entries for SVCHOST.EXE with different hashes"
    severity: HIGH
    description: "Possible svchost masquerading"
    mitre_att&ck: "T1036.003"
    
  - condition: "Multiple prefetch entries for RUNDLL32.EXE with different hashes"
    severity: MEDIUM
    description: "Rundll32 executed from multiple locations"
    
  - condition: "System executable hash mismatch"
    severity: CRITICAL
    description: "System binary executed from non-standard location"
```

---

## Expected Report Output Structure

### 1. Executive Summary

```markdown
# Prefetch Analysis Report

## Executive Summary
- **Analysis Date:** 2026-02-05
- **Total Prefetch Files Analyzed:** 847
- **Unique Executables:** 312
- **Date Range:** 2026-01-15 to 2026-02-05
- **Critical Findings:** 3
- **High Severity Findings:** 12
- **Medium Severity Findings:** 28
- **Suspicious Executions:** 43
```

### 2. Timeline View

```markdown
## Execution Timeline

| Timestamp | Executable | Run Count | Source Path | Severity |
|-----------|------------|-----------|-------------|----------|
| 2026-02-05 14:32:15 | MIMIKATZ.EXE | 1 | C:\Users\admin\Downloads\ | CRITICAL |
| 2026-02-05 14:30:45 | PSEXEC.EXE | 3 | C:\Tools\ | HIGH |
| 2026-02-05 14:25:12 | 7Z.EXE | 15 | C:\Program Files\7-Zip\ | MEDIUM |
```

### 3. Critical Findings Section

```markdown
## Critical Findings

### 🔴 Credential Theft Tool Executed
- **Executable:** MIMIKATZ.EXE
- **Hash:** 89305D47
- **First Seen:** 2026-02-05 14:32:15
- **Run Count:** 1
- **Files Loaded:** 47 files including sekurlsa.dll
- **MITRE ATT&CK:** T1003 - OS Credential Dumping
- **Recommendation:** Immediate incident response required

### 🔴 Shadow Copy Deletion Detected
- **Executable:** VSSADMIN.EXE
- **Execution Count:** 5
- **Context:** Executed after archive tool usage
- **MITRE ATT&CK:** T1490 - Inhibit System Recovery
- **Recommendation:** Check for ransomware activity
```

### 4. Detailed Findings by Category

```markdown
## Findings by Category

### Lateral Movement Tools
| Executable | Run Count | Last Run | Severity |
|------------|-----------|----------|----------|
| PSEXEC.EXE | 3 | 2026-02-05 14:30:45 | HIGH |
| WMIC.EXE | 12 | 2026-02-04 09:15:32 | MEDIUM |

### Anti-Forensics Activity
| Executable | Run Count | Last Run | Description |
|------------|-----------|----------|-------------|
| CCLEANER64.EXE | 2 | 2026-02-03 11:45:00 | System cleaning tool |
| SDELETE.EXE | 1 | 2026-02-05 15:00:00 | Secure file deletion |

### Remote Access Tools
| Executable | Run Count | First Seen | Last Run |
|------------|-----------|------------|----------|
| ANYDESK.EXE | 45 | 2026-01-20 | 2026-02-05 |
```

### 5. Suspicious Path Executions

```markdown
## Executions from Suspicious Locations

### Temp Directory Executions
| Executable | Full Path | Run Count | Status |
|------------|-----------|-----------|--------|
| UPDATE.EXE | C:\Users\admin\AppData\Local\Temp\ | 1 | SUSPICIOUS |
| HELPER.EXE | C:\Windows\Temp\ | 1 | SUSPICIOUS |

### Downloads Folder Executions  
| Executable | Run Count | Last Run | Risk |
|------------|-----------|----------|------|
| INSTALLER.EXE | 1 | 2026-02-01 | MEDIUM |
| TOOL.EXE | 1 | 2026-02-04 | HIGH |
```

### 6. DLL Analysis

```markdown
## Suspicious DLL Loading Detected

| Parent Executable | Suspicious DLL | Location | Severity |
|-------------------|----------------|----------|----------|
| RUNDLL32.EXE | MALICIOUS.DLL | C:\Users\Public\ | CRITICAL |
| CMD.EXE | HELPER.DLL | C:\Temp\ | HIGH |
```

### 7. Execution Statistics

```markdown
## Execution Statistics

### Most Frequently Executed (Top 20)
| Rank | Executable | Run Count | Category |
|------|------------|-----------|----------|
| 1 | CHROME.EXE | 1547 | Browser |
| 2 | EXPLORER.EXE | 892 | System |
| 3 | SVCHOST.EXE | 734 | System |

### Single Execution Programs (Potentially Suspicious)
| Executable | Last Run | Location | Risk Assessment |
|------------|----------|----------|-----------------|
| BEACON.EXE | 2026-02-05 | Temp | CRITICAL |
| PAYLOAD.EXE | 2026-02-04 | Downloads | HIGH |

### New Programs (First Seen in Analysis Period)
| Executable | First Execution | Run Count |
|------------|-----------------|-----------|
| NEWAPP.EXE | 2026-02-03 | 5 |
```

---

## Input Requirements

### PECmd CSV Input

```
Expected file: prefetch_output.csv
Required columns:
- SourceFilename
- ExecutableName  
- RunCount
- LastRun
- PreviousRun0-7 (optional)
- FilesLoaded
- DirectoriesReferenced
```

### PECmd Timeline Input

```
Expected file: prefetch_output_Timeline.csv
Required columns:
- ExecutionTime
- ExecutableName
- SourceFile
```

---

## Configuration Options

```yaml
# analyzer_config.yaml

input:
  main_csv: "path/to/prefetch_output.csv"
  timeline_csv: "path/to/prefetch_output_Timeline.csv"
  
output:
  report_path: "path/to/report.html"
  format: "html"  # Options: html, markdown, json
  
analysis:
  enable_dll_analysis: true
  enable_timeline_analysis: true
  enable_frequency_analysis: true
  
thresholds:
  high_frequency_threshold: 100
  rapid_execution_window_minutes: 5
  
whitelist:
  executables:
    - "CHROME.EXE"
    - "FIREFOX.EXE"
    - "MSEDGE.EXE"
  paths:
    - "C:\\Program Files\\"
    - "C:\\Program Files (x86)\\"
    - "C:\\Windows\\System32\\"
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Detection Method |
|--------------|----------------|------------------|
| T1003 | OS Credential Dumping | Mimikatz/Procdump detection |
| T1046 | Network Service Scanning | Nmap/Scanner detection |
| T1047 | Windows Management Instrumentation | WMIC execution |
| T1053.005 | Scheduled Task | Schtasks execution |
| T1059.001 | PowerShell | PowerShell execution |
| T1070 | Indicator Removal | CCleaner/SDelete detection |
| T1071 | Application Layer Protocol | C2 framework detection |
| T1105 | Ingress Tool Transfer | Certutil/Curl detection |
| T1197 | BITS Jobs | Bitsadmin detection |
| T1218 | Signed Binary Proxy Execution | LOLBin detection |
| T1219 | Remote Access Software | AnyDesk/TeamViewer detection |
| T1490 | Inhibit System Recovery | VSS/BCDEdit detection |
| T1560.001 | Archive Collected Data | 7Z/RAR detection |
| T1567 | Exfiltration Over Web Service | Rclone/MegaSync detection |
| T1570 | Lateral Tool Transfer | PsExec detection |

---

## Integration Points

### Input Sources
- Eric Zimmerman's PECmd CSV output
- PECmd JSON output
- PECmd Timeline output

### Output Formats
- HTML Report (interactive)
- Markdown Report
- JSON (for SIEM integration)
- CSV (for timeline tools)

### Correlation Opportunities
- Windows Event Logs (4688 - Process Creation)
- Sysmon Logs (Event ID 1)
- AmCache analysis
- ShimCache analysis
- MFT timeline

---

## References

- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- [SANS DFIR Prefetch Analysis](https://www.sans.org/blog/windows-prefetch-forensics/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Prefetch File Format Documentation](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-05 | Initial documentation |
