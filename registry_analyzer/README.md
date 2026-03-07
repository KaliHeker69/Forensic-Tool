# KaliHeker Registry Analyzer

A high-performance Windows Registry forensic analysis tool written in Rust. Accepts parsed registry data in JSON format and generates a detailed HTML report with the KaliHeker dark theme.

## Features

### Detection Categories

| Category | What it Detects |
|---|---|
| **Persistence** | Run/RunOnce keys, malicious services, Winlogon hijacks, IFEO abuse, AppInit_DLLs, BHOs, scheduled tasks |
| **Program Execution** | BAM/DAM records, LOLBin usage, suspicious process paths, encoded PowerShell commands |
| **User Activity** | RunMRU commands, typed paths, recent documents, UserAssist (ROT13 decoded), search queries |
| **Network** | Wireless profiles, public network connections, mapped drives, admin share access |
| **USB / Devices** | USBSTOR history, MountPoints, mounted device enumeration |
| **Security** | Suspicious user accounts, disabled audit policies, LSA Secrets, credential stores |
| **System Info** | OS version, hostname, timezone, shutdown time |
| **Browser** | Typed URLs, suspicious web navigation (pastebin, internal IPs, C2 indicators) |

### MITRE ATT&CK Mapping

Findings are automatically tagged with relevant MITRE ATT&CK technique IDs (T1547, T1543, T1218, T1059, T1053, etc.) with direct links.

### Severity Levels

- **Critical** — Active compromise indicators (malware persistence, encoded commands, IFEO backdoors, known offensive tools)
- **High** — Strong suspicious activity (temp-dir execution, admin share access, execution policy bypass)
- **Medium** — Notable items requiring review (LOLBins, public WiFi, dual-use tools, scheduled tasks)
- **Low** — Informational with minor concern (RunMRU commands, USB devices, mapped drives)
- **Info** — Baseline system information (OS info, timezone, normal autostart entries)

## Installation

```bash
# Clone or navigate to the project
cd registry_analyzer

# Build in release mode
cargo build --release

# Binary will be at: target/release/registry_analyzer
```

## Usage

```bash
# Basic usage
./target/release/registry_analyzer -i input.json -o report.html

# With verbose console output
./target/release/registry_analyzer -i input.json -o report.html -v

# Using the sample data
./target/release/registry_analyzer -i sample_registry.json -o sample_report.html -v
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Path to input JSON file (required) | — |
| `-o, --output` | Path for output HTML report | `registry_report.html` |
| `-v, --verbose` | Print findings summary to stdout | `false` |

## JSON Input Schema

The tool expects a JSON file with this structure:

```json
{
  "system_name": "WORKSTATION-01",
  "export_date": "2026-02-10T08:30:00Z",
  "hives": [
    {
      "name": "SYSTEM",
      "keys": [
        {
          "path": "CurrentControlSet\\Services\\SomeService",
          "last_write_time": "2026-01-15T10:30:00Z",
          "values": [
            {
              "name": "ImagePath",
              "type": "REG_EXPAND_SZ",
              "data": "C:\\Windows\\System32\\svchost.exe"
            }
          ],
          "subkeys": []
        }
      ]
    }
  ]
}
```

### Supported Hives

| Hive Name | Analysis Performed |
|-----------|---|
| `SYSTEM` | Services, USBSTOR, BAM/DAM, computer name, timezone, shutdown, mounted devices |
| `SOFTWARE` | Run keys, Winlogon, IFEO, AppInit_DLLs, network profiles, OS info, scheduled tasks, BHOs, installed software |
| `NTUSER.DAT` | User Run keys, RunMRU, typed paths, RecentDocs, UserAssist, search queries, typed URLs, MountPoints, mapped drives |
| `SAM` | User accounts, backdoor detection, RID analysis |
| `SECURITY` | Audit policies, LSA Secrets |

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `system_name` | No | Hostname for the report header |
| `export_date` | No | When the registry was exported |
| `hives[].name` | Yes | Hive identifier (SYSTEM, SOFTWARE, etc.) |
| `hives[].keys[].path` | Yes | Registry key path relative to hive root |
| `hives[].keys[].last_write_time` | No | ISO-8601 timestamp |
| `hives[].keys[].values[].name` | Yes | Value name |
| `hives[].keys[].values[].type` | No | REG_SZ, REG_DWORD, REG_BINARY, etc. |
| `hives[].keys[].values[].data` | No | String representation of value data |
| `hives[].keys[].subkeys` | No | Nested sub-keys (recursive) |

## Report Features

- **Dark theme** matching the KaliHeker design system
- **Severity filtering** — click Critical/High/Medium/Low/Info buttons to filter
- **Full-text search** — search across all findings
- **Collapsible sections** — click category headers to collapse/expand
- **MITRE ATT&CK links** — direct links to technique pages
- **Evidence boxes** — detailed forensic evidence for each finding
- **Summary table** — sortable overview of all findings

## How to Generate Input JSON

You can create the input JSON from registry hives using tools like:

- **RegRipper** — Export to JSON with plugins
- **regipy** (Python) — `RegistryHive` class with JSON serialization
- **python-registry** — Parse `.DAT` files and export
- **Eric Zimmerman's Registry Explorer** — Export selected keys

### Example with regipy (Python):

```python
import json
from regipy.registry import RegistryHive

def export_hive(path, name):
    reg = RegistryHive(path)
    keys = []
    for entry in reg.recurse_subkeys(as_json=True):
        keys.append({
            "path": entry.path,
            "last_write_time": str(entry.timestamp),
            "values": [
                {"name": v.name, "type": v.value_type, "data": str(v.value)}
                for v in (entry.values or [])
            ]
        })
    return {"name": name, "keys": keys}

dump = {
    "system_name": "TARGET-PC",
    "export_date": "2026-02-10T00:00:00Z",
    "hives": [
        export_hive("/path/to/SYSTEM", "SYSTEM"),
        export_hive("/path/to/SOFTWARE", "SOFTWARE"),
        export_hive("/path/to/NTUSER.DAT", "NTUSER.DAT"),
    ]
}

with open("registry_dump.json", "w") as f:
    json.dump(dump, f, indent=2)
```

## License

For authorized forensic and security research use only.
