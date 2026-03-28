# 🔍 registry_parser

**A cross-platform, offline Windows registry hive parser built in Rust — designed for DFIR analysis.**

`registry_parser` reads raw Windows registry hive files (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `NTUSER.DAT`, etc.) and exports their complete key/value tree as structured JSON, enriched with forensic metadata. It runs natively on **Linux**, **macOS**, and **Windows** with zero Windows API dependencies.

---

## ✨ Features

### Core Parsing
- Parses any offline Windows registry hive file (binary `regf` format)
- Full **recursive key/value tree traversal** with configurable depth limits
- **Native Transaction Log Recovery** — automatically detects and applies `.LOG1`, `.LOG2`, and `.LOG` files to recover dirty hives
- Supports all standard REG_* value types
- **KAPE-aware directory scanning** — auto-discovers base hives and applies their logs

### DFIR-Focused Output
- **Per-hive statistics** — total keys, total values, max depth, deepest path, earliest/latest key timestamps
- **Per-key metadata** — tree depth, expected subkey count, value count, last write time (ISO-8601)
- **Per-value metadata** — data size in bytes, residency flag (inline vs. external cell storage)
- **Rich typed value data** — integers with hex + decimal, binary with full hex dump + ASCII preview, multi-strings as native arrays
- Per-hive JSON files + optional combined dump

### Cross-Platform
- Pure Rust — no Win32 API calls, no admin privileges required
- Powered by [`nt_hive2`](https://crates.io/crates/nt_hive2) for direct binary hive parsing
- Compiles and runs on Linux, macOS, and Windows

---

## 📦 Installation

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.70+)
- C compiler (`cc` / `clang` / `gcc`) for linking

### Build from Source

```bash
git clone https://github.com/YOUR_USERNAME/registry_parser.git
cd registry_parser
cargo build --release
```

The binary will be at `target/release/registry_parser`.

---

## 🚀 Usage

### Parse a Single Hive

```bash
registry_parser --hive /path/to/SYSTEM --output-dir ./out
```

### Parse Multiple Hives

```bash
registry_parser \
  --hive /evidence/SYSTEM \
  --hive /evidence/SOFTWARE \
  --hive /evidence/NTUSER.DAT \
  --output-dir ./out
```

### Parse a KAPE-Extracted Directory

```bash
registry_parser --dir /evidence/C/Windows/System32/config --output-dir ./out
```

This auto-discovers all files without extensions (`DEFAULT`, `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`) and skips `.LOG1` / `.LOG2` sidecars.

### Combine Individual Hives + Directory

```bash
registry_parser \
  --dir /evidence/config \
  --hive /evidence/Users/JohnDoe/NTUSER.DAT \
  --output-dir ./out \
  --combined-output ./all_hives.json
```

### Limit Traversal Depth

```bash
registry_parser --dir ./config --max-depth 3 --output-dir ./out
```

### Compact Output (Single-Line JSON)

```bash
registry_parser --dir ./config --compact --output-dir ./out
```

### Using `cargo run` During Development

```bash
cargo run --release -- --dir /path/to/config --output-dir ./out
```

---

## ⚙️ Command-Line Reference

```
registry_parser [OPTIONS]

Options:
  -H, --hive <FILE>               Individual hive file(s) to parse
                                   (repeatable: --hive A --hive B)

  -d, --dir <DIR>                 Directory containing hive files (KAPE-aware).
                                   Auto-discovers .hve, .dat, and extensionless files.
                                   .LOG1 / .LOG2 sidecars are automatically applied to dirty hives.

  -o, --output-dir <DIR>          Output directory for per-hive JSON files
                                   [default: json_output]

      --combined-output <FILE>    Also write a single combined JSON file
                                   containing all parsed hives

      --compact                   Emit compact (single-line) JSON instead of
                                   pretty-printed

      --max-depth <N>             Maximum key recursion depth (0 = unlimited)
                                   [default: 0]

  -h, --help                      Print help
  -V, --version                   Print version
```

> **Note:** At least one of `--hive` or `--dir` must be provided.

---

## 📊 Output Schema

Each per-hive JSON file follows this structure:

### Top Level

```json
{
  "hive_name": "SYSTEM",
  "hive_path": "/evidence/config/SYSTEM",
  "hive_size_bytes": 17563648,
  "parsed_at": "2026-03-22T17:53:29+00:00",
  "statistics": { ... },
  "root": { ... }
}
```

### `statistics` Block

Provides high-level forensic metrics for the hive:

```json
{
  "total_keys": 48701,
  "total_values": 127834,
  "max_depth": 14,
  "deepest_path": "ROOT\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-...",
  "earliest_timestamp": "2019-03-19T11:45:08+00:00",
  "latest_timestamp": "2025-06-11T14:10:35+00:00"
}
```

| Field | Description |
|---|---|
| `total_keys` | Total number of registry keys in the hive |
| `total_values` | Total number of values across all keys |
| `max_depth` | Deepest nesting level reached |
| `deepest_path` | Full path of the deepest key |
| `earliest_timestamp` | Oldest `last_write_time` across all keys |
| `latest_timestamp` | Most recent `last_write_time` across all keys |

### Key Object

```json
{
  "name": "Control",
  "path": "ROOT\\ControlSet001\\Control",
  "depth": 2,
  "last_write_time": "2025-06-11T14:10:35.857574+00:00",
  "subkey_count": 142,
  "value_count": 11,
  "values": [ ... ],
  "subkeys": [ ... ]
}
```

| Field | Description |
|---|---|
| `name` | Key name (leaf component) |
| `path` | Full registry path from root |
| `depth` | Nesting depth (0 = root) |
| `last_write_time` | ISO-8601 timestamp of last modification |
| `subkey_count` | Expected subkey count from the hive header |
| `value_count` | Number of values under this key |
| `values` | Array of value objects |
| `subkeys` | Array of child key objects (recursive) |

### Value Object

```json
{
  "name": "CurrentUser",
  "type": "REG_SZ",
  "data": "DESKTOP-ABC123$",
  "data_size_bytes": 32,
  "is_resident": false
}
```

| Field | Description |
|---|---|
| `name` | Value name (`"(Default)"` for unnamed values) |
| `type` | Registry type (`REG_SZ`, `REG_DWORD`, `REG_BINARY`, etc.) |
| `data` | Decoded value data (structure varies by type — see below) |
| `data_size_bytes` | Raw data size in bytes from the hive cell |
| `is_resident` | `true` if data is stored inline in the value cell (≤4 bytes); `false` if stored externally. Forensically relevant for data carving. |

### Value Data Formats

The `data` field is **typed** — its structure depends on the registry type:

#### String Types (`REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`)

```json
"data": "C:\\Windows\\system32\\config"
```

#### Integer Types (`REG_DWORD`, `REG_DWORD_BIG_ENDIAN`)

```json
"data": {
  "decimal": 28,
  "hex": "0x0000001c"
}
```

#### 64-bit Integer (`REG_QWORD`)

```json
"data": {
  "decimal": 133579800000000,
  "hex": "0x0000797f29a63d00"
}
```

#### Multi-String (`REG_MULTI_SZ`)

```json
"data": ["RpcSs", "Power", "BrokerInfrastructure", "DcomLaunch"]
```

#### Binary (`REG_BINARY`)

```json
"data": {
  "hex": "01 00 04 80 48 00 00 00 58 00 00 00 ...",
  "size": 108,
  "ascii_preview": "....H...X........S...",
  "decoded": "SomeHiddenString"
}
```

- **`hex`**: Complete hex dump (no truncation)
- **`size`**: Total byte count
- **`ascii_preview`**: Printable ASCII representation (no truncation, non-printable as `.`)
- **`decoded`**: Attempted UTF-16LE / UTF-8 string extraction (useful for finding hidden texts; `null` if no valid text is found)

#### Null (`REG_NONE`, unknown)

```json
"data": null
```

---

## 🗂 Supported Registry Types

| Type | Numeric ID | Output Format |
|---|---|---|
| `REG_NONE` | 0x0000 | `null` |
| `REG_SZ` | 0x0001 | String |
| `REG_EXPAND_SZ` | 0x0002 | String (unexpanded) |
| `REG_BINARY` | 0x0003 | `{ hex, size, ascii_preview }` |
| `REG_DWORD` | 0x0004 | `{ decimal, hex }` |
| `REG_DWORD_BIG_ENDIAN` | 0x0005 | `{ decimal, hex }` |
| `REG_LINK` | 0x0006 | String |
| `REG_MULTI_SZ` | 0x0007 | Array of strings |
| `REG_RESOURCE_LIST` | 0x0008 | String |
| `REG_FULL_RESOURCE_DESCRIPTOR` | 0x0009 | String |
| `REG_RESOURCE_REQUIREMENTS_LIST` | 0x000A | String |
| `REG_QWORD` | 0x000B | `{ decimal, hex }` |
| `REG_FILE_TIME` | 0x0010 | String |

---

## 🔬 DFIR Use Cases

### Timeline Analysis
Use `earliest_timestamp` and `latest_timestamp` from the statistics block to quickly scope hive activity windows. The `last_write_time` on each key enables precise event timelining.

### Persistence Hunting
Parse `SOFTWARE` and `SYSTEM` hives and search the JSON output for keys under:
- `ROOT\ControlSet001\Services\*` — service-based persistence
- `ROOT\Microsoft\Windows\CurrentVersion\Run*` — auto-start entries
- `ROOT\ControlSet001\Control\Session Manager\BootExecute` — boot-time execution

### Credential Analysis
Parse `SAM` and `SECURITY` hives to extract:
- SID-to-account mappings under `ROOT\SAM\Domains\Account\Users`
- Cached domain credentials under `ROOT\Cache\NL$*`
- LSA policy data under `ROOT\Policy\*`

### Depth Anomaly Detection
Unusually deep keys (`max_depth` > 10) may indicate:
- Malware hiding data in deeply nested keys
- Registry-based data exfiltration channels
- Obfuscated configuration storage

### Grepping the Output
Since the output is JSON, use `jq` for quick analysis:

```bash
# Find all keys modified after a specific date
jq '.. | objects | select(.last_write_time > "2025-06-01")' SYSTEM.json

# Extract all REG_BINARY values larger than 1KB
jq '.. | objects | select(.type == "REG_BINARY" and .data_size_bytes > 1024)' SYSTEM.json

# List all service names from the SYSTEM hive
jq '.root.subkeys[] | select(.name == "ControlSet001") | .subkeys[] | select(.name == "Services") | .subkeys[].name' SYSTEM.json

# Find recently written keys
jq -r '.. | objects | select(.last_write_time != null) | "\(.last_write_time) \(.path)"' SYSTEM.json | sort -r | head -20
```

---

## 📁 KAPE Integration

When [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) collects `C:\Windows\System32\config`, it produces:

```
config/
  DEFAULT        DEFAULT.LOG1   DEFAULT.LOG2
  SAM            SAM.LOG1       SAM.LOG2
  SECURITY       SECURITY.LOG1  SECURITY.LOG2
  SOFTWARE       SOFTWARE.LOG1  SOFTWARE.LOG2
  SYSTEM         SYSTEM.LOG1    SYSTEM.LOG2
```

Simply run:

```bash
registry_parser --dir /evidence/config --output-dir ./analysis
```

All five base hives are parsed. `.LOG1`/`.LOG2` transaction logs are skipped (they are sidecar files for the OS and not standalone hives).

---

## 🏗 Architecture

```
registry_parser
├── Cargo.toml         # Dependencies: nt_hive2, clap, serde, chrono, anyhow
└── src/
    └── main.rs        # Single-file implementation (~500 lines)
        ├── CLI        # clap-based argument parsing
        ├── Output     # Serde-serializable structs (ParsedHive, HiveKey, HiveValue, ValueData)
        ├── Parsing    # Hive loading via nt_hive2, recursive tree walker, stats collector
        ├── Discovery  # Directory scanner for KAPE-style folders
        └── Utilities  # JSON writer, filename sanitizer
```

### Dependencies

| Crate | Purpose |
|---|---|
| [`nt_hive2`](https://crates.io/crates/nt_hive2) | Binary registry hive parser (pure Rust, cross-platform) |
| [`clap`](https://crates.io/crates/clap) | CLI argument parsing with derive macros |
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | JSON serialization |
| [`chrono`](https://crates.io/crates/chrono) | Timestamp formatting (ISO-8601 / RFC-3339) |
| [`anyhow`](https://crates.io/crates/anyhow) | Error handling with context |

---

## 📋 Example Output

```
$ registry_parser --dir ./evidence/config --output-dir ./out

[*] Discovered 5 hive(s) in ./evidence/config
    ./evidence/config/DEFAULT
    ./evidence/config/SAM
    ./evidence/config/SECURITY
    ./evidence/config/SOFTWARE
    ./evidence/config/SYSTEM
[*] Parsing: ./evidence/config/DEFAULT
[+] 312 keys, 845 values, max depth 6 → ./out/DEFAULT.json
[*] Parsing: ./evidence/config/SAM
[+] 67 keys, 189 values, max depth 5 → ./out/SAM.json
[*] Parsing: ./evidence/config/SECURITY
[+] 125 keys, 302 values, max depth 4 → ./out/SECURITY.json
[*] Parsing: ./evidence/config/SOFTWARE
[+] 95421 keys, 312847 values, max depth 12 → ./out/SOFTWARE.json
[*] Parsing: ./evidence/config/SYSTEM
[+] 48701 keys, 127834 values, max depth 14 → ./out/SYSTEM.json
[*] Done.
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## 📄 License

This project is open source. Please add your preferred license.

---

> Built with 🦀 Rust for the DFIR community.
]]>
