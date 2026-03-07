# Forensic Tool

A collection of digital forensics tools and analyzers built primarily in Rust, with supporting Python utilities. Each sub-project targets a specific forensic artefact or analysis domain.

---

## Projects

| Folder | Description |
|--------|-------------|
| `browser_forensics` | Parse and analyse browser artefacts (history, cookies, cache) |
| `chainsaw` | Windows event-log hunting using Sigma rules |
| `data_theft` | Detect and correlate data-exfiltration indicators |
| `loki-rs` | Rust port of the Loki IOC scanner |
| `memory_corelation` | Correlate Volatility 3 memory analysis output (JSONL) |
| `ntfs_analyzer` | Parse NTFS MFT, USN journal, and file-system artefacts |
| `pe_entropy` | Python script to compute entropy of PE file sections |
| `portal` | Web portal for aggregating forensic reports |
| `prefetch_analyzer` | Parse and analyse Windows Prefetch files |
| `registry_analyzer` | Parse Windows Registry hives and apply detection rules |
| `rust_forensics_collector` | Artefact collection utility |
| `shim-amcache_analyzer` | Parse Shimcache (AppCompatCache) and Amcache hives |
| `srum_analysis` | Parse and correlate SRUM (System Resource Usage Monitor) data |
| `Transfer` | Staging area / data transfer utilities |

> `ez_tools_net9` is excluded from this repository (third-party Eric Zimmerman tools).

---

## Requirements

- **Rust** 1.75+ (`cargo`)
- **Python** 3.10+ (for `pe_entropy`)
- `.NET 9` runtime required only for `ez_tools_net9` (not included in this repo)

---

## Quick Start

Each sub-project is an independent Cargo workspace. To build any of them:

```bash
cd <project_folder>
cargo build --release
```

For the Python utility:

```bash
cd pe_entropy
pip install -r requirements.txt   # if present
python pe_entropy.py <binary>
```

---

## Repository Conventions

- `**/target/` — Rust build artefacts (ignored)
- `**/output/` — generated reports (ignored)
- `*.json` — analysis output files (ignored)
- `timeline.csv` — generated timelines (ignored)


---

## Azure Filewall Settings
```
Source: Any
Source port ranges: *
Destination: Any
Destination port ranges: 8000
Protocol: TCP
Action: Allow
Priority: 1000
Name: allow-8000
```



---

## License

See individual project directories for licence information.
