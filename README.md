# Forensic Tool

A collection of digital forensics tools and analyzers built primarily in Rust, with supporting Python utilities. The toolkit is designed for deployment on a Linux analysis server where evidence is collected, processed, correlated, and published for review through a web portal.

The workflow is intentionally server-centric:

1. Evidence is collected from endpoints or source systems.
2. The data is transferred to the Linux analysis server through the agent-driven pipeline.
3. Individual analyzers process the artefacts and generate structured outputs.
4. Results are published to the portal so investigators can review them in an advanced dashboard.

The repository is organized as a set of independent tools, each focused on a specific artefact family or analysis domain, so the pipeline can be deployed incrementally or as a full stack.

---

## Projects

| Folder | Description |
|--------|-------------|
| `browser_forensics` | Parse and analyse browser artefacts such as history, downloads, cookies, cache, and session data |
| `chainsaw` | Windows event-log hunting using Sigma rules and other detection logic |
| `data_theft` | Detect and correlate data-exfiltration indicators across artefacts and timelines |
| `loki-rs` | Rust port of the Loki IOC scanner for signature-based hunting |
| `memory_corelation` | Correlate Volatility 3 memory analysis output exported as JSONL |
| `pe_entropy` | Python utility to compute entropy of PE file sections |
| `portal_from_azure` | Web portal for aggregating, browsing, and presenting forensic reports |
| `prefetch_analyzer` | Parse and analyse Windows Prefetch files for program execution evidence |
| `registry_analyzer` | Parse Windows Registry hives and apply detection and triage rules |
| `rust_forensics_collector` | Artefact collection utility for gathering endpoint evidence |
| `srum_analysis` | Parse and correlate SRUM (System Resource Usage Monitor) data |
| `Transfer` | Staging area and data-transfer utilities used before analysis |

> `ez_tools_net9` is excluded from this repository (third-party Eric Zimmerman tools).

---

## Deployment Model

The intended deployment target is a Linux server that hosts the analysis services and the web portal. That server acts as the central processing point for uploaded data, analysis output, dashboards, and investigator review.

The recommended operational split is:

- Collection or upload happens on the source side.
- Analysis runs on the Linux server using the Rust and Python tools in this repository.
- Human review happens in the portal, which presents the outputs in a dashboard-oriented interface.

This layout keeps the evidence-handling path separate from the user-facing review experience and makes it easier to scale the analysis layer independently from the portal.

---

## Portal And Dashboard

The `portal_from_azure` web app provides the interface used to share analysis results. It is intended to surface artefacts, reports, and derived findings in a more interactive dashboard than a flat file export.

Typical portal content includes:

- Summary tiles and quick status views.
- Resource and report launchers.
- Artifact inventories and format breakdowns.
- Charts and compact panels for fast triage.
- Drill-down views for individual reports and datasets.

When deployed on the Linux analysis server, the portal becomes the primary review layer for analysts and investigators who need to inspect findings without opening each report manually.

---

## Requirements

- **Rust** 1.75+ (`cargo`)
- **Python** 3.10+ (for `pe_entropy`)
- `.NET 9` runtime required only for `ez_tools_net9` (not included in this repo)
- Linux server for hosting the analysis workloads and portal service

---

## Quick Start

Each Rust sub-project is an independent Cargo workspace. To build any of them:

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

For a Linux server deployment, the usual pattern is to build the analysis binaries on the host or in CI, copy the generated outputs into the shared report location, and let the portal read from those report paths.

---

## Data Flow

The high-level data flow is:

- Source systems generate forensic artefacts.
- The agent-based transfer layer stages the artefacts for analysis.
- Parser and correlation tools normalize the raw input into structured JSON, CSV, or report output.
- The portal reads the generated outputs and renders them in the dashboard.

This pattern supports multiple artefact families without forcing a single monolithic processing pipeline.

---

## Repository Layout

The top-level folders are intentionally separated by function:

- Analysis tools live in their own project directories.
- The portal lives in `portal_from_azure/`.
- Transfer and staging helpers live in `Transfer/`.
- Generated results are kept out of source folders so evidence and code remain easy to distinguish.

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

This port is used by the portal service when the dashboard is exposed on the analysis server.



---

## License

See individual project directories for licence information.
