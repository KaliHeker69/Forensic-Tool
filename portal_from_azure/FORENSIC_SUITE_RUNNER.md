---
noteId: "025dc5402ec911f1b957c1d989bc8e46"
tags: []

---

# Forensic Suite Runner

`run_release_forensic_suite.sh` builds and runs the supported forensic tools in release mode, collects their outputs into a single case folder, and records the generated HTML reports.

Script path:
- `/Users/kali/Codes/wsl/portal_from_azure/scripts/run_release_forensic_suite.sh`

## Included Tools

The runner currently executes only these tools:

1. `browser_forensics`
2. `network_forensics`
3. `memory_corelation`
4. `registry_parser`
5. `registry_analyzer`
6. `srum_analysis`
7. `prefetch_analyzer`

## Excluded Tools

These are intentionally not executed by this runner:

1. `data_theft`
2. `ntfs_analyzer`
3. `shimcache-amcache_analyzer`
4. `pe_entropy`
5. `forensic_correlation`

## What The Runner Does

For each enabled tool:

1. Builds the crate with `cargo build --release`
2. Executes the release binary from that tool's crate directory
3. Writes the tool output into a subfolder under one shared output root
4. Appends any generated HTML report path to `html_reports.txt`
5. Writes a run summary to `run_manifest.txt`

The script skips tools whose required input flags were not provided.

## Output Layout

Example output root:

```text
portal_from_azure/case_reports/run_20260403_142500/
```

Inside that folder the runner creates:

```text
browser_forensics/
network_forensics/
memory_corelation/
registry_parser/
registry_analyzer/
srum_analysis/
prefetch_analyzer/
html_reports.txt
run_manifest.txt
```

## Command

Basic usage:

```bash
./portal_from_azure/scripts/run_release_forensic_suite.sh \
  --output-root /Users/kali/Codes/wsl/portal_from_azure/case_reports/case_alpha \
  --browser-evidence-dir /path/to/browser_evidence \
  --network-live-json /path/to/network/live.json \
  --memory-input /path/to/volatility_output \
  --registry-dir /path/to/registry_hives \
  --srum-input /path/to/srum_csv \
  --prefetch-input /path/to/PECmd_Output.json
```

If you already built the release binaries:

```bash
./portal_from_azure/scripts/run_release_forensic_suite.sh \
  --skip-build \
  --output-root /Users/kali/Codes/wsl/portal_from_azure/case_reports/case_alpha \
  --browser-evidence-dir /path/to/browser_evidence \
  --network-live-json /path/to/network/live.json \
  --memory-input /path/to/volatility_output \
  --registry-dir /path/to/registry_hives \
  --srum-input /path/to/srum_csv \
  --prefetch-input /path/to/PECmd_Output.json
```

## Supported Flags

Shared:

1. `--output-root PATH`
2. `--case-name NAME`
3. `--skip-build`
4. `-h`, `--help`

If `--output-root` is omitted, the runner creates:

```text
portal_from_azure/case_reports/run_<timestamp>
```

Browser:

1. `--browser-evidence-dir PATH`

Network:

1. `--network-live-json PATH`
2. `--network-kape-path PATH`
3. `--network-evtx-path PATH`
4. `--network-ioc-feed PATH`

Memory:

1. `--memory-input PATH`

Registry:

1. `--registry-dir PATH`

SRUM:

1. `--srum-input PATH`

Prefetch:

1. `--prefetch-input PATH`

## Tool-Specific Notes

### Browser

The runner writes:

1. `report.html`
2. `report.json`

### Network

The runner uses `--out-format all` and writes the output directory produced by `netforens`.

### Memory

The runner uses:

```text
--output all
```

This produces both JSON analysis output and `report.html`.

### Registry

The runner executes:

1. `registry_parser`
2. `registry_analyzer`

`registry_analyzer` uses the parser output directory as its input.

### SRUM

The tool writes:

1. `srum_analysis_report.html`
2. `srum_analysis_report.json`

### Prefetch

`prefetch_analyzer` may exit with code `1` when findings exist. The runner treats that as success and still records the HTML output.

## Generated Summary Files

### `run_manifest.txt`

Contains:

1. case name
2. workspace path
3. output root
4. generation timestamp
5. tool output directories
6. excluded tool list

### `html_reports.txt`

Contains the HTML report file paths produced during the run.

## Validation

To verify the script itself:

```bash
/bin/bash -n /Users/kali/Codes/wsl/portal_from_azure/scripts/run_release_forensic_suite.sh
```

To view the help text:

```bash
/Users/kali/Codes/wsl/portal_from_azure/scripts/run_release_forensic_suite.sh --help
```

## Notes

1. This runner does not infer evidence paths automatically.
2. Each tool is executed only if its required input flag is provided.
3. All execution happens against release binaries.
