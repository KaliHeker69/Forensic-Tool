# NTFS Analyzer Command Reference

This document explains every command and flag available in the ntfs_analyzer CLI.
The tool has four subcommands:

- analyze   : Full correlation analysis and reporting
- timeline  : Timeline-only export
- list-rules: Show detection rules
- validate  : Validate input JSON structure

All commands use standard Clap short/long flags. Examples assume you are in the
project root and the binary is available at ./target/release/ntfs_analyzer.

-------------------------------------------------------------------------------

## 1) analyze

Run full analysis on NTFS JSON data (MFT, USN, I30, Bitmap where present), apply
rules, apply whitelist, and generate reports.

### Syntax

```
ntfs_analyzer analyze -i <INPUT> [options]
```

### Required

- -i, --input <PATH>
  Path to input JSON file or directory containing split JSON files.
  - If a directory is supplied, all expected input files are loaded from it.
  - If a file is supplied, it is loaded as a single JSON/NDJSON source.

### Options

- -r, --rules <PATH>
  Path to the rules TOML file.
  Default auto-discovery order:
  1) <exe_dir>/rules/default_rules.toml
  2) <exe_dir>/../rules/default_rules.toml
  3) rules/default_rules.toml
  4) ./rules/default_rules.toml

- -w, --whitelist <PATH>
  Path to the whitelist TOML file (regex-based path exclusions).
  Default auto-discovery order (used when --whitelist is not provided):
  1) <exe_dir>/rules/whitelist.toml
  2) <exe_dir>/../rules/whitelist.toml
  3) rules/whitelist.toml
  4) ./rules/whitelist.toml

  Note: If you provide --whitelist explicitly, that file is used and no
  auto-discovery occurs.

- -o, --output <DIR>
  Output directory for reports. Default: output

- -f, --format <LIST>
  Output formats as a comma-separated list. Default: all
  Supported values: json, text, html, all

  Examples:
  - --format json
  - --format text,html

- --start-date <YYYY-MM-DD>
  Timeline start date filter. Only events on or after this date are included
  in the timeline and report summaries.

- --end-date <YYYY-MM-DD>
  Timeline end date filter. Only events on or before this date are included.

- --timeline-csv
  Also export the timeline to output/timeline.csv

- --timeline-bodyfile
  Also export the timeline to output/timeline.bodyfile (Sleuth Kit format)

- --no-color
  Disable colored terminal output (useful for logs or pipelines).

- --dry-run
  Run full parsing + correlation + timeline generation but skip writing any
  report or timeline output files.

### Outputs

- output/report.json   (if json or all)
- output/report.txt    (if text or all)
- output/report.html   (if html or all)
- output/timeline.csv  (if --timeline-csv)
- output/timeline.bodyfile (if --timeline-bodyfile)

Validation behavior:
- Invalid `--format` values now return an error immediately.
- Invalid date values (not `YYYY-MM-DD`) return an error immediately.
- If `--start-date` is later than `--end-date`, the command fails fast.

### Examples

Full analysis with defaults:
```
./target/release/ntfs_analyzer analyze -i output/
```

Specify rules and whitelist explicitly:
```
./target/release/ntfs_analyzer analyze \
  -i output/ \
  -r rules/default_rules.toml \
  -w rules/whitelist.toml \
  -o report_custom \
  --format json,text
```

Filter timeline by date range and export CSV:
```
./target/release/ntfs_analyzer analyze \
  -i output/ \
  --start-date 2025-01-01 \
  --end-date 2025-12-31 \
  --timeline-csv
```

Run a no-write dry-run:
```
./target/release/ntfs_analyzer analyze -i output/ --dry-run
```

-------------------------------------------------------------------------------

## 2) timeline

Generate a timeline only, without correlation or reporting. This is useful for
quick triage or external timeline tooling.

### Syntax

```
ntfs_analyzer timeline -i <INPUT> [options]
```

### Required

- -i, --input <PATH>
  Path to input JSON file.

### Options

- -o, --output <PATH>
  Output file path. Default: timeline.csv

- -f, --format <TYPE>
  Output format. Default: csv
  Supported values: csv, json, bodyfile

- --start-date <YYYY-MM-DD>
  Start date filter.

- --end-date <YYYY-MM-DD>
  End date filter.

Validation behavior:
- Invalid `--format` values return an error immediately.
- Invalid dates or reversed date ranges return an error.

### Outputs

- The file specified by --output.

### Examples

CSV timeline to a custom path:
```
./target/release/ntfs_analyzer timeline -i output/mft.json -o /tmp/timeline.csv
```

Bodyfile timeline:
```
./target/release/ntfs_analyzer timeline -i output/mft.json --format bodyfile
```

-------------------------------------------------------------------------------

## 3) list-rules

List detection rules and optionally filter by category.

### Syntax

```
ntfs_analyzer list-rules [options]
```

### Options

- -r, --rules <PATH>
  Path to rules TOML file. Default: auto-discovered rules file
  (see analyze -> --rules for search order).

- -c, --category <CATEGORY>
  Show only rules with the specified category.

### Examples

List all enabled rules:
```
./target/release/ntfs_analyzer list-rules
```

List rules for a specific category:
```
./target/release/ntfs_analyzer list-rules --category timestomping
```

Use a custom rules file:
```
./target/release/ntfs_analyzer list-rules -r rules/default_rules.toml
```

-------------------------------------------------------------------------------

## 4) validate

Validate the input JSON structure without running analysis.

### Syntax

```
ntfs_analyzer validate -i <INPUT>
```

### Required

- -i, --input <PATH>
  Path to input JSON file or directory.

### Output

- Prints a summary of parsed artifacts and whether validation succeeded.

### Example

```
./target/release/ntfs_analyzer validate -i output/
```

-------------------------------------------------------------------------------

## Whitelist File (Regex)

Whitelist patterns are applied to full file paths. If any pattern matches, the
finding is suppressed.

- Default file: rules/whitelist.toml (auto-discovered if present)
- Each [[rules]] entry contains:
  - id, name, description
  - pattern (regex)
  - enabled (true/false)

Example whitelist entry:

```
[[rules]]
id = "WL-999"
name = "Case staging folder"
description = "Ignore staging artifacts"
pattern = '(?i)[/\\]CaseWork[/\\]Staging[/\\]'
enabled = true
```

Notes:
- The tool automatically applies case-insensitive matching.
- Use [/\\] to match both Windows and Unix path separators.
- Keep patterns specific to avoid suppressing real findings.

-------------------------------------------------------------------------------

## Rules File

The detection rules file is TOML-based. It defines the rules used during
correlation. The default rules file lives at rules/default_rules.toml.

If you supply a custom rules file using --rules, the tool loads that file and
then auto-discovers the whitelist unless --whitelist is explicitly provided.

-------------------------------------------------------------------------------

## Common Workflows

1) Standard analysis with defaults
```
./target/release/ntfs_analyzer analyze -i output/
```

2) Custom rules and whitelist
```
./target/release/ntfs_analyzer analyze -i output/ \
  -r rules/default_rules.toml \
  -w rules/whitelist.toml
```

3) JSON-only report for automation
```
./target/release/ntfs_analyzer analyze -i output/ --format json
```

4) Quick validation before full run
```
./target/release/ntfs_analyzer validate -i output/
```

-------------------------------------------------------------------------------

## Help and Version

Use built-in help for any subcommand:

```
ntfs_analyzer --help
ntfs_analyzer analyze --help
ntfs_analyzer timeline --help
ntfs_analyzer list-rules --help
ntfs_analyzer validate --help
```

Check version:
```
ntfs_analyzer --version
```
