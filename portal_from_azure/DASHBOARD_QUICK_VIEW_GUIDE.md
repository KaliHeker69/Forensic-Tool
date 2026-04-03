# Dashboard Quick View Generator

## Purpose

`dashboard_setter` builds the file used by the portal dashboard and Host Information page:

- Output: `portal_from_azure/rust-backend/data/dashboard_quick_view.json`

The portal reads that JSON and uses it as the primary quick-view data source instead of parsing every module report at request time.

## Recommended Command

Use the dedicated wrapper script instead of calling Cargo manually:

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh generate
```

That command:

1. runs the Rust binary `dashboard_setter`
2. generates the quick-view JSON
3. prints a section/source summary after generation

## Other Commands

Generate with explicit paths:

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh generate \
  --root /Users/kali/Codes/wsl \
  --output /Users/kali/Codes/wsl/portal_from_azure/rust-backend/data/dashboard_quick_view.json \
  --config /Users/kali/Codes/wsl/portal_from_azure/json_files_path.json
```

Print a summary from an existing quick-view JSON without regenerating it:

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh summary
```

Build the generator binary only:

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh build
```

## Direct Rust CLI

The Rust binary now supports explicit commands:

```bash
cargo run --manifest-path portal_from_azure/rust-backend/Cargo.toml \
  --bin dashboard_setter -- generate --summary
```

```bash
cargo run --manifest-path portal_from_azure/rust-backend/Cargo.toml \
  --bin dashboard_setter -- summary
```

Available options:

- `--root PATH`
- `--output PATH`
- `--config PATH`
- `--summary`
- `--quiet`

Help:

```bash
cargo run --manifest-path portal_from_azure/rust-backend/Cargo.toml \
  --bin dashboard_setter -- --help
```

## How It Works

### 1. Resolve workspace roots

The generator builds a list of roots to search from:

1. `--root`
2. `FORENSICS_WORKSPACE_ROOT`
3. current working directory and parent fallbacks
4. `/Users/kali/Codes/wsl`

### 2. Resolve the path-config file

The generator reads module input locations from:

1. `--config`
2. `JSON_FILES_PATH_CONFIG`
3. `portal_from_azure/json_files_path.json`
4. `json_files_path.json`

This file is the single source of truth for module output paths.

### 3. Read module outputs

The generator reads and summarizes the available module reports, including:

- Host Information inputs
- Memory
- Network
- NTFS
- Browser
- Execution
- Windows Event
- SRUM
- Prefetch-derived timeline/correlation sources

It preserves each section's `source` field so the portal can show provenance.

### 4. Build the dashboard payload

The final JSON contains:

- `analysis_metadata`
- `host_information_quickview`
- `network_quickview`
- `memory_quickview`
- `ntfs_quickview`
- `browser_quickview`
- `execution_quickview`
- `windows_event_quickview`
- `srum_quickview`
- `super_timeline`
- `connections_engine`

### 5. Portal consumption

The portal route loads `dashboard_quick_view.json` and uses it as the primary dashboard seed. If the file is missing or a section is empty, the portal can still fall back to live collectors for some sections.

## Metadata Added To The JSON

`analysis_metadata` now includes:

- `generated_by`
- `generated_at`
- `output_path`
- `config_path`
- `workspace_roots`
- `modules_processed`
- `module_sources`

This makes the payload easier to audit and debug.

## Wrapper Script Behavior

`scripts/run_dashboard_quickview.sh` exists to keep operations simple.

Why it exists:

- shorter command to remember
- separate execution path from the main portal start script
- macOS linker/toolchain environment is handled automatically when needed

Supported wrapper commands:

- `generate`
- `summary`
- `build`

## Common Flow

### Regenerate quick-view after new analysis outputs

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh generate
```

### Verify what sources were used

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh summary
```

### Restart the portal after the JSON is updated

```bash
./portal_from_azure/scripts/start_rust_portal.sh restart
```

## Troubleshooting

### The portal does not show updated data

Check:

1. `dashboard_quick_view.json` was regenerated
2. the expected section has non-empty values
3. the portal backend was restarted if templates/routes changed
4. the browser was hard refreshed

### A section is empty

Check:

1. the module output exists at the configured path
2. the path is listed correctly in `json_files_path.json`
3. the artifact format matches what `dashboard_setter` expects

### Need to inspect the actual input source used

Run:

```bash
./portal_from_azure/scripts/run_dashboard_quickview.sh summary
```

That prints the resolved source path for each section.
