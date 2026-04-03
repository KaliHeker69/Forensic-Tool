#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$PROJECT_DIR/.." && pwd)"

CARGO_BIN="${CARGO_BIN:-}"
if [[ -z "$CARGO_BIN" ]]; then
    CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
fi
if [[ -z "$CARGO_BIN" && -x "$HOME/.cargo/bin/cargo" ]]; then
    CARGO_BIN="$HOME/.cargo/bin/cargo"
fi
if [[ -z "$CARGO_BIN" ]]; then
    echo "[ERROR] cargo not found in PATH" >&2
    exit 1
fi

if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    export CC="${CC:-/usr/bin/clang}"
    export AR="${AR:-/usr/bin/ar}"
    export SDKROOT="${SDKROOT:-/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk}"
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="${CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER:-/usr/bin/clang}"
fi

timestamp() {
    /bin/date +"%Y%m%d_%H%M%S"
}

usage() {
    /bin/cat <<'USAGE'
Usage:
  ./portal_from_azure/scripts/run_release_forensic_suite.sh [options]

Output:
  --output-root PATH              Root folder where all tool outputs will be stored
                                  Default: portal_from_azure/case_reports/run_<timestamp>

Tool inputs:
  --browser-evidence-dir PATH     Evidence directory for browser_forensics
  --network-live-json PATH        Live JSON input for network_forensics
  --network-kape-path PATH        KAPE directory for network_forensics
  --network-evtx-path PATH        EVTX JSON directory for network_forensics
  --network-ioc-feed PATH         IOC CSV feed for network_forensics
  --memory-input PATH             Volatility output directory for memory_corelation
  --registry-dir PATH             Registry hive directory for registry_parser
  --srum-input PATH               SrumECmd CSV directory for srum_analysis
  --prefetch-input PATH           PECmd JSON input for prefetch_analyzer

Optional:
  --case-name NAME                Case/run label used in the manifest
  --skip-build                    Reuse existing release binaries without rebuilding
  -h, --help                      Show this help

Included tools:
  - browser_forensics
  - network_forensics
  - memory_corelation
  - registry_parser
  - registry_analyzer
  - srum_analysis
  - prefetch_analyzer

Excluded by design:
  - data_theft
  - ntfs_analyzer
  - shimcache-amcache_analyzer
  - pe_entropy
  - forensic_correlation

Example:
  ./portal_from_azure/scripts/run_release_forensic_suite.sh \
    --output-root /tmp/case_outputs \
    --browser-evidence-dir /evidence/browser \
    --network-live-json /evidence/network/live.json \
    --memory-input /evidence/vol3 \
    --registry-dir /evidence/config \
    --srum-input /evidence/srum_csv \
    --prefetch-input /evidence/prefetch/PECmd_Output.json
USAGE
}

OUTPUT_ROOT=""
CASE_NAME=""
SKIP_BUILD=0

BROWSER_EVIDENCE_DIR=""
NETWORK_LIVE_JSON=""
NETWORK_KAPE_PATH=""
NETWORK_EVTX_PATH=""
NETWORK_IOC_FEED=""
MEMORY_INPUT=""
REGISTRY_DIR=""
SRUM_INPUT=""
PREFETCH_INPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --case-name)
            CASE_NAME="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --browser-evidence-dir)
            BROWSER_EVIDENCE_DIR="$2"
            shift 2
            ;;
        --network-live-json)
            NETWORK_LIVE_JSON="$2"
            shift 2
            ;;
        --network-kape-path)
            NETWORK_KAPE_PATH="$2"
            shift 2
            ;;
        --network-evtx-path)
            NETWORK_EVTX_PATH="$2"
            shift 2
            ;;
        --network-ioc-feed)
            NETWORK_IOC_FEED="$2"
            shift 2
            ;;
        --memory-input)
            MEMORY_INPUT="$2"
            shift 2
            ;;
        --registry-dir)
            REGISTRY_DIR="$2"
            shift 2
            ;;
        --srum-input)
            SRUM_INPUT="$2"
            shift 2
            ;;
        --prefetch-input)
            PREFETCH_INPUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$OUTPUT_ROOT" ]]; then
    OUTPUT_ROOT="$PROJECT_DIR/case_reports/run_$(timestamp)"
fi

if [[ -z "$CASE_NAME" ]]; then
    CASE_NAME="$(/usr/bin/basename "$OUTPUT_ROOT")"
fi

/bin/mkdir -p "$OUTPUT_ROOT"

MANIFEST="$OUTPUT_ROOT/run_manifest.txt"
SUMMARY="$OUTPUT_ROOT/html_reports.txt"

echo "Forensic Suite Run" > "$MANIFEST"
echo "Case Name: $CASE_NAME" >> "$MANIFEST"
echo "Workspace: $WORKSPACE_DIR" >> "$MANIFEST"
echo "Output Root: $OUTPUT_ROOT" >> "$MANIFEST"
echo "Generated At: $(/bin/date '+%Y-%m-%d %H:%M:%S %Z')" >> "$MANIFEST"
echo "" >> "$MANIFEST"
echo "HTML Reports" > "$SUMMARY"

log() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

build_release_binary() {
    local crate_dir="$1"
    local binary_name="$2"
    local manifest_path="$crate_dir/Cargo.toml"
    local binary_path="$crate_dir/target/release/$binary_name"

    if [[ "$SKIP_BUILD" -eq 1 && -x "$binary_path" ]]; then
        log "Reusing release binary: $binary_path"
        return 0
    fi

    log "Building release binary for $(/usr/bin/basename "$crate_dir")"
    "$CARGO_BIN" build --release --manifest-path "$manifest_path"
}

run_checked() {
    local label="$1"
    local allow_exit_one="$2"
    shift 2

    set +e
    "$@"
    local status=$?
    set -e

    if [[ $status -eq 0 ]]; then
        return 0
    fi

    if [[ $status -eq 1 && "$allow_exit_one" -eq 1 ]]; then
        warn "$label completed with exit code 1; treating it as success-with-findings"
        return 0
    fi

    echo "[ERROR] $label failed with exit code $status" >&2
    exit $status
}

record_report() {
    local label="$1"
    local path="$2"
    if [[ -f "$path" ]]; then
        echo "$label: $path" >> "$SUMMARY"
    fi
}

# Browser Forensics
if [[ -n "$BROWSER_EVIDENCE_DIR" ]]; then
    TOOL_DIR="$WORKSPACE_DIR/browser_forensics"
    OUT_DIR="$OUTPUT_ROOT/browser_forensics"
    /bin/mkdir -p "$OUT_DIR"
    build_release_binary "$TOOL_DIR" "browser_forensics"
    log "Running browser_forensics"
    (
        cd "$TOOL_DIR"
        run_checked "browser_forensics" 0 \
            "$TOOL_DIR/target/release/browser_forensics" \
            --evidence-dir "$BROWSER_EVIDENCE_DIR" \
            --json "$OUT_DIR/report.json" \
            --html "$OUT_DIR/report.html" \
            --summary
    )
    echo "browser_forensics -> $OUT_DIR" >> "$MANIFEST"
    record_report "browser_forensics" "$OUT_DIR/report.html"
else
    warn "Skipping browser_forensics: --browser-evidence-dir not provided"
fi

# Network Forensics
if [[ -n "$NETWORK_LIVE_JSON" || -n "$NETWORK_KAPE_PATH" || -n "$NETWORK_EVTX_PATH" ]]; then
    TOOL_DIR="$WORKSPACE_DIR/network_forensics"
    OUT_DIR="$OUTPUT_ROOT/network_forensics"
    /bin/mkdir -p "$OUT_DIR"
    build_release_binary "$TOOL_DIR" "netforens"
    NETWORK_ARGS=(--out-format all --out-dir "$OUT_DIR")
    if [[ -n "$NETWORK_LIVE_JSON" ]]; then
        NETWORK_ARGS+=(--live-json "$NETWORK_LIVE_JSON")
    fi
    if [[ -n "$NETWORK_KAPE_PATH" ]]; then
        NETWORK_ARGS+=(--kape-path "$NETWORK_KAPE_PATH")
    fi
    if [[ -n "$NETWORK_EVTX_PATH" ]]; then
        NETWORK_ARGS+=(--evtx-path "$NETWORK_EVTX_PATH")
    fi
    if [[ -n "$NETWORK_IOC_FEED" ]]; then
        NETWORK_ARGS+=(--ioc-feed "$NETWORK_IOC_FEED")
    fi
    log "Running network_forensics"
    (
        cd "$TOOL_DIR"
        run_checked "network_forensics" 0 \
            "$TOOL_DIR/target/release/netforens" \
            "${NETWORK_ARGS[@]}"
    )
    echo "network_forensics -> $OUT_DIR" >> "$MANIFEST"
    record_report "network_forensics" "$OUT_DIR/forensic_report.html"
else
    warn "Skipping network_forensics: no network input flags provided"
fi

# Memory Correlation
if [[ -n "$MEMORY_INPUT" ]]; then
    TOOL_DIR="$WORKSPACE_DIR/memory_corelation"
    OUT_DIR="$OUTPUT_ROOT/memory_corelation"
    /bin/mkdir -p "$OUT_DIR"
    build_release_binary "$TOOL_DIR" "vol3-correlate"
    log "Running memory_corelation"
    (
        cd "$TOOL_DIR"
        run_checked "memory_corelation" 0 \
            "$TOOL_DIR/target/release/vol3-correlate" \
            --input "$MEMORY_INPUT" \
            --output all \
            --output-dir "$OUT_DIR"
    )
    echo "memory_corelation -> $OUT_DIR" >> "$MANIFEST"
    record_report "memory_corelation" "$OUT_DIR/report.html"
else
    warn "Skipping memory_corelation: --memory-input not provided"
fi

# Registry Parser + Registry Analyzer
if [[ -n "$REGISTRY_DIR" ]]; then
    PARSER_DIR="$WORKSPACE_DIR/registry_parser"
    ANALYZER_DIR="$WORKSPACE_DIR/registry_analyzer"
    PARSER_OUT_DIR="$OUTPUT_ROOT/registry_parser"
    ANALYZER_OUT_DIR="$OUTPUT_ROOT/registry_analyzer"
    COMBINED_JSON="$PARSER_OUT_DIR/combined.json"
    /bin/mkdir -p "$PARSER_OUT_DIR" "$ANALYZER_OUT_DIR"

    build_release_binary "$PARSER_DIR" "registry_parser"
    build_release_binary "$ANALYZER_DIR" "registry_analyzer"

    log "Running registry_parser"
    (
        cd "$PARSER_DIR"
        run_checked "registry_parser" 0 \
            "$PARSER_DIR/target/release/registry_parser" \
            --dir "$REGISTRY_DIR" \
            --output-dir "$PARSER_OUT_DIR" \
            --combined-output "$COMBINED_JSON"
    )
    echo "registry_parser -> $PARSER_OUT_DIR" >> "$MANIFEST"

    log "Running registry_analyzer"
    (
        cd "$ANALYZER_DIR"
        run_checked "registry_analyzer" 0 \
            "$ANALYZER_DIR/target/release/registry_analyzer" \
            --input-dir "$PARSER_OUT_DIR" \
            --output "$ANALYZER_OUT_DIR/registry_report.html" \
            --json "$ANALYZER_OUT_DIR/registry_report.json"
    )
    echo "registry_analyzer -> $ANALYZER_OUT_DIR" >> "$MANIFEST"
    record_report "registry_analyzer" "$ANALYZER_OUT_DIR/registry_report.html"
else
    warn "Skipping registry_parser/registry_analyzer: --registry-dir not provided"
fi

# SRUM Analysis
if [[ -n "$SRUM_INPUT" ]]; then
    TOOL_DIR="$WORKSPACE_DIR/srum_analysis"
    OUT_DIR="$OUTPUT_ROOT/srum_analysis"
    /bin/mkdir -p "$OUT_DIR"
    build_release_binary "$TOOL_DIR" "srum_analysis"
    log "Running srum_analysis"
    (
        cd "$TOOL_DIR"
        run_checked "srum_analysis" 0 \
            "$TOOL_DIR/target/release/srum_analysis" \
            --input "$SRUM_INPUT" \
            --output "$OUT_DIR"
    )
    echo "srum_analysis -> $OUT_DIR" >> "$MANIFEST"
    record_report "srum_analysis" "$OUT_DIR/srum_analysis_report.html"
else
    warn "Skipping srum_analysis: --srum-input not provided"
fi

# Prefetch Analyzer
if [[ -n "$PREFETCH_INPUT" ]]; then
    TOOL_DIR="$WORKSPACE_DIR/prefetch_analyzer"
    OUT_DIR="$OUTPUT_ROOT/prefetch_analyzer"
    /bin/mkdir -p "$OUT_DIR"
    build_release_binary "$TOOL_DIR" "prefetch_analyzer"
    log "Running prefetch_analyzer"
    (
        cd "$TOOL_DIR"
        run_checked "prefetch_analyzer" 1 \
            "$TOOL_DIR/target/release/prefetch_analyzer" \
            --input "$PREFETCH_INPUT" \
            --output "$OUT_DIR/report.html" \
            --format html
    )
    echo "prefetch_analyzer -> $OUT_DIR" >> "$MANIFEST"
    record_report "prefetch_analyzer" "$OUT_DIR/report.html"
else
    warn "Skipping prefetch_analyzer: --prefetch-input not provided"
fi

echo "" >> "$MANIFEST"
echo "Excluded tools: data_theft, ntfs_analyzer, shimcache-amcache_analyzer, pe_entropy, forensic_correlation" >> "$MANIFEST"

log "Suite complete"
log "Output root: $OUTPUT_ROOT"
log "Manifest: $MANIFEST"
log "HTML report list: $SUMMARY"
