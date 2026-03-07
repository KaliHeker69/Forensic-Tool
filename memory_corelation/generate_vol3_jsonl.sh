#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Generate Volatility3 JSONL outputs for all plugins used by this project.

Usage:
  ./generate_vol3_jsonl.sh -m <memory_image> [-o <output_dir>] [-v <vol.py path>] [--printkey <registry_key>]

Options:
  -m, --memory-image   Path to memory dump image (required)
  -o, --output-dir     Output directory for JSONL files (default: ./jsonl)
  -v, --volatility     Path to vol.py (optional). If omitted, script tries `vol` first.
      --printkey       Registry key for windows.registry.printkey (default shown below)
  -h, --help           Show this help

Default printkey:
  HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

Examples:
  ./generate_vol3_jsonl.sh -m ~/mem/win.raw
  ./generate_vol3_jsonl.sh -m ~/mem/win.raw -o ./jsonl -v ~/tools/volatility3/vol.py
  ./generate_vol3_jsonl.sh -m ~/mem/win.raw --printkey 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
  ./generate_vol3_jsonl.sh -m ~/mem/win.raw    # will auto-use 'vol3' if installed, otherwise 'vol' or provided vol.py
EOF
}

MEMORY_IMAGE=""
OUTPUT_DIR="./jsonl"
VOL_PY_PATH=""
PRINTKEY_KEY='HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
MEMORY_HASH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--memory-image)
      MEMORY_IMAGE="$2"
      shift 2
      ;;
    -o|--output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -v|--volatility)
      VOL_PY_PATH="$2"
      shift 2
      ;;
    --printkey)
      PRINTKEY_KEY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$MEMORY_IMAGE" ]]; then
  echo "[!] --memory-image is required"
  usage
  exit 1
fi

if [[ ! -f "$MEMORY_IMAGE" ]]; then
  echo "[!] Memory image not found: $MEMORY_IMAGE"
  exit 1
fi

# Compute SHA256 hash of memory image for chain of custody
echo "[+] Computing SHA256 hash of memory image..."
MEMORY_HASH=$(sha256sum "$MEMORY_IMAGE" | awk '{print $1}')
echo "    SHA256: $MEMORY_HASH"

mkdir -p "$OUTPUT_DIR"
LOG_DIR="$OUTPUT_DIR/_logs"
mkdir -p "$LOG_DIR"

# Prefer `vol3` style (vol with symbol dirs)
VOL_CMD=(vol --symbol-dirs ~/volatility3/symbols)

echo "[+] Using Volatility command: ${VOL_CMD[*]}"
echo "[+] Memory image: $MEMORY_IMAGE"
echo "[+] Output directory: $OUTPUT_DIR"
echo

# Format: output_file|plugin|extra_args
# Ordered for DLL-injection analysis: process context first, then injection indicators,
# then network/persistence/credentials.
PLUGINS=(
  # ── System info ─────────────────────────────────────────────────────────
  "info.jsonl|windows.info|"

  # ── Process enumeration (both methods required for hidden-process XCOR004) ─
  # "pslist.jsonl|windows.pslist|"
  # "psscan.jsonl|windows.psscan|"
  # "pstree.jsonl|windows.pstree|"
  # "cmdline.jsonl|windows.cmdline|"
  # "cmdscan.jsonl|windows.cmdscan|"
  # "consoles.jsonl|windows.consoles|"

  # ── DLL / handle / thread analysis (core DLL-injection artefacts) ────────
  # "dlllist.jsonl|windows.dlllist|"
  # "handles.jsonl|windows.handles|"
  # "thrdscan.jsonl|windows.thrdscan|"

  # ── Memory injection detection ───────────────────────────────────────────
  # "malfind.jsonl|windows.malfind|"
  # "vadinfo.jsonl|windows.vadinfo|"

  # ── Network ──────────────────────────────────────────────────────────────
  # "netscan.jsonl|windows.netscan|"
  # "netstat.jsonl|windows.netstat|"

  # ── Filesystem / MFT (dropped payloads, ADS hiding, resident data) ───────
  # "filescan.jsonl|windows.filescan|"
  # "mftscan.jsonl|windows.mftscan.MFTScan|"
  # "ads.jsonl|windows.mftscan.ADS|"
  # "residentdata.jsonl|windows.mftscan.ResidentData|"

  # ── Registry ─────────────────────────────────────────────────────────────
  # "hivelist.jsonl|windows.registry.hivelist.HiveList|"
  # "hivescan.jsonl|windows.registry.hivescan.HiveScan|"
  # "printkey.jsonl|windows.registry.printkey|--key ${PRINTKEY_KEY}"
  # "userassist.jsonl|windows.registry.userassist|"

  # ── Services / modules ───────────────────────────────────────────────────
  # "svcscan.jsonl|windows.svcscan|"
  # "modscan.jsonl|windows.modscan|"

  # ── Security / credentials ───────────────────────────────────────────────
  # "privileges.jsonl|windows.privileges|"
  # "getsids.jsonl|windows.getsids|"
  # "certificates.jsonl|windows.registry.certificates.Certificates|"
  # "cachedump.jsonl|windows.cachedump|"

  # ── Persistence ──────────────────────────────────────────────────────────
  # "scheduled_tasks.jsonl|windows.scheduled_tasks|"
)

TOTAL=${#PLUGINS[@]}
SUCCESS=0
FAILED=0

for i in "${!PLUGINS[@]}"; do
  IFS='|' read -r out_file plugin extra <<<"${PLUGINS[$i]}"

  out_path="$OUTPUT_DIR/$out_file"
  log_path="$LOG_DIR/${out_file%.jsonl}.log"

  echo "[$((i + 1))/$TOTAL] Running $plugin -> $out_file"

  # Use vol3 style: writes JSONL to stdout with `-r jsonl`
  cmd=("${VOL_CMD[@]}" -f "$MEMORY_IMAGE" -r jsonl "$plugin")
  if [[ -n "$extra" ]]; then
    read -r -a extra_args <<<"$extra"
    cmd+=("${extra_args[@]}")
  fi

  # Prints JSONL to stdout — capture stdout to the output file and stderr to the log
  if "${cmd[@]}" >"$out_path" 2>"$log_path"; then
    ((SUCCESS+=1))
    echo "    [+] OK"
  else
    ((FAILED+=1))
    echo "    [!] FAILED (see $log_path)"
  fi
done

echo
echo "[+] Completed. Success: $SUCCESS, Failed: $FAILED"
echo "[+] JSONL output: $OUTPUT_DIR"
echo "[+] Logs: $LOG_DIR"

if [[ $FAILED -gt 0 ]]; then
  exit 2
fi

# Run the correlation binary if it's available
echo
echo "[+] Attempting to run vol3-correlate on generated JSONL files..."
if [[ -x "./target/release/vol3-correlate" ]]; then
  echo "    [*] Executing: ./target/release/vol3-correlate --input $OUTPUT_DIR --output html --memory-hash $MEMORY_HASH"
  ./target/release/vol3-correlate --input "$OUTPUT_DIR" --output html --memory-hash "$MEMORY_HASH"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "    [!] vol3-correlate exited with code $rc" >&2
    exit $rc
  fi
  echo "    [+] vol3-correlate finished successfully. HTML output directory: ./html"
else
  echo "    [!] ./target/release/vol3-correlate not found or not executable. Build it with: cargo build --release" >&2
fi
