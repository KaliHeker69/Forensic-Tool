#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_DIR="$PROJECT_DIR/rust-backend"
MANIFEST_PATH="$RUST_DIR/Cargo.toml"

CMD="${1:-generate}"
shift || true

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

case "$CMD" in
    generate)
        exec "$CARGO_BIN" run --manifest-path "$MANIFEST_PATH" --bin dashboard_setter -- generate --summary "$@"
        ;;
    summary)
        exec "$CARGO_BIN" run --manifest-path "$MANIFEST_PATH" --bin dashboard_setter -- summary "$@"
        ;;
    build)
        exec "$CARGO_BIN" build --manifest-path "$MANIFEST_PATH" --bin dashboard_setter "$@"
        ;;
    *)
        cat <<'USAGE' >&2
Usage:
  ./scripts/run_dashboard_quickview.sh generate [--root PATH] [--output PATH] [--config PATH]
  ./scripts/run_dashboard_quickview.sh summary  [--output PATH]
  ./scripts/run_dashboard_quickview.sh build
USAGE
        exit 1
        ;;
esac
