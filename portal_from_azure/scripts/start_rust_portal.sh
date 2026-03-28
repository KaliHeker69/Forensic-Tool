#!/usr/bin/env bash
# =============================================================================
# start_rust_portal.sh  –  Production start/stop/status manager
#
# Usage:
#   ./scripts/start_rust_portal.sh start    # build release + start (default)
#   ./scripts/start_rust_portal.sh stop     # graceful shutdown
#   ./scripts/start_rust_portal.sh restart  # stop then start
#   ./scripts/start_rust_portal.sh status   # print running / stopped
#   ./scripts/start_rust_portal.sh build    # compile release binary only
#   ./scripts/start_rust_portal.sh dev      # debug build + foreground run
#
# Environment variables (override in .env or shell):
#   SECRET_KEY      – JWT signing key (required in production)
#   BIND            – host:port to listen on         (default: 0.0.0.0:8000)
#   DATABASE_URL    – SQLite path                    (default: portal.db)
#   RUST_LOG        – tracing filter                 (default: info)
#   LOG_DIR         – directory for log files        (default: $PROJECT_DIR/logs)
#   CARGO_BUILD_JOBS – parallel cargo jobs           (default: $(nproc))
# =============================================================================

set -euo pipefail

# ── paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_DIR="$PROJECT_DIR/rust-backend"
BINARY_RELEASE="$RUST_DIR/target/release/portal-rs"
BINARY_DEBUG="$RUST_DIR/target/debug/portal-rs"
PID_FILE="$PROJECT_DIR/portal.pid"
ENV_FILE="$PROJECT_DIR/.env"

# ── load .env if present ─────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
    # export non-comment, non-empty KEY=VALUE lines
    set -o allexport
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +o allexport
fi

# ── defaults ─────────────────────────────────────────────────────────────────
BIND="${BIND:-0.0.0.0:8000}"
DATABASE_URL="${DATABASE_URL:-portal.db}"
RUST_LOG="${RUST_LOG:-info}"
LOG_DIR="${LOG_DIR:-$PROJECT_DIR/logs}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"
SECRET_KEY="${SECRET_KEY:-}"

export BIND DATABASE_URL RUST_LOG SECRET_KEY

# ── colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLD='\033[1m'; RST='\033[0m'
info()  { echo -e "${GRN}[INFO]${RST}  $*"; }
warn()  { echo -e "${YLW}[WARN]${RST}  $*"; }
error() { echo -e "${RED}[ERROR]${RST} $*" >&2; }
die()   { error "$*"; exit 1; }

# ── pre-flight checks ────────────────────────────────────────────────────────
preflight() {
    # Templates and static assets are now embedded in the binary – no on-disk check needed

    # Cargo / Rust toolchain
    command -v cargo &>/dev/null \
        || die "cargo not found – install Rust via https://rustup.rs"

    # Warn on default dev secret
    if [[ -z "$SECRET_KEY" || "$SECRET_KEY" == *"dev-secret-key"* ]]; then
        warn "SECRET_KEY is not set or is the default dev key."
        warn "Generate one with:  openssl rand -hex 32"
        warn "Set it in .env or as an environment variable."
    fi

    # Check port is free (non-fatal)
    local port
    port="${BIND##*:}"
    if ss -tlnH "sport = :$port" 2>/dev/null | grep -q ":$port"; then
        warn "Port $port appears to be in use."
    fi
}

# ── release build ────────────────────────────────────────────────────────────
build_release() {
    info "Building release binary  (jobs: $CARGO_BUILD_JOBS) …"
    CARGO_INCREMENTAL=1 cargo build \
        --release \
        --jobs "$CARGO_BUILD_JOBS" \
        --manifest-path "$RUST_DIR/Cargo.toml" \
        2>&1
    info "Binary → $BINARY_RELEASE  ($(du -sh "$BINARY_RELEASE" | cut -f1))"
}

# ── start (release, daemonised) ───────────────────────────────────────────────
cmd_start() {
    preflight

    # Refuse to start a second instance
    if [[ -f "$PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            die "Portal is already running (PID $old_pid). Use 'restart' or 'stop'."
        else
            warn "Stale PID file found – removing."
            rm -f "$PID_FILE"
        fi
    fi

    # Build if binary outdated or missing.
    # Templates/static assets are embedded with include_dir!, so asset changes
    # must also invalidate the release binary.
    if [[ ! -x "$BINARY_RELEASE" ]] || \
       find "$RUST_DIR/src" "$RUST_DIR/assets" -type f -newer "$BINARY_RELEASE" 2>/dev/null | grep -q .; then
        build_release
    else
        info "Release binary is up to date."
    fi

    mkdir -p "$LOG_DIR"
    local LOG_FILE="$LOG_DIR/portal-$(date +%Y%m%d).log"

    info "Starting Resource Portal (release)"
    info "  Bind:        $BIND"
    info "  Database:    $DATABASE_URL"
    info "  Log:         $LOG_FILE"
    info "  PID file:    $PID_FILE"

    # Run server in background; cwd=PROJECT_DIR so relative paths resolve
    cd "$PROJECT_DIR"
    nohup "$BINARY_RELEASE" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    # Give the process a moment then verify it's alive
    sleep 1
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        info "${BLD}Portal is UP  (PID $(cat "$PID_FILE"))${RST}"
        info "Open → http://$BIND"
    else
        rm -f "$PID_FILE"
        die "Process exited immediately. Check logs: $LOG_FILE"
    fi
}

# ── stop ─────────────────────────────────────────────────────────────────────
cmd_stop() {
    if [[ ! -f "$PID_FILE" ]]; then
        warn "No PID file found – portal may not be running."
        return 0
    fi
    local pid
    pid=$(cat "$PID_FILE")
    if ! kill -0 "$pid" 2>/dev/null; then
        warn "PID $pid not found – removing stale PID file."
        rm -f "$PID_FILE"
        return 0
    fi
    info "Stopping portal (PID $pid) …"
    kill -SIGTERM "$pid"
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.5
        (( waited++ ))
        if (( waited > 20 )); then
            warn "Process did not exit after 10 s – sending SIGKILL."
            kill -SIGKILL "$pid" 2>/dev/null || true
            break
        fi
    done
    rm -f "$PID_FILE"
    info "Portal stopped."
}

# ── status ────────────────────────────────────────────────────────────────────
cmd_status() {
    if [[ ! -f "$PID_FILE" ]]; then
        echo -e "${YLW}Stopped${RST}  (no PID file)"
        return 0
    fi
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        local uptime
        uptime=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ' || echo 'unknown')
        echo -e "${GRN}Running${RST}  PID $pid  uptime $uptime"
        echo    "  Bind:     $BIND"
        echo    "  Database: $DATABASE_URL"
        echo    "  Log dir:  $LOG_DIR"
    else
        echo -e "${RED}Dead${RST}  (stale PID file for $pid)"
    fi
}

# ── dev (foreground debug build) ──────────────────────────────────────────────
cmd_dev() {
    preflight
    info "Building debug binary …"
    cargo build --manifest-path "$RUST_DIR/Cargo.toml" 2>&1
    info "Starting in foreground (Ctrl-C to stop) …"
    cd "$PROJECT_DIR"
    exec "$BINARY_DEBUG"
}

# ── entry ────────────────────────────────────────────────────────────────────
CMD="${1:-start}"

echo -e "${BLD}=== Resource Portal (Rust) ===${RST}  cmd=$CMD"
echo

case "$CMD" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    restart) cmd_stop; cmd_start ;;
    status)  cmd_status  ;;
    build)   preflight; build_release ;;
    dev)     cmd_dev     ;;
    *) die "Unknown command '$CMD'. Use: start | stop | restart | status | build | dev" ;;
esac
