#!/usr/bin/env bash
# start_timeline_arch.sh — Minimal Arch Linux helper to run the portal UVicorn app
# Usage: ./scripts/start_timeline_arch.sh [install|start|stop|restart|status|fg|help]

set -euo pipefail
shopt -s nullglob

# --- Configuration (customize if needed) ---
APP_MODULE="app.main:app"
HOST="0.0.0.0"
PORT=8000
WORKERS=1
RELOAD=true         # set false for production

# Virtualenv directory (default to the provided 'portal' venv in repo)
PORTAL_VENV="${PORTAL_VENV:-./portal}"
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/timeline.log"
PID_FILE=".timeline.pid"
REQUIREMENTS="requirements.txt"

# --- Helpers ---
info() { echo -e "\e[34m[info]\e[0m $*"; }
warn() { echo -e "\e[33m[warn]\e[0m $*"; }
err() { echo -e "\e[31m[error]\e[0m $*"; }

usage() {
    cat <<EOF
Usage: $0 <command>
Commands:
  install     Install Python deps into the project venv (or system) using requirements.txt
  start       Start UVicorn in background (creates $PID_FILE, writes logs to $LOG_FILE)
  stop        Stop background UVicorn (uses PID in $PID_FILE)
  restart     Stop then start
  status      Show running status and tail of log (last 20 lines)
  fg          Run UVicorn in foreground (useful for development)
  help        Show this help

Environment variables:
  PORTAL_VENV   Path to Python virtualenv (default: ./portal)
  HOST          Host to bind (default: $HOST)
  PORT          Port to run (default: $PORT)
  WORKERS       Number of workers (default: $WORKERS)
  RELOAD        true/false (default: $RELOAD)

Examples:
  # Install dependencies into the portal venv
  $0 install

  # Start server in background
  $0 start

  # Run server in foreground (useful with --reload)
  $0 fg
EOF
}

find_python() {
    # Prefer explicitly packaged venv python if available
    if [[ -x "$PORTAL_VENV/python" ]]; then
        echo "$PORTAL_VENV/python"
        return
    fi

    # Check common venv locations
    if [[ -x "./venv/bin/python" ]]; then
        echo "./venv/bin/python"; return
    fi
    if [[ -x "./.venv/bin/python" ]]; then
        echo "./.venv/bin/python"; return
    fi

    # Fallback to system python3
    if command -v python3 >/dev/null 2>&1; then
        echo "$(command -v python3)"; return
    fi

    err "python3 not found on PATH"
    exit 1
}

ensure_venv_exists() {
    if [[ -x "$PORTAL_VENV/python" ]]; then
        info "Using venv: $PORTAL_VENV"
        return
    fi

    warn "Virtualenv not found at $PORTAL_VENV"
    read -r -p "Create a venv at $PORTAL_VENV now? (y/N): " yn
    if [[ "${yn,,}" == "y" ]]; then
        python3 -m venv "$PORTAL_VENV"
        info "Created venv at $PORTAL_VENV"
    else
        warn "Continuing using system Python"
    fi
}

install_deps() {
    ensure_venv_exists
    PY=$(find_python)

    if [[ -f "$REQUIREMENTS" ]]; then
        info "Installing dependencies from $REQUIREMENTS"
        "$PY" -m pip install --upgrade pip
        "$PY" -m pip install -r "$REQUIREMENTS"
    else
        warn "$REQUIREMENTS not found — skipping install"
    fi
}

check_port_free() {
    if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
        warn "Port $PORT appears to be in use"
        return 1
    fi
    return 0
}

start_bg() {
    check_port_free || warn "Proceeding anyway"

    mkdir -p "$LOG_DIR"

    PY=$(find_python)

    ARGS=("-m" "uvicorn" "$APP_MODULE" "--host" "$HOST" "--port" "$PORT")
    if [[ "$RELOAD" == "true" ]]; then
        ARGS+=("--reload")
    fi
    if [[ -n "$WORKERS" && "$WORKERS" -gt 1 ]]; then
        ARGS+=("--workers" "$WORKERS")
    fi

    info "Starting UVicorn in background — logs: $LOG_FILE"
    nohup "$PY" "${ARGS[@]}" > "$LOG_FILE" 2>&1 &
    PID=$!
    echo "$PID" > "$PID_FILE"
    sleep 0.5
    if kill -0 "$PID" 2>/dev/null; then
        info "Started (PID $PID)"
    else
        err "Process died quickly — check $LOG_FILE"
    fi
}

start_fg() {
    PY=$(find_python)

    ARGS=("-m" "uvicorn" "$APP_MODULE" "--host" "$HOST" "--port" "$PORT")
    if [[ "$RELOAD" == "true" ]]; then
        ARGS+=("--reload")
    fi
    if [[ -n "$WORKERS" && "$WORKERS" -gt 1 ]]; then
        ARGS+=("--workers" "$WORKERS")
    fi

    info "Running in foreground — press Ctrl+C to stop"
    exec "$PY" "${ARGS[@]}"
}

stop_bg() {
    if [[ ! -f "$PID_FILE" ]]; then
        warn "No PID file ($PID_FILE) found"
        return
    fi
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        info "Stopping PID $PID"
        kill "$PID"
        sleep 0.5
        if kill -0 "$PID" 2>/dev/null; then
            warn "PID $PID still running — sending SIGKILL"
            kill -9 "$PID" || true
        fi
    else
        warn "PID $PID not running"
    fi
    rm -f "$PID_FILE"
}

status() {
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            info "Running (PID $PID)"
            tail -n 20 "$LOG_FILE" || true
            return
        else
            warn "PID file exists but process not running"
        fi
    fi

    if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
        info "Something is listening on port $PORT"
    else
        info "Not running"
    fi
}

# --- Command dispatch ---
cmd=${1:-help}
case "$cmd" in
    install)
        install_deps
        ;;
    start)
        start_bg
        ;;
    stop)
        stop_bg
        ;;
    restart)
        stop_bg
        start_bg
        ;;
    status)
        status
        ;;
    fg)
        start_fg
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        err "Unknown command: $cmd"
        usage
        exit 2
        ;;
esac
