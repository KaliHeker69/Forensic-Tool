#!/usr/bin/env bash
# Refresh the ipsum IP threat feed.
# Downloads the latest feed from GitHub and restarts the portal service
# so it loads the updated data into memory.
set -euo pipefail

FEED_URL="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IOC_DIR="${IOC_DIR:-/home/kali_arch/tools/portal/ioc}"
DEST="${IOC_DIR}/ipsum.txt"
TMP="${DEST}.tmp"
LOG="/var/log/ipsum-refresh.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting ipsum refresh"

mkdir -p "$IOC_DIR"

if ! curl --silent --fail --location \
          --max-time 60 \
          --retry 3 --retry-delay 5 \
          --user-agent "ipsum-refresh/1.0" \
          -o "$TMP" "$FEED_URL"; then
    log "ERROR: download failed"
    rm -f "$TMP"
    exit 1
fi

LINES=$(wc -l < "$TMP")
IPS=$(grep -cv "^#" "$TMP" || true)

if [[ "$IPS" -lt 10000 ]]; then
    log "ERROR: suspiciously small feed ($IPS IPs). Aborting."
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$DEST"
log "Feed updated: $IPS IPs, $LINES lines"

# Restart portal service to reload in-memory data
if systemctl is-active --quiet portal-rs; then
    systemctl restart portal-rs
    log "portal-rs restarted"
else
    log "WARNING: portal-rs is not running, skipping restart"
fi
