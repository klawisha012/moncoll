#!/bin/bash
# Script to update blocked IPs from CrowdSec for Angie
# This script should be run periodically (e.g., every 15 seconds)
#
# Can run either:
#   - On the host (uses ./configs/... relative paths, docker exec)
#   - Inside a container with docker socket mounted (uses /configs/... paths)

set -e

# Detect if running inside a container or on the host
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
    # Running inside a container — use absolute paths as mounted
    OUTPUT_FILE="/configs/angie/http.d/blocked_ips.list"
    # Container names — derive from compose project or use defaults
    COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-waf}"
    CROWDSEC_CONTAINER="${COMPOSE_PROJECT}-crowdsec-1"
    ANGIE_CONTAINER="${COMPOSE_PROJECT}-angie-1"
else
    # Running on the host — use relative paths
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    OUTPUT_FILE="$SCRIPT_DIR/../configs/angie/http.d/blocked_ips.list"
    CROWDSEC_CONTAINER="waf-crowdsec-1"
    ANGIE_CONTAINER="waf-angie-1"
fi

TMP_FILE=$(mktemp)

# Get decisions from CrowdSec and format for Angie
# Uses JSON output (stable API) parsed with jq for reliability
docker exec "$CROWDSEC_CONTAINER" cscli decisions list -o json 2>/dev/null | \
  jq -r '.[]?.decisions[]? | select(.type == "ban") | .value' | \
  sort -u | \
  awk '{print "deny " $0 ";"}' > "$TMP_FILE"

# Helper: write blocked IPs to a target file (only if changed)
write_blocked_ips() {
    local target="$1"
    if [ -s "$TMP_FILE" ]; then
        if ! diff -q "$TMP_FILE" "$target" > /dev/null 2>&1; then
            cp "$TMP_FILE" "$target"
            return 0
        fi
    fi
    return 1
}

# Only update if there are changes
UPDATED=0
if [ -s "$TMP_FILE" ]; then
    # ── Global blocked_ips.conf (for default.conf) ──
    if write_blocked_ips "$OUTPUT_FILE"; then
        UPDATED=1
    fi

    # ── Per-connection blocked_ips.conf ──
    CONFIG_DIR=$(dirname "$OUTPUT_FILE")
    for conn_dir in "$CONFIG_DIR"/conn_*; do
        if [ -d "$conn_dir" ]; then
            if write_blocked_ips "$conn_dir/blocked_ips.conf"; then
                UPDATED=1
            fi
        fi
    done

    if [ "$UPDATED" -eq 1 ]; then
        echo "Updated blocked IPs list ($(wc -l < "$OUTPUT_FILE") IPs blocked)"
        # Reload Angie to apply new deny rules — but debounce to avoid
        # rapid successive reloads that can cause ModSecurity to lose
        # its rules (0/0/0) which then drops port bindings.
        RELOAD_STAMP="/tmp/angie-last-reload"
        NOW=$(date +%s)
        if [ -f "$RELOAD_STAMP" ]; then
            LAST=$(cat "$RELOAD_STAMP" 2>/dev/null || echo 0)
        else
            LAST=0
        fi
        if [ $((NOW - LAST)) -ge 5 ]; then
            docker exec "$ANGIE_CONTAINER" angie -s reload 2>/dev/null || true
            echo "$NOW" > "$RELOAD_STAMP"
        fi
    fi

    rm -f "$TMP_FILE"
else
    # If TMP_FILE is empty, it means something went wrong (docker exec failed, no decisions, etc.)
    # DO NOT clear the existing file — keep the last known good state
    rm -f "$TMP_FILE"
    echo "No blocked IPs retrieved (CrowdSec may be starting or docker unavailable)"
fi
