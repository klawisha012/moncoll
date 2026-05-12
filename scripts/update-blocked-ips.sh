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
    OUTPUT_FILE="/configs/angie/http.d/blocked_ips.conf"
    # Container names — derive from compose project or use defaults
    COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-waf}"
    CROWDSEC_CONTAINER="${COMPOSE_PROJECT}-crowdsec-1"
    ANGIE_CONTAINER="${COMPOSE_PROJECT}-angie-1"
else
    # Running on the host — use relative paths
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    OUTPUT_FILE="$SCRIPT_DIR/../configs/angie/http.d/blocked_ips.conf"
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

# Only update if there are changes
if [ -s "$TMP_FILE" ]; then
    if ! diff -q "$TMP_FILE" "$OUTPUT_FILE" > /dev/null 2>&1; then
        mv "$TMP_FILE" "$OUTPUT_FILE"
        echo "Updated blocked IPs list ($(wc -l < "$OUTPUT_FILE") IPs blocked)"
        # Reload Angie to apply new deny rules
        docker exec "$ANGIE_CONTAINER" angie -s reload 2>/dev/null || true
    else
        rm "$TMP_FILE"
    fi
else
    # If TMP_FILE is empty, it means something went wrong (docker exec failed, no decisions, etc.)
    # DO NOT clear the existing file — keep the last known good state
    rm -f "$TMP_FILE"
    echo "No blocked IPs retrieved (CrowdSec may be starting or docker unavailable)"
fi
