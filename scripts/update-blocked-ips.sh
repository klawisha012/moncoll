#!/bin/bash
# Script to update blocked IPs from CrowdSec for Angie
# This script should be run periodically (e.g., every minute)

CROWDSEC_CONTAINER="waf-crowdsec-1"
OUTPUT_FILE="./configs/angie/blocked_ips.conf"
TMP_FILE=$(mktemp)

# Get decisions from CrowdSec and format for Angie
docker exec "$CROWDSEC_CONTAINER" cscli decisions list -o raw 2>/dev/null | \
  tail -n +2 | \
  grep -E "^[0-9]+,crowdsec,ip:" | \
  cut -d',' -f3 | \
  sed 's/^ip://' | \
  awk '{print "deny " $0 ";"}' > "$TMP_FILE"

# Only update if there are changes
if [ -s "$TMP_FILE" ]; then
    if ! diff -q "$TMP_FILE" "$OUTPUT_FILE" > /dev/null 2>&1; then
        mv "$TMP_FILE" "$OUTPUT_FILE"
        echo "Updated blocked IPs list"
    else
        rm "$TMP_FILE"
    fi
else
    # If no blocked IPs, clear the file
    > "$OUTPUT_FILE"
    rm "$TMP_FILE"
fi
