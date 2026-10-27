#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this validator as root on the Wazuh manager." >&2
    exit 1
fi

LOGTEST=/var/ossec/bin/wazuh-logtest
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SAMPLE="$SCRIPT_DIR/sample_event.txt"

if [ ! -x "$LOGTEST" ]; then
    echo "wazuh-logtest was not found: $LOGTEST" >&2
    exit 1
fi
if [ ! -f "$SAMPLE" ]; then
    echo "Sample event was not found: $SAMPLE" >&2
    exit 1
fi

OUTPUT=$(cat "$SAMPLE" | "$LOGTEST" 2>&1 || true)
printf '%s\n' "$OUTPUT"

printf '%s\n' "$OUTPUT" | grep -q "name: 'securescope-ntp'" || {
    echo "SecureScope decoder did not match." >&2
    exit 1
}
printf '%s\n' "$OUTPUT" | grep -q "id: '100201'" || {
    echo "SecureScope unsynchronized rule 100201 did not match." >&2
    exit 1
}

echo "SecureScope Wazuh decoder/rule validation passed."
