#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$SCRIPT_DIR/securescope_time_sync.sh"
DESTINATION="/var/ossec/bin/securescope_time_sync.sh"

if [ ! -f "$SOURCE" ]; then
    echo "Probe script not found: $SOURCE" >&2
    exit 1
fi
if [ ! -d /var/ossec ]; then
    echo "Wazuh agent directory /var/ossec was not found." >&2
    exit 1
fi

install -o root -g wazuh -m 0750 "$SOURCE" "$DESTINATION" 2>/dev/null || \
    install -o root -g root -m 0750 "$SOURCE" "$DESTINATION"

echo "Installed: $DESTINATION"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$DESTINATION"
fi

echo "Test output:"
/bin/sh "$DESTINATION"

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^wazuh-agent'; then
    systemctl restart wazuh-agent
    echo "Wazuh agent restarted."
else
    echo "Restart the Wazuh agent manually."
fi
