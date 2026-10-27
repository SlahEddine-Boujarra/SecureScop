#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root on the Wazuh manager." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DECODER_SOURCE="$SCRIPT_DIR/local_decoder.xml"
RULE_SOURCE="$SCRIPT_DIR/local_rules.xml"
DECODER_DEST="/var/ossec/etc/decoders/securescope_ntp_decoder.xml"
RULE_DEST="/var/ossec/etc/rules/securescope_ntp_rules.xml"

for file in "$DECODER_SOURCE" "$RULE_SOURCE"; do
    if [ ! -f "$file" ]; then
        echo "Missing deployment file: $file" >&2
        exit 1
    fi
done

install -o wazuh -g wazuh -m 0640 "$DECODER_SOURCE" "$DECODER_DEST"
install -o wazuh -g wazuh -m 0640 "$RULE_SOURCE" "$RULE_DEST"

echo "Installed decoder: $DECODER_DEST"
echo "Installed rules:   $RULE_DEST"

echo "Merge agent.conf.example into the selected Wazuh group agent.conf, then run:"
echo "  /var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf"
echo "After validation, restart the manager:"
echo "  systemctl restart wazuh-manager"
