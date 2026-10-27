#!/usr/bin/env bash
set -euo pipefail

marker="SECURESCOPE_REMEDIATION"
recipe_id="ubuntu-security-updates"
log_path="${SECURESCOPE_REMEDIATION_LOG_PATH:-/var/ossec/active-response/active-responses.log}"

write_event() {
    local status="$1"
    local exit_code="$2"
    local message="$3"
    local restart_required="$4"
    printf '{"marker":"%s","recipe_id":"%s","status":"%s","exit_code":%s,"restart_required":%s,"message":"%s","timestamp_utc":"%s"}\n' \
        "$marker" "$recipe_id" "$status" "$exit_code" "$restart_required" \
        "${message//\"/\\\"}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$log_path"
}

if ! IFS= read -r wazuh_message; then
    write_event "failed" 6 "Missing Wazuh Active Response input." false
    exit 6
fi
if [[ ! "$wazuh_message" =~ \"command\"[[:space:]]*:[[:space:]]*\"add\" ]]; then
    write_event "ignored" 0 "Only the Wazuh add action is supported." false
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    write_event "failed" 1 "Root privileges are required." false
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    write_event "failed" 2 "This recipe supports apt-based systems only." false
    exit 2
fi

if ! command -v unattended-upgrade >/dev/null 2>&1; then
    write_event "failed" 3 "Install and approve unattended-upgrades first." false
    exit 3
fi

if ! apt-get update; then
    write_event "failed" 4 "Package metadata refresh failed." false
    exit 4
fi

if ! DEBIAN_FRONTEND=noninteractive unattended-upgrade -d; then
    write_event "failed" 5 "Security update installation failed." false
    exit 5
fi

restart_required=false
if [[ -f /var/run/reboot-required ]]; then
    restart_required=true
fi
write_event "completed" 0 "Approved security updates were processed." "$restart_required"
exit 0
