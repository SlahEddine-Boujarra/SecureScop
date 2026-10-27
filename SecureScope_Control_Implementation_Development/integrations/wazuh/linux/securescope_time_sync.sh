#!/usr/bin/env sh
set -u

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}

hostname_value=$(hostname 2>/dev/null || printf '')
ip_value=$(hostname -I 2>/dev/null | awk '{print $1}')
epoch_ms=$(date +%s%3N 2>/dev/null || printf '%s000' "$(date +%s)")
collected_at=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

synchronized=false
source_value=""
stratum_value="null"
offset_value="null"
service_value="unknown"

if command -v timedatectl >/dev/null 2>&1; then
    timedate_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [ "$timedate_sync" = "yes" ]; then
        synchronized=true
    fi
fi

if command -v chronyc >/dev/null 2>&1; then
    service_value="chrony"
    tracking=$(chronyc tracking -n 2>/dev/null || true)
    source_value=$(chronyc sources -n 2>/dev/null | awk '$1 ~ /^\^\*/ {print $2; exit}')
    [ -n "$source_value" ] || source_value=$(printf '%s\n' "$tracking" | awk -F': ' '/Reference ID/ {print $2; exit}')
    stratum=$(printf '%s\n' "$tracking" | awk -F': ' '/^Stratum/ {print $2; exit}' | awk '{print $1}')
    case "$stratum" in
        ''|*[!0-9]*) ;;
        *) stratum_value=$stratum ;;
    esac
    offset_seconds=$(printf '%s\n' "$tracking" | awk -F': ' '/^System time/ {print $2; exit}' | awk '{print $1}')
    direction=$(printf '%s\n' "$tracking" | awk -F': ' '/^System time/ {print $2; exit}' | awk '{print $3}')
    if printf '%s' "$offset_seconds" | grep -Eq '^[0-9]+([.][0-9]+)?$'; then
        offset_value=$(awk -v value="$offset_seconds" -v direction="$direction" 'BEGIN { sign=(direction=="slow"?-1:1); printf "%.3f", sign*value*1000 }')
    fi
    leap=$(printf '%s\n' "$tracking" | awk -F': ' '/^Leap status/ {print $2; exit}')
    if [ "$leap" = "Normal" ]; then
        synchronized=true
    fi
elif command -v ntpq >/dev/null 2>&1; then
    service_value="ntpd"
    source_value=$(ntpq -pn 2>/dev/null | awk '$1 ~ /^\*/ {sub(/^\*/, "", $1); print $1; exit}')
    if [ -n "$source_value" ]; then
        synchronized=true
    fi
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    service_value="systemd-timesyncd"
    source_value=$(timedatectl show-timesync --property=ServerName --value 2>/dev/null || true)
fi

printf 'SECURESCOPE_NTP: {"hostname":"%s","ip":"%s","os":"Linux","service":"%s","synchronized":%s,"source":"%s","stratum":%s,"offset_ms":%s,"epoch_ms":%s,"collected_at":"%s"}\n' \
    "$(json_escape "$hostname_value")" \
    "$(json_escape "$ip_value")" \
    "$(json_escape "$service_value")" \
    "$synchronized" \
    "$(json_escape "$source_value")" \
    "$stratum_value" \
    "$offset_value" \
    "$epoch_ms" \
    "$(json_escape "$collected_at")"
