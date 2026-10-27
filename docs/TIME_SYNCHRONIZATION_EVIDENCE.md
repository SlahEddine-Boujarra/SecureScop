# Time-synchronization evidence for ISO/IEC 27001 A.8.17

SecureScope does not treat UDP/123 as proof that an endpoint clock is
synchronized. UDP/123 only shows that a target answers as an NTP server.

## Endpoint collection

Wazuh schedules a reviewed local script on each enrolled endpoint.

### Windows

The probe checks:

- the `W32Time` service is running;
- `w32tm /query /status /verbose` succeeds;
- the time source is not blank and is not `Local CMOS Clock`;
- the source and stratum;
- one `w32tm /stripchart` sample against the configured source, converted to
  milliseconds when available;
- the endpoint UTC epoch at collection time.

### Linux

The probe checks the available local implementation:

- `timedatectl` for `NTPSynchronized`;
- `chronyc tracking -n` and `chronyc sources -n`;
- `ntpq -pn`; or
- active `systemd-timesyncd`.

For chrony, SecureScope collects the selected source, stratum, system-time
offset and leap status.

## Wazuh transport

The script emits one line beginning with `SECURESCOPE_NTP:` followed by JSON.
Wazuh forwards the output, custom rules identify it, and SecureScope searches
the configured `wazuh-alerts-*` index for the latest event per endpoint.

## Nmap correlation

Evidence is joined to the selected client workspace in this order:

1. exact IP address;
2. exact hostname;
3. Wazuh agent ID obtained from the existing agent-to-asset correlation.

An unmatched Nmap asset remains `No evidence`; it is never counted as
synchronized.

## Decision rules

Default environment values:

```env
NTP_OFFSET_TOLERANCE_MS=1000
NTP_MANAGER_DELTA_TOLERANCE_MS=5000
NTP_EVIDENCE_MAX_AGE_MINUTES=15
```

SecureScope applies the following order:

1. Event older than the maximum age → `Stale evidence`.
2. Endpoint service reports unsynchronized → `Not synchronized`.
3. Absolute endpoint source offset exceeds tolerance → `Out of tolerance`.
4. Absolute endpoint epoch / Wazuh-event delta exceeds the wider tolerance →
   `Out of tolerance`.
5. Otherwise → `Synchronized`.

The endpoint-reported source offset is the primary precision signal. The
endpoint/Wazuh event delta is supporting evidence only because transport and
indexing delay are included.
