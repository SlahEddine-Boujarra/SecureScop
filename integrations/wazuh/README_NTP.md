# Wazuh endpoint clock evidence for ISO/IEC 27001:2022 A.8.17

SecureScope correlates Nmap inventory records with Wazuh agents and reads a
`SECURESCOPE_NTP` JSON event generated locally on each endpoint.

## Why endpoint evidence is required

A network probe to UDP/123 can show that an asset behaves as an NTP server. It
does not prove that the asset's own operating-system clock is synchronized.
The Wazuh agent therefore runs a local probe that reads the actual endpoint time
service and sends the result to the Wazuh manager.

## Evidence fields

- endpoint IP and hostname;
- operating system and time-service name;
- synchronized state;
- active/configured time source;
- stratum when available;
- measured source offset when available;
- endpoint UTC epoch and collection time;
- Wazuh manager receipt timestamp;
- calculated manager/agent clock delta.

The source offset is the primary precision signal. The manager/agent delta is
supporting evidence because network transmission and indexing delay are included.

## 1. Install endpoint probe

### Windows agent

Copy the whole `windows` folder to the endpoint and run PowerShell as
Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_agent_clock_probe.ps1
```

Default destination:

```text
C:\Program Files (x86)\ossec-agent\securescope_time_sync.ps1
```

The script checks W32Time, its source and stratum, and attempts one
`w32tm /stripchart` source-offset measurement.

### Linux agent

Copy the whole `linux` folder to the endpoint, then run:

```bash
sudo ./install_agent_clock_probe.sh
```

Default destination:

```text
/var/ossec/bin/securescope_time_sync.sh
```

The script supports chrony, ntpd and systemd-timesyncd signals where available.

Each installer executes the probe once. Expected output begins with:

```text
SECURESCOPE_NTP: {
```

## 2. Install Wazuh manager decoder and rules

Copy the `manager` folder to the Wazuh manager and run:

```bash
sudo ./install_manager_rules.sh
```

This installs separate custom files under:

```text
/var/ossec/etc/decoders/securescope_ntp_decoder.xml
/var/ossec/etc/rules/securescope_ntp_rules.xml
```

It does not overwrite the manager's existing `local_decoder.xml` or
`local_rules.xml`.

Validate the decoder and rules with the included sample event before restarting:

```bash
sudo ./validate_manager_clock_rules.sh
```

The custom decoder uses Wazuh's JSON decoder after the `SECURESCOPE_NTP:`
marker, so fields such as `synchronized`, `source`, `offset_ms` and `epoch_ms`
are preserved as dynamic fields.

## 3. Configure centralized command monitoring

Merge `manager/agent.conf.example` into the selected Wazuh group configuration,
for example:

```text
/var/ossec/etc/shared/default/agent.conf
```

The Command module runs every five minutes and forwards output. Before
activation, validate the merged configuration:

```bash
sudo /var/ossec/bin/verify-agent-conf \
  -f /var/ossec/etc/shared/default/agent.conf
```

Centralized Command-module execution requires this line on each agent:

```text
wazuh_command.remote_commands=1
```

Add it to the agent's `local_internal_options.conf`, then restart the agent.
Enable this only for reviewed scripts and controlled Wazuh groups.

Restart the manager after validating the configuration:

```bash
sudo systemctl restart wazuh-manager
```

## 4. Verify evidence in Wazuh

Wait for one interval or restart the agent. Search `wazuh-alerts-*` for:

```text
SECURESCOPE_NTP
```

Rule IDs:

```text
100200  clock evidence received
100201  endpoint reports synchronized=false
```

## 5. Collect in SecureScope

1. Discover/save the asset with Nmap.
2. Open **SIEM & Wazuh**.
3. Select **Load Wazuh agents**.
4. Select **Collect clock evidence**.
5. Confirm that the Nmap asset is matched to an agent.
6. Review source offset, manager/agent delta and freshness.
7. Open **ISO 27001 Assessment** and inspect A.8.17.

## Interpretation

- `Synchronized`: endpoint service reports synchronization, available source
  offset is within `NTP_OFFSET_TOLERANCE_MS`, manager/agent delta is within the
  wider supporting tolerance, and evidence is current.
- `Out of tolerance`: source offset or manager/agent delta exceeds its threshold.
- `Not synchronized`: endpoint service reports no synchronization.
- `Stale evidence`: the Wazuh event is older than
  `NTP_EVIDENCE_MAX_AGE_MINUTES`.
- `No evidence`: the Nmap asset has no matching current Wazuh event.

Recommended initial thresholds:

```env
NTP_OFFSET_TOLERANCE_MS=1000
NTP_MANAGER_DELTA_TOLERANCE_MS=5000
NTP_EVIDENCE_MAX_AGE_MINUTES=15
```

Tune thresholds according to the organization's approved time-synchronization
policy and measured Wazuh transport delay.
