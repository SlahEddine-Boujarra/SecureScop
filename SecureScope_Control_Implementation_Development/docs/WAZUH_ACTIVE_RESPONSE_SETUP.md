# Wazuh Active Response setup

The Active Response adapter is optional and disabled by default. Leave it
disabled unless the Wazuh manager and endpoint change-control process have been
reviewed.

## Default configuration

```dotenv
WAZUH_REMEDIATION_EXECUTION_ENABLED=false
REMEDIATION_WORKER_AUTOSTART=false
WAZUH_REMEDIATION_COMMAND_ALLOWLIST=
```

No remote action is possible with these defaults.

## Reviewed artifacts

- Linux: `integrations/wazuh/remediation/linux/securescope_security_updates.sh`
- Windows launcher: `integrations/wazuh/remediation/windows/securescope_security_updates.cmd`
- Windows implementation:
  `integrations/wazuh/remediation/windows/securescope_security_updates.ps1`

The registry in `remediation_recipes.json` stores a fixed command ID, recipe
version and SHA-256 for each executable artifact. The registry refuses missing,
modified or path-traversing artifacts.

## Administrator procedure

1. Review each script and its rollback/restart implications.
2. Copy the appropriate artifact to the Wazuh endpoint Active Response folder.
3. Configure matching `<command>` entries on the Wazuh manager using the exact
   command IDs from the recipe registry.
4. Restrict the manager configuration to the intended agents and test in a
   non-production workspace.
5. Add only the reviewed command IDs to
   `WAZUH_REMEDIATION_COMMAND_ALLOWLIST`.
6. Enable `WAZUH_REMEDIATION_EXECUTION_ENABLED=true` only after approval.
7. Enable `REMEDIATION_WORKER_AUTOSTART=true` only when automated dispatch of
   already approved requests is required.

The endpoint scripts read Wazuh JSON from standard input and reject any command
other than `add`. SecureScope also requires exact workspace and asset
confirmation, a compatible active agent, recipe integrity and an approver.

After dispatch, the worker waits at least
`REMEDIATION_VERIFICATION_DELAY_SECONDS`, queues a targeted verification scan
and leaves the result pending verification.
