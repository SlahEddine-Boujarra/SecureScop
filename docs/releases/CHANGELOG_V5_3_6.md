# SecureScope v5.3.6

## Repository structure

- Adopted an installable `src/securescope` Python package.
- Separated core, UI, persistence, integrations, scanners, reporting,
  compliance, validation, and CLI modules.
- Centralized repository and runtime paths in `securescope.paths`.
- Grouped Windows operational scripts under `scripts/windows`.
- Moved Wazuh deployment artifacts to `integrations/wazuh`.
- Moved reviewed remediation recipes to `config`.

## Engineering governance

- Added GitHub Actions compilation, test, and dependency checks.
- Added `pyproject.toml`, development dependencies, editor configuration, and
  lint/format configuration.
- Added security, contribution, architecture, quality, executive, and GitHub
  publication documentation.
- Preserved the v5.3.5 animated sidebar and the complete NTP service fix.

