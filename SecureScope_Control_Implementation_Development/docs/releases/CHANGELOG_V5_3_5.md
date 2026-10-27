# SecureScope v5.3.5

## Integrated animated sidebar

- Added `securescope_sidebar.py` as the production sidebar component.
- Replaced the duplicated sidebar implementation in `app_ciso_nmap.py` with a
  small integration adapter.
- Connected the real Client workspaces and Connection status dialogs to the
  validated menu controls.
- Preserved the existing page identifiers and dashboard quick-action routes.
- Preserved workspace switching and all `client_id`-scoped application data.
- Added static regression contracts for menu routing, callbacks, compact
  geometry and workspace-state cleanup.

No Nmap, OpenVAS, Nuclei, Wazuh, PostgreSQL, worker, report, remediation or
ISO-assessment implementation was replaced.
