# Changed files — SecureScope v5.3.5

## Production

- `app_ciso_nmap.py`
  - imports the integrated sidebar;
  - replaces duplicated menu rendering with a callback adapter;
  - makes the Client History route explicit.
- `securescope_sidebar.py`
  - contains the approved expanded and compact menu;
  - owns icon alignment, active states, hover effects and transition CSS;
  - returns the existing internal page identifiers.

## Verification and documentation

- `tests/test_sidebar_integration_v5_3_5.py`
- `tests/test_ui_port_v5_3_2.py`
- `tests/test_ui_fix_v5_3_3.py`
- `README.md`
- `PROJECT_STRUCTURE.md`
- `CHANGELOG_V5_3_5.md`
- `BUILD_VERIFICATION_V5_3_5.json`
- `VERSION.txt`

No scanner, persistence, worker, report, remediation, Wazuh or ISO-assessment
module changed.
