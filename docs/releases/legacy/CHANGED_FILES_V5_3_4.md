# Changed files in v5.3.4

## Application presentation

- `app_ciso_nmap.py`
  - removed all workflow-bar imports, calls and stale session-state handling;
  - changed the seven ISO A.8 tab labels to accessible Material-icon labels.
- `exposure_management_ui.py`
  - changed the six Gap Assessment tab labels to accessible Material-icon
    labels.
- `securescope_ui_theme.py`
  - removed the workflow-bar renderer and its CSS;
  - added a fixed-width sidebar icon column;
  - added square icon-control styling and hover/focus tooltips.

## Validation and release metadata

- `tests/test_ui_fix_v5_3_4.py`
- `VERSION.txt`
- `BUILD_VERIFICATION_V5_3_4.json`
- `FILE_MANIFEST.txt`
- `CHANGELOG_V5_3_4.md`
- `docs/CHANGED_FILES_V5_3_4.md`
- `docs/VALIDATION_RESULTS_V5_3_4.md`
- `docs/KNOWN_LIMITATIONS_V5_3_4.md`

No database migration, scanner configuration or `.env` change was added.
