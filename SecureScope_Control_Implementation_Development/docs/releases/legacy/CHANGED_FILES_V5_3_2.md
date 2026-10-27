# Changed files in v5.3.2

## Modified from the supplied v5.3.1 archive

- `.env.example` — default-off remediation settings.
- `README.md`, `PROJECT_STRUCTURE.md`, `VERSION.txt` — release documentation.
- `app_ciso_nmap.py` — imports, two sidebar entries and two page routes.
- `db_service.py` — workspace ID lookup used by new repositories.
- `start_securescope.ps1` — migration step and optional remediation worker.
- `wazuh_service.py` — validated PUT and exact-agent Active Response methods.

## New application modules

- `exposure_management_ui.py`
- `exposure_repository.py`
- `finding_domain.py`
- `gap_assessment_domain.py`
- `grc_repository.py`
- `migration_service.py`
- `output_sanitizer.py`
- `quick_remediation_service.py`
- `remediation_domain.py`
- `remediation_execution_repository.py`
- `remediation_recipe_service.py`
- `remediation_recipes.json`
- `remediation_worker_runner.py`
- `remediation_worker_service.py`
- `wazuh_remediation_adapter.py`

## New migrations and Windows entry points

- `database/migrations/001_v6_exposure_grc.sql`
- `database/migrations/002_v6_1_quick_remediation.sql`
- `run_migrations.py`, `run_migrations.ps1`
- `start_remediation_worker.ps1`

## New reviewed endpoint artifacts

- `wazuh/remediation/linux/securescope_security_updates.sh`
- `wazuh/remediation/windows/securescope_security_updates.cmd`
- `wazuh/remediation/windows/securescope_security_updates.ps1`

## New tests and documentation

- `tests/__init__.py`
- `tests/test_gap_assessment_port_v5_3_2.py`
- `tests/test_quick_remediation_v6_1.py`
- `tests/test_remediation_guardrails_v6_1.py`
- `tests/test_ui_port_v5_3_2.py`
- `CHANGELOG_V5_3_2.md`
- the v5.3.2 documents under `docs/`.

The OpenVAS, Nuclei, Nmap, PDF, CISO Assistant, clock-evidence and scanner
engine modules listed in `BUILD_VERIFICATION_V5_3_2.json` are byte-identical to
the uploaded v5.3.1 archive.
