# SecureScope v5.3.5 project structure

## Application

- `app_ciso_nmap.py` — main Streamlit UI.
- `securescope_sidebar.py` — integrated expanded/compact sidebar, icon
  geometry, animation and page selection.
- `scanner_engine_service.py` — OpenVAS/Nuclei engine state.
- `dual_engine_ui.py` — scanner fabric and Nuclei Scan Center.
- `db_service.py` — client, asset and common scan-history persistence.

## Nuclei integration

- `nuclei_client.py` — executable discovery, health checks, profiles and safe
  argument-list construction.
- `nuclei_persistence.py` — PostgreSQL batches, exact attempts, events, worker
  state and wake requests.
- `nuclei_worker_service.py` — standalone process orchestration,
  reconciliation and finalization.
- `nuclei_worker_runner.py` — worker entry point.
- `nuclei_job_runner.py` — detached per-job child process and atomic result
  marker.
- `nuclei_report.py` — JSONL parsing, severity counts, ISO references and PDF
  bundle storage.
- `nuclei_diagnostics.py` — read-only CLI/database/worker diagnostics.
- `nuclei_worker_probe.py` — heartbeat probe.

## OpenVAS integration

The existing `openvas_*` modules remain unchanged except for shared
provider-neutral report wording.

## Supporting services

- `wazuh_service.py`, `db_wazuh_service.py` — SIEM evidence.
- `ntp_audit_service.py`, `clock_evidence_persistence.py` — time assurance.
- `iso_control_assessment_service.py`, `iso_report_service.py` — ISO evidence.
- `vulnerability_intelligence_service.py` — NVD, EPSS and KEV enrichment.
- `ciso_assistant_service.py` — GRC synchronization.

## v5.3.1 report additions

- `dual_engine_report.py` - exact scan-record lookup, provider PDF resolution,
  and consolidated OpenVAS + Nuclei report generation.
- `docs/DUAL_ENGINE_REPORTS.md` - UI action, consolidation, and PDF behavior.
- `tests/test_dual_engine_reports.py` - combined-record, PDF, and nullable PID
  regression tests.

## v5.3.2 remediation

- `finding_domain.py` — canonical finding identity and lifecycle rules.
- `exposure_repository.py` — workspace-scoped findings, plans, tasks, risk
  acceptance and audit persistence.
- `quick_remediation_service.py` — deterministic grouping, priority and plan
  preparation.
- `remediation_domain.py` — validated remediation-plan input.
- `remediation_recipe_service.py` and `remediation_recipes.json` — reviewed,
  integrity-checked recipe registry.
- `remediation_execution_repository.py` — approved execution queue and events.
- `wazuh_remediation_adapter.py` — default-off Wazuh Active Response boundary.
- `remediation_worker_service.py` and `remediation_worker_runner.py` —
  asynchronous dispatch and delayed verification queueing.

## v5.3.2 Gap Assessment

- `gap_assessment_domain.py` — quantitative, checklist, process, SLA,
  effectiveness, evidence, risk and composite models.
- `grc_repository.py` — versioned profiles, targets, assessments, criteria,
  assurance dimensions, gaps, actions, SoA and Risk Treatment Plans.
- `exposure_management_ui.py` — the new Remediation and Gap Assessment pages.

## v5.3.3 targeted UI correction

- `securescope_ui_theme.py` — fixed expanded-menu alignment and separated,
  wrapping tab buttons.
- `app_ciso_nmap.py` — removed the workflow and clock-assurance presentation
  from Asset Management only.
- `tests/test_ui_fix_v5_3_3.py` — static regression contracts for these UI
  boundaries.

## v5.3.5 sidebar integration

- `securescope_sidebar.py` — production version of the validated standalone
  menu.
- `app_ciso_nmap.py` — passes the active workspace, counters and real dialog
  callbacks to the sidebar component.
- `tests/test_sidebar_integration_v5_3_5.py` — routing, callback, compact
  geometry and workspace-isolation regression contracts.

## Database upgrade

- `migration_service.py` — ordered, checksum-protected PostgreSQL migrations.
- `database/migrations/001_v6_exposure_grc.sql` — canonical exposure,
  remediation and GRC schema.
- `database/migrations/002_v6_1_quick_remediation.sql` — approved execution
  and execution-event schema.
- `run_migrations.py` and `run_migrations.ps1` — migration entry points.
