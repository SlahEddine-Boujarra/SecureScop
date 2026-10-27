# M4.1 development review — SIEM monitoring UX and reviewed Kimi fixes

27 October 2026. Development slice ready for review; this is not completion of all M4 screens or production approval.

## Outcome

The existing Streamlit SIEM route now presents a full-width asset monitoring table, search/state filters, 25-row pagination and an accessible observation inspector. A compact Wazuh actions menu reaches the existing connection test, collection, configuration, approved-binding and recurring-schedule workflows. All business operations remain in the existing services and PostgreSQL infrastructure.

Kimi's seven application-file changes were reviewed and integrated, with the Evidence Register's independent reviewer/scope filters preserved. The proposed Docker/bootstrap files were excluded from the runtime for the specific reasons documented in `M4_1_KIMI_REVIEW.md`. The 333 files omitted from Kimi's upload were preserved from M3.

## Exact application changes

| File | Change |
|---|---|
| `src/securescope/app.py` | SIEM presentation and compact action dispatch; explicit workspace membership/action guards; safe source-load failure state. Kimi's configured-default-workspace preference retained. |
| `src/securescope/ui/siem_presentation.py` | New read-only, allowlisted view model with canonical asset IDs, conservative expiry handling and no raw payload/credential projection. |
| `src/securescope/ui/components_v2/monitoring_workbench.py` | Existing Components v2 bridge; rejects foreign workspace/asset navigation events and duplicate nonces. |
| `src/securescope/ui/components_v2/monitoring_workbench.js` | Table/search/filter/paging, keyboard inspector, provenance and explicit scope limits. Expiry can downgrade display state; server snapshot time plus elapsed time prevents a slow browser clock prolonging proof. It never upgrades an unverified observation. |
| `src/securescope/ui/components_v2/monitoring_workbench.css` | Scoped responsive table/inspector styling using existing shared tokens. Mobile layout and focus treatment. |
| `src/securescope/ui/wazuh_monitoring_ui.py` | Compact action menu and on-demand existing editors; Kimi's readable legacy detail labels/status pill. |
| `src/securescope/ui/evidence_hub_ui.py` | Kimi's clearer evidence operations and collector navigation, register default and combined search; retained advanced reviewer/scope filters; no collection shortcut for Auditor/no-role empty views. |
| `src/securescope/ui/securescope_sidebar.py` | Existing Evidence Register route is now visible in security navigation. |
| `src/securescope/ui/pages/command_center.py` | Uses current `Monitoring verified` label for Wazuh inventory coverage instead of obsolete `Monitored`. |
| `src/securescope/ui/components/primitives.py` | Kimi's semantic status tones. |
| `src/securescope/ui/styles/components.css` | Scoped evidence-overview metric styling. |

Tests added: `tests/test_m4_siem_presentation.py`, `tests/test_m4_kimi_integration.py`, `tests/frontend/m4_monitoring.test.mjs`, and Kimi's `tests/test_command_center_evidence.py`. Updated `tests/test_stitch_ui_v5_3_8_13.py` to assert the preserved canonical Evidence Register route in visible navigation rather than require its old hidden placement.

Documentation: this report, `M4_1_PLAN.md`, `M4_1_KIMI_REVIEW.md`, root `START_M4_REVIEW.md`. Reproduction scripts, exact run logs, environment/preservation inventory and profile results are under `validation/m4_1/`. The archive includes a complete Git diff and local Git history bundle for exact review.

## Executed verification

| Check | Result | Evidence |
|---|---|---|
| Pre-change focused M3 Wazuh/UI baseline | 73 passed | `baseline-focused.log` |
| Final focused M4/Kimi Python checks | 34 passed | `focused-final.log` |
| Full Python regression suite | 908 passed, 47 skipped, 1 warning | `python-regression.log` |
| Full frontend DOM regression suite | 58 passed | `frontend-final.log` |
| Actual Streamlit route + Components v2 in Chromium 153.0.8010.0 | 12 browser checks passed at 1440px and 390px | `browser-results.json`, `browser-run.log` |
| Syntax/style | Targeted compile, new-module lint/style and changed-line lint checked | `static-checks.log`, `lint.log` |
| Source preservation | All 22 SQL migration files byte-identical; no migration added/deleted; backend/evidence/integration source unchanged; clock/ISO/export tail byte-identical | `preservation-check.json` |
| Adapter profiling | 10,000 synthetic rows profiled; no production performance claim | `profile.log`, `profile_presentation.py` |

The browser checks cover seven monitoring states, quiet-agent collection-health provenance, active-only telemetry-unverified state, inspector sections and Escape, search/empty search/reset, state filtering, native connection/collection menu transitions, CSV and Excel downloads, and mobile inspector/layout without document horizontal overflow. Desktop and mobile screenshots were inspected internally.

The browser harness loads the actual SIEM route function from source and runs it in Streamlit, with explicitly synthetic service boundaries. It does **not** bootstrap the complete authenticated application, contact Wazuh, write PostgreSQL evidence or prove end-to-end production collection. The fake collector's two IDs are test fixtures, not observed real evidence. The production application has no fixture data or new browser-test dependency.

The initial new collection test expected `None` for empty context; the existing service contract actually passes `{}`. The test was corrected without changing that contract. Kimi's visible navigation invalidated an old source-text assertion that the route must be hidden; it now checks the actual route mapping. Browser selectors were corrected to use actual accessible names/popover state. The remaining Python warning is the installed Starlette/httpx TestClient deprecation, not a failed assertion.

## Preservation and limitations

- No new migration, worker, broker, evidence ingestion rule, scanner implementation, scope association rule or human decision write. Nmap, Nuclei including zero-finding behavior, policies, Risk Management, Control Profile rules, assessments and historical records remain on the existing backend. Full non-database regressions passed.
- A.8.17 clock-evidence identity remains deferred. The complete existing SIEM clock/ISO/export tail and backend clock code are unchanged. Rendering/export checks do not validate clock collection or identity.
- The inspector shows the retained **observation** SHA-256, not a newly verified artifact hash. Exact canonical artifacts and approved scope/profile associations remain in the Evidence Register. Its navigation button opens the workspace register; it does not claim to apply an asset filter.
- The Command Center fix is current workspace inventory coverage, not verified approved-scope/control coverage. The existing workspace inventory identity matching is retained.
- Native PostgreSQL concurrency/recovery/migration checks are **unverified in this run**: no PostgreSQL executables or dedicated test database are available. All 47 skipped database tests are listed in the regression log.
- Live Wazuh and live scanner testing were **not performed**. Authentication hardening, authorized worker production gates, restore validation and live integration acceptance remain mandatory. Production recurring collection remains disabled by the unchanged gates.
- No Docker daemon is available; Kimi's proposed image/entrypoint were inspected, not built/run. No deployment artifacts from that proposal were activated.
- Shared shell/global navigation styling and the remaining ATLAS screens have not been redesigned. M4 continues screen by screen after review of this slice; M5 has not started.

## Acceptance checklist

- [x] Review Kimi changes against the actual M3 baseline; preserve omitted files.
- [x] Integrate applicable fixes without replacing the in-progress M4 implementation.
- [x] Full-width monitoring table; responsive inspector, search, filtering and paging.
- [x] Active-agent status alone never becomes verified monitoring; zero alerts alone never becomes monitoring absence.
- [x] Expired observations downgrade while the view stays open, including a browser clock behind the server.
- [x] Membership/action guards, safe text rendering and workspace/asset navigation isolation tested.
- [x] Existing configuration/binding/schedule service surfaces and CSV/Excel exports retained.
- [x] Human assessments, historical evidence, migrations and deferred clock identity code preserved.
- [x] Focused/full available regressions and synthetic browser checks executed.
- [ ] Native PostgreSQL, live Wazuh/scanner, authenticated full-application and production-gate acceptance — outstanding.
- [ ] User review of this M4.1 UI slice — pending; no claim of complete M4 acceptance.
