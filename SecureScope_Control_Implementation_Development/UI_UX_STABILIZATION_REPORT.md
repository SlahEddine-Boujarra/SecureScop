# SecureScope UI/UX stabilization — 29 September 2026

## Delivery and verification boundary

This is a presentation-only update of the recovered latest source archive (prior source revision `7a0e29bf759745bcda439aabc6eb49e8650063a0`). It preserves the current Programme Foundation, Risk Management, Policies and Control Assurance architecture.

The actual application was started before editing. It stopped at the missing `SECURESCOPE_DATABASE_URL` configuration. Consequently, the visual work used production renderers with synthetic in-memory records, not a connected customer workspace. No database migration, scanner operation, credential write or customer-record modification was performed.

**The code changes are delivered; full live-environment acceptance remains open.** Nmap and Client Workspace received field-component verification, not full routed-page verification. OpenVAS/Nuclei connectivity and complete integration pages also require the configured scanner host. Screenshots must not be interpreted as proof of live integrations or successful database writes.

## Changes

| Area | Correction |
| --- | --- |
| Text fields | Current Streamlit text-input and textarea elements get visible token-based borders/backgrounds and accent focus. Selectors do not target checkbox, radio, date, slider, upload or custom-component inputs. Existing assessment styles remain in place. |
| Application toolbar | Supported Streamlit 1.62 `client.toolbarMode = "viewer"` removes developer controls; no toolbar-hiding CSS was added. |
| Back navigation | Existing Python and JavaScript Back-link styles use the brand token. Narrow overrides resolve older global button rules. |
| Foundation Overview | Same card renderer remains in use. A 220px minimum replaces 360px; native stretch layout aligns cards within a row and grouped actions sit at the bottom. Scope version and boundary metrics are preserved. |
| Assurance | Compact KPI styling preserves all metrics. What Needs Attention is a sorted list of compact native action rows. Meaningful zeros remain visible and muted; View still selects the existing filter. |
| Remediation | Existing metrics support a compact variant; actionable counts retain emphasis and zeros are muted. Workflow stages and their calculations are unchanged. |
| Resolve Gap | Status, expected result, reason and next action are prominent; technical source/asset details move into a disclosure. Existing action handlers and permissions remain. One main action is emphasized. No Evidence remains neutral. |
| Evidence | Existing actor and role render as an escaped identity chip; owner stays editable. Evidence detail includes owner and freshness. Provider identifiers/mapping columns move into Technical details while retaining editor data. |
| Configuration | Shared summary pattern distinguishes setup, unverified configuration, verified connection and unavailable/issue states. Known placeholders and sample URLs cannot imply readiness. Wazuh essentials precede Indexer/TLS details. Host-wide confirmation and the separate connection test remain intact. |
| Scanners | Nmap availability does not imply target connectivity. OpenVAS/Nuclei show concise status/context; paths and diagnostics are secondary. Scanner instructions use platform-neutral language. No commands, worker lifecycle or scanning rules were changed. |
| Disabled actions | Custom reading/operational workbench primary buttons use neutral disabled styling; Add Risk Register permissions are unchanged. Policy Builder is excluded from this styling. |
| Disclosures and layout | Shared native disclosure styling; content remains intact. Main content clears the fixed Streamlit header. |
| Internal copy | Gap Actions refactor language removed. Sidebar build/roadmap table requires explicit `SECURESCOPE_INTERNAL_DIAGNOSTICS=true`; its tracking data remains. |
| Accessibility | Application-owned decorative context icons are hidden from accessibility output. Existing text labels, native widgets, focus handling and keyboard interactions remain. |

## Reused and added presentation components

Reused: `overview_card`, `back_link`, `workflow_section`, `metric_card`, `status_pill`, the Components v2 workbench, native Streamlit forms/expanders, and `tokens.css`.

Added: `render_attention_actions` alongside the existing attention presentation helpers; `identity_context`; a compact variant of `metric_card`; and `integration_presentation.py` for display-only configuration classification and summary rendering. These do not introduce a persistence layer or control/risk/configuration model.

## Files changed

- `.streamlit/config.toml`
- `src/securescope/app.py` — configuration/connection presentation and Nmap context only
- `src/securescope/ui/assurance_dashboard.py`
- `src/securescope/ui/components/context_bar.py`
- `src/securescope/ui/components/primitives.py`
- `src/securescope/ui/components/stitch.py`
- `src/securescope/ui/components_v2/assurance_workbench.css`
- `src/securescope/ui/components_v2/assurance_workbench.js`
- `src/securescope/ui/dual_engine_ui.py`
- `src/securescope/ui/evidence_hub_ui.py`
- `src/securescope/ui/exposure_management_ui.py`
- `src/securescope/ui/grc_workspace/overview.py`
- `src/securescope/ui/integration_presentation.py` — new presentation helper
- `src/securescope/ui/securescope_sidebar.py`
- `src/securescope/ui/styles/components.css`
- `src/securescope/ui/styles/legacy.css`
- `src/securescope/ui/wazuh_settings_ui.py`
- `src/securescope/ui/workflow_sections.py`
- `scripts/stabilization_preview.py`, `scripts/verify_stabilization_browser.py`
- `tests/test_ui_stabilization.py`
- This report and `validation/stabilization/` evidence

## Validation

- Python regression suite: **639 passed, 4 skipped**. All skips explicitly require a PostgreSQL test connection. Existing dependency deprecation warnings remain.
- Frontend DOM suite: **40 passed**. Covers existing editing, save/error state, permissions, risk calculations, navigation, table and Policy Builder interactions.
- Focused final presentation/assessment checks: **19 passed**.
- Browser: production components at **1440×1000 and 1280×800**, with no recorded JavaScript/page-render exceptions in the final runs.
- Empty states captured for Foundation, Assurance, Remediation and Policies. Long policy title, disabled register action, disclosures, tabs and visible form borders checked.
- Screenshots and computed text-field styles: `validation/stabilization/`. Reproduce with `python scripts/verify_stabilization_browser.py` after installing Playwright and Chromium. The runner binds to loopback and does not require or write client data.

### Visual coverage

| Screen | Coverage |
| --- | --- |
| Foundation Overview | Production renderer with repository reads replaced by synthetic records; populated and empty states |
| Control Assurance Dashboard | Production renderer with synthetic scoped evaluations; attention panel and metrics |
| Control Profiles | Production register renderer with synthetic profiles |
| Assess Control | Production assessment renderer; assessment conclusion tab and fields |
| Control Workspace | Production browser component; Resolve Gap drawer and secondary details |
| Evidence | Production Manual Evidence form and identity component |
| Risk Management | Production register component; disabled Add Risk Register |
| Remediation | Production metric and workflow components, populated/zero states |
| Policies and Policy Builder | Production browser components, long title and existing editor toolbar |
| Wazuh | Production configuration form with a synthetic administrator permission fixture; no save/test request issued |
| Nmap and Client Workspace | Shared text-field/component fixtures only; full production routes remain unverified |

## Deliberately preserved / deferred

- Policy Builder layout, editor, suggestions, document preview, Undo/Redo, Format, Previous/Next and Save behavior remain unchanged. Standalone B/I buttons were already absent in the baseline. Its existing palette is retained per the strict boundary.
- No combined automatic Save & Test was introduced: Wazuh credentials affect all workspaces and already require a separate review/confirmation. Replacing that flow would exceed a visual pass.
- No invented last-check/collection timestamps. Wazuh shows a verified result only after the existing connection test succeeds in the current render; persistent connection-history tracking was not added.
- No new breadcrumbs requiring routing changes. Existing navigation remains.
- No bulk CSS rewrite or changes to Streamlit's own generated icon markup. Application-owned icon spans were corrected; a complete screen-reader audit remains future work.
- No domain/service/repository files changed. Risk calculations, matrix logic, evidence evaluation, approval state machines, scope relationships, SoA ownership, remediation closure gates and authorization rules were not intentionally changed.

## Remaining acceptance work

Run the updated code against the normal configured PostgreSQL installation and verify full routes, scope navigation, real empty/populated records, actual integration connection tests and restricted-role sessions. Recheck mobile layouts below laptop width and a real screen reader. Formal Risk Acceptance and configurable Methodology remain at their previous availability level.

During verification, automatic approval review rejected Streamlit's unsolicited external-IP discovery. The local verification runner was restricted to loopback with an explicit browser address; subsequent local runs completed without that lookup.
