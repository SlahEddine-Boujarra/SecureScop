# SecureScope UI hardening audit — v5.4.3

This handoff covers the eleven reported defects, shared components and continued
toolkit work. Source and offline interaction checks were performed. The deployed
browser, PostgreSQL database and scanner services were unavailable; this is not
a production visual or database acceptance report.

## Located bugs and implemented fixes

Paths are relative to `src/securescope/`. The initial audit was shared before
editing; this table records the resulting implementation.

| Bug | Located in | Change and limit |
| --- | --- | --- |
| 1. Workspace tooltip | `ui/securescope_sidebar.py::render_sidebar_menu` | Removed redundant workspace-button help in compact and expanded modes. There was no tooltip session flag; the suspected flag was not the cause. Button text supplies the accessible name. |
| 2. Ghost navigation | Same function, navigation callbacks | Page switches run from callbacks; render a stable sidebar frame, discard old transition state and suppress stale rerun content. animate_transition was already ignored. Browser acceptance remains necessary. |
| 3. Two-character context | `ui/components/context_bar.py`; `ui/styles/components.css` | Removed the narrow hidden-icon column effect. Client, engagement and scope each get a wrapping cell with a full-value title. The shell renders the context across pages. |
| 4. ANSI text | `core/output_sanitizer.py`; `scanners/nuclei/nuclei_client.py`; `ui/dual_engine_ui.py` | Reuse strip_ansi_sequences/display_tool_output for health, version, worker and report errors; handle textual SGR fragments too. |
| 5. Developer paths | Same sanitizer and Nuclei health methods | Redact user-profile paths in displayed output; show generic binary/template labels. Internal paths still work. |
| 6. TLS defaults | `integrations/wazuh_service.py`; `integrations/ntp_audit_service.py`; `ui/wazuh_settings_ui.py` | API and Indexer verification default on independently. Either opt-out has a persistent warning, including for read-only users. NTP collection also loads protected settings. |
| 7. Credential disclosure | `ui/wazuh_settings_ui.py`; `integrations/credential_store.py`; `integrations/wazuh_service.py` | Require host-authorized identity AND workspace Administrator. Never prefill saved secrets. Review and confirmation precede atomic Fernet-encrypted storage; no password writes to .env. Blank replacement inputs retain saved encrypted values. |
| 8. KEV/EPSS missing | `integrations/vulnerability_intelligence_service.py`; `ui/intelligence_ui.py`; finding/remediation tables | Join canonical findings to CVE cache. Failed, missing or partial checks remain unavailable rather than false negatives or zero EPSS. CVE-less findings are explicitly not applicable. |
| 9. Radar clipping | `ui/gap_charts.py::radar_chart` | Increase height, radial bounds and label margins; autosize with unclipped labels. |
| 10. Truncated tables | `ui/components/primitives.py::readable_table`; Asset/Wazuh in `app.py`; Components v2 table | Add paged reading view with wrapped cells/full-value titles and a compact-native-table toggle. |
| 11. Percentage overlap | `ui/components/progress_card.py`; component stylesheet | Dedicated Foundation classes and separate header position the percentage above the track without table-progress CSS collisions. |

Page switching stops the current script, making render-loop interruption a
real risk. [Streamlit navigation API](https://docs.streamlit.io/develop/api-reference/navigation/st.switch_page)

KEV and EPSS use CISA and FIRST feeds; NVD_API_KEY is not their prerequisite.
An NVD key would not repair the disconnected cache read.
[FIRST EPSS data/API](https://www.first.org/epss/data)

The native password widget can reveal a newly typed replacement to its author.
Saved secrets are never sent back to the widget. Existing plaintext credentials
in an old host configuration are not silently deleted. The encryption key must
be configured and kept separately from the encrypted file.

## Shared design system

`ui/styles/tokens.css` is the token source for semantic colors, spacing,
typography, radii, shadows and sidebar widths. `components.css` and
`sidebar.css` consume them; `legacy.css` retains older layout rules.
This is incremental: untouched screens still have legacy styles.

| Shared function in ui/components/primitives.py | Use |
| --- | --- |
| metric_card | Escaped label, value and detail |
| panel_heading | Consistent title/supporting text |
| empty_state | Reusable empty/error/loading presentation |
| status_pill | Muted waiting states, amber action, explicit success/error |
| readable_table | Escaped, wrapped, paginated reading surface |

dashboard_metric_card, _soft_metric_card and asset_meta_card delegate to the
shared implementation. app.safe_text remains available and delegates to the
same core.presentation.safe_text helper. Dynamic HTML in the new components
uses that boundary. Existing SQL parameterization remains intact.

Discovery copy describes preview before import; Asset Management describes the
committed inventory. Nmap remains available. Continued changes also include
bulk project dates, editable control profiles/evidence workflows and direct
per-asset scan-report downloads.

## Toolkit implementation and limits

See [the final mapping and schema proposal](TOOLKIT_MAPPING_PROPOSAL.md).

- Original files are included under config/toolkit_templates.
- Upload parsing, preview/diff and validation work. Applying uploaded rows is
  disabled pending actual database-column/constraint review. Existing manual
  editors and saves remain usable.
- Sample risk/opportunity input rows are blank; the sample SoA's 93 Yes values
  lack justifications. None should become approved assessments automatically.
- Migrations 008/009 are normal .sql files now; the runner ignores .disabled.
  Renaming did not alter SQL bytes, preserving prior applied checksums. No
  reliable history explains their previous uncommitted filenames. The apparent
  missing commas were valid column-level CHECK clauses. No live migration ran.
- No dedicated opportunity migration or reference-content extraction was made.

reporting/template_toolkit.py copies the original XLSX archive and patches only
input cells. It preserves namespace declarations, formulas and untouched parts.
Both simple exports and template inputs use the shared spreadsheet sanitizer.

Before downloading, the UI requests LibreOffice recalculation and checks formula
definitions/caches, all error cells, chart/pivot design, pivot records and chart
series caches. Changed editor data/templates invalidate prepared downloads.
Failure produces an error, never an unverifiable file.

This is materially harder than plain export: the supplied workbooks contain
extensions openpyxl warns it cannot preserve, and pivot editing support is
limited. XML population avoids that round-trip loss; conversion can still
alter objects. [openpyxl pivots](https://openpyxl.readthedocs.io/en/stable/pivot.html),
[preservation limits](https://openpyxl.readthedocs.io/en/3.1/tutorial.html)

The local LibreOffice process did not complete a tiny-workbook check.
End-to-end faithful output is **not verified**. SECURESCOPE_SOFFICE_PATH selects
a host binary, but it must also pass preservation and cache validation; merely
configuring it does not guarantee success. No faithful populated workbook is
included as a finished deliverable.

Risk/opportunity templates support 20 rows; larger datasets are rejected
explicitly. Template bands are Low 1–4, Medium 5–11, High 12–25; existing app
bands are Low 1–4, Medium 5–9, High 10–16, Critical 17–25. The UI discloses
the difference. Imported scores/sample Yes values never drive live Gap metrics.
The app distinguishes blank/unverified residual risk; exact templates retain
their original formula behavior.

Clean data exports cover editable records and routine exchange at much lower
complexity, but do not reproduce original pivot dashboards. Their formula cells
recalculate in spreadsheet software. This is a useful interim deliverable,
not completion of the exact-template fidelity requirement.

## Remaining deployment acceptance

| Surface | Needed context |
| --- | --- |
| Sidebar/context/radar/progress/tables | Your browser at deployed screen widths; interaction tests do not prove pixels |
| Credential administration | Host identity, allowlist/key and actual workspace membership |
| Live scan/monitoring/enrichment | Connected workers and feed access |
| Database import/migration | Read-only live schema report |
| Faithful workbook download | Recalculation host passing preservation and refreshed-cache checks |
| Canonical scenario/opportunity/reference storage | Decisions in the mapping proposal |

The earlier request to remove the OpenVAS Scan Center surface is not implemented
here. The later brief describes integrations as part of the retained
architecture; OpenVAS remains available. This release does not claim a complete
redesign of every older screen.

## Streamlit versus React/Next.js

Keep Streamlit for this internal release: hardening existing forms costs less
than replacing routing, state and workflows while the product model is changing.
[Streamlit page model](https://docs.streamlit.io/develop/concepts/multipage-apps/page-and-navigation)

React gives a higher ceiling for dense editing, keyboard workflows, responsive
layouts and background updates, with explicit component/state control and more
frontend code. [React state model](https://react.dev/learn/managing-state)

FastAPI already exposes GRC workspace and evidence routes, but is not a complete
drop-in backend for every Streamlit editor. Migration must add missing APIs,
browser auth/sessions, server permissions, upload/download flows, pagination,
error handling and end-to-end tests. Host environment identity is not browser-
user authentication for multi-user deployment. Backend authorization must still
be explicitly enforced. [FastAPI scopes](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/)

Engineering estimate, not a promise: a shell plus one substantial asset/
remediation workflow could take one experienced full-stack engineer 6–12 weeks,
depending on auth/API readiness. Full parity takes longer with two UIs to
support temporarily.

Retain PostgreSQL, parameterized repositories, scanners, domain services,
credential storage and reporting. Stabilize API contracts, then migrate one
high-interaction screen when user testing justifies it. React is likely useful
for a broader self-hosted product, but is not a same-effort shortcut for these
repairs.
