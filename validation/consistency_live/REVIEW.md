# fix ui/ux desgin — app-wide consistency and accessibility

Date: 2026-10-02
Status: implemented and verified against a fresh isolated PostgreSQL instance and the real Streamlit application.

## Changes

- Removed app.py's conflicting dark sidebar gradient, light labels, white button text fill, radio/checkbox labels, expander and code overrides. The generic page-button readability patch now excludes sidebar descendants. sidebar.css remains the light-sidebar authority, including explicit currentColor text fill for nested labels.
- Added one native navigation adapter in ui/components/navigation.py. Programme Foundation, Governance, Discovery tasks, Risk lifecycle, Risk workspace and Evidence use native tabs with icon labels. Existing native tab call sites share the same wrapper. Canonical selection keys, pending navigation and callbacks are retained. Filter controls and genuine view toggles remain filters/toggles.
- Removed 13 competing native-tab blocks from legacy.css. The shared bar uses white surfaces, a teal selected underline, identical spacing and native overflow controls. Embedded workbench navigation uses a shared icon/label shell with overflow arrows and the same visual treatment.
- Programme Foundation native forms now use a scoped shared card/form/metric shell. Discovery recommendation states use the shared status pill; Engagement uses readable summary fields and a status pill without truncating the engagement type. Existing Context, Interested Parties and Governance workbench tables/cards retain their renderers, fields, permissions and events, with consistent spacing and surfaces. Discovery and Engagement inherit the same native form treatment. No workflow or persistence was replaced.
- Reused identity_context for the control owner/assessor, policy editor/approver, comment author/reply identity, risk task owner, Foundation owner/session/history, historical treatment owner and recorded evaluation author. Existing identity fields are still editable in their original forms.
- No migrations, repositories, domain services, assessment calculations or disclaimers changed.

## Verification performed

- Fresh native PostgreSQL was initialized as the existing unprivileged nobody account, listening only on localhost. All 14 migrations applied successfully; see migrations.txt.
- Python regression suite including PostgreSQL integration tests: **654 passed, no skips**. See python-tests.txt. One previously skipped rollback test had an outdated error-message regex; it now matches the existing message and still verifies that both task and audit changes roll back. No persistence behavior changed.
- Frontend DOM suite: **48 passed**; see frontend-tests.txt.
- The real entry point `streamlit run src/securescope/app.py` was launched at desktop width 1440 x 1000. The normal Client Workspace administrator setup/sign-in was used. This browser session used real repository reads/writes against the isolated database, without monkeypatches or preview renderers.
- Captured all seven Foundation sections, both Governance sub-tabs, all three Discovery task sub-tabs after saving a test organization profile, six Risk lifecycle stages, eight Control Assurance tabs, and all nine Evidence tabs. See page-verification.json and the PNG files. None of the captured module pages reported a Streamlit exception.
- Visually compared actual browser crops of Foundation, Risk Management, Control Assurance and Evidence navigation in navigation-comparison.png. All use the same white surface, icon/label spacing, teal active state and underline. Evidence overflow is visible; all nine destinations were opened successfully.
- Sidebar workspace-button `color`, `-webkit-text-fill-color`, nested label color and nested text fill are all **rgb(11, 28, 48)**. The sidebar background is **rgb(255, 255, 255)**. Normal, hover and focus checks passed; the workspace-switch dialog opened. See sidebar-computed-styles.json, sidebar-states.json and workspace-switch-dialog.png.
- Sidebar checkbox/radio labels, expander summaries and code elements were not rendered in this current sidebar. Their conflicting dark-theme source rules were removed and shared currentColor treatment added; no computed check is claimed for an absent element.
- The isolated native-tab browser check also verified canonical selection keys, callback order and programmatic navigation. Source/DOM tests cover the same context and identity contracts.
- The final Discovery/Engagement presentation polish additionally passed 39 focused regression tests and a fresh real-app capture; see final-foundation-migrations.txt and the updated screenshots.
- Compile checks and `git diff --check` passed.

## Verification environment and limits

The initial restricted execution environment denied switching to an unprivileged user, so an early real-app attempt stopped at database readiness. A permission-reviewed execution successfully enabled the legitimate non-root PostgreSQL setup. The initial blocker is resolved; it is not an outstanding acceptance limitation.

Records used here are the real freshly migrated default workspace/catalog plus a test administrator and saved Discovery organization profile. No production client database, scanner execution or external evidence integration was exercised. Screenshots show fresh-database and Discovery test-data states, not a production populated client. The verification changes live only in the isolated database, not application seed logic.

## Flag A — product/compliance decision required; no behavior changed

The catalog DOES distinguish `kind="clause"` and `kind="annex_a"` in grc/control_catalog.py:_catalog_entry. Profile presentation also distinguishes Annex A from ISO requirements using the control identifier. SoA export/editor rows are restricted to A.* in exposure_management_ui.py:_soa_rows_for_export.

However, grc/assurance_requirements.py:evaluate_assurance applies its Applicability result and the applicability blocker without a clause/Annex A branch. Thus an existing distinction is not consistently used by the shared evaluation/presentation path. Product/compliance needs to decide the clause-specific presentation and evaluation contract before any behavior changes. This pass leaves it unchanged.

## Flag B — traceability exists in part; no behavior changed

Related Risk Treatments is not an unconditional stub in the current code. grc_workspace/linked_modules.py:render_related_risk_treatments loads canonical risk-register records, applies the current Scope filter, displays recorded treatment/control references, and opens the canonical risk workflow. The empty message is conditional on that query's result.

SoA items already store related_risks and related_treatment_plans as JSON arrays (database/migrations/001_v6_exposure_grc.sql; grc_repository.py's SoA write). The editor normalizes comma-separated strings into those arrays. Storage of references is therefore present, but these arrays alone do not prove enforced canonical identity/referential integrity or a complete clickable justification → treatment decision → scenario audit trail. The related-treatments table is not itself that per-SoA-justification traceability view.

Product/compliance should confirm the required canonical link validation, display and approval completeness rules. No evidence found here establishes a committed implementation roadmap; that cannot be inferred from the empty-state copy. No new relationships, automatic backfills or workflow changes were introduced.
