# SecureScope — App-Wide UI/UX Consistency

## Delivery status

The shared presentation update is implemented and regression-checked. **Live PostgreSQL and rendered-browser acceptance remain pending.** This package does not claim newly captured application screenshots or verified production writes.

Base: supplied archive `SecureScope_Control_Implementation_Development (21)(1).zip`, version `5.4.9.dev0`. Its `validation/SOURCE_REVISION.txt` identifies source revision `c162317af65f93e0f1077f49ee6fb13282906d4d`. The archive contains no original Git history. A local baseline was created to review this update's diff.

## Inspection and design decisions

The active Programme Foundation router already has seven sections and canonical module links. The same Overview card renderer already serves Foundation and linked modules. Risk Management retains its existing lifecycle. Evidence, SoA and control assessment already use the existing scope-aware services; this update does not replace them.

Visual drift came from four inline CSS injectors, older dark-sidebar styling, independently defined shadow-component colors and a purple workbench palette. Native icon tabs and the fixed underline owner were already implemented. They are preserved.

`DESIGN.md` applies the selected StitchDesign skills to a restrained operational dashboard. Its decorative defaults are explicitly adapted to the supplied requirements: minimal motion, ordinary aligned forms, useful density and equal Overview cards. No direct Google Stitch connection or Google-generated screen is claimed.

## Implemented changes

- One slate/white/teal token system, including more readable muted text and visible field boundaries.
- Shared tokens and theme rules inside existing custom Streamlit shadow components: workbench, plan, assurance pages, editable policy component and enterprise tables.
- Four verified style-only injectors moved out of `app.py` into packaged compatibility CSS. Their geometry loads before current shared styles. Obsolete global overrides and the older dark-sidebar block were removed.
- Remaining native tab rows in assets, mapping, client dialog, provider diagnostics and scan views use the existing icon/overflow navigation adapter.
- Native forms, labels, action targets, workflow sections, identity chips and status badges receive consistent styling.
- Control Profiles, tables, cards, plan metrics, policy views and drawers use the shared theme while keeping their existing handlers and permissions.
- Reused workbenches now clear page-specific classes when changing mode. Old overflow observers disconnect before rerender, and explicit overflow scrolling respects reduced motion.
- Assessment context, owner and approved target are visible; their existing inputs and save logic remain. Optional technical settings, audit history and other secondary disclosures remain collapsed.
- Truly empty Control Profiles and assurance result views omit unused filter controls. Existing one-page pagination behavior remains.
- Ordinary native columns and custom form/card grids stack on narrow screens. Calendar and risk-matrix geometry are deliberately preserved.

## Page inventory and coverage

“Integrated” means the active renderer consumes the changed shared styles/components. It does **not** mean a live route or screenshot passed acceptance here.

| Area | Presentation integration | Live browser / database acceptance |
| --- | --- | --- |
| Programme Foundation Overview | Existing unified Overview card; shared native shell | Pending |
| Discovery and its three preparation views | Shared forms, statuses, native navigation | Pending |
| Context / Interested Parties / ISMS Scope | Existing Foundation workbench gets shared shadow theme | Pending |
| Governance: Roles & RACI / Objectives | Existing Foundation workbench and native navigation | Pending |
| Engagement | Shared native cards, table, forms and optional administration details | Pending |
| Risk registers / scenario editor / treatment / residual / monitoring | Existing workbench theme; risk editor steps and matrix preserved | Pending |
| Risk Acceptance / Methodology | Existing availability and disclaimers preserved | Pending |
| Control Assurance dashboard / Project Plan | Existing custom components get shared tokens and styling | Pending |
| Control Profiles / control detail | Shared workbench; stale mode classes and observers fixed | Pending |
| Assess Control | Existing native assessment forms; context and target visible | Pending |
| SoA / related treatment visibility | Existing canonical renderers and ownership preserved | Pending |
| Evidence overview and nine workspace views | Shared native navigation, forms, identity and cards | Pending |
| Policies / details / editor / review | Existing workbench and editor receive the shared theme | Pending |
| Assets / Nmap / Scan Center / SIEM / integration settings | Global shell, forms, cards and existing native navigation adapter | Pending; configured providers required |
| Calendar / remediation / audit views / Client Workspace | Existing component or native shared presentation | Pending |

This is a shared-component consistency pass. It does not claim a separate bespoke screen redesign for every routed page.

## Preserved boundaries

No domain, repository, migration, scanner-service or integration-service file changed. No duplicate Scope, Risk, Policy, Stakeholder, Evidence, Treatment or SoA model was introduced. Risk calculations and matrix code remain unchanged. Application changes outside `ui/` are limited to moving CSS injection and routing existing tab rows through the shared presentation adapter.

Methodological disclaimers remain. Clause applicability and SoA/risk-treatment traceability were not changed as styling fixes. Existing identity, context selection, versioning and approval state machines remain authoritative. No scan, deployment, production record write or permission change was performed.

## Validation performed

- Python: **743 passed, 5 skipped, 79 warnings**; see `validation/design_consistency/python-tests.txt`.
- Frontend DOM: **50 passed**; see `frontend-tests.txt`. Added regressions cover mode-class cleanup, empty controls and overflow-observer cleanup.
- Streamlit AppTest regressions continue checking draft saves, conclusion saves, selected-control isolation, scope behavior and navigation. These use the existing test fixtures, not a live database.
- Compilation, focused fatal/undefined-name lint and Git whitespace checks pass.
- Preview: eight Overview cards, tab navigation, filtering and stylesheet parsing checked through JSDOM. This verifies document structure and interactions, not browser paint.
- Ten static WCAG token-pair contrast calculations pass, including text, semantic states and field borders. This is **not** a computed-style or accessibility conformance claim.
- Actual application entry point exercised through AppTest: it reports the missing `SECURESCOPE_DATABASE_URL` configuration and no unexpected exception. This is startup evidence only.

The five skipped PostgreSQL checks cover project-plan persistence/isolation and legacy SoA draft migration. Warnings are recorded dependency deprecations; the complete log remains available.

## Concrete live-verification blockers

An attempt to create a fresh PostgreSQL instance failed before initialization: the container's UID/GID mapping contains only UID 0, and assigning an unprivileged database owner raises `OSError: [Errno 22] Invalid argument`. No fresh migration run is claimed.

Local Chromium could not establish a browser session. The cloud browser could not reach the loopback preview (`ERR_CONNECTION_REFUSED`). No actual rendered-page screenshots or computed sidebar paint checks were obtained. Previous screenshots elsewhere in this archive are historical and must not be treated as screenshots of this update.

## Review and run

1. Open `docs/design/Preview.html` for an interactive visual prototype. It is labeled illustrative and does not save anything.
2. Read `DESIGN.md` for the implemented design system.
3. Unpack the updated project into a separate folder and use the existing Windows launcher and normal database configuration. Restart Streamlit to reload cached custom-component CSS.
4. Use a disposable test database for migrations and database-dependent tests; never point test scripts at production.
5. For browser acceptance, install `requirements-ui-validation.txt`, then run `python -m playwright install chromium`.
6. Run `python scripts/capture_design_acceptance.py --url http://localhost:8501 --headed --pause-for-sign-in`. Select an authorized test workspace in the opened browser before continuing. The script navigates and captures without submitting forms or starting scans.
7. Review its screenshots, computed sidebar `color` and `-webkit-text-fill-color`, nested navigation, hover/focus/disabled states and scope context. Missing routes/sub-tabs are recorded as unverified rather than silently passing.

Functional saves, approvals, a real evidence write/read chain, restricted-role sessions and configured scanners still require live acceptance. This update must not be labeled fully accepted until those checks and actual screenshots are complete.
