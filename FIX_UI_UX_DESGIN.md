# fix ui/ux desgin

This update covers Project Plan, Assurance Dashboard, Assess Control, Statement of Applicability and their shared navigation bar.

## What changed

- **Project Plan:** removed the bottom View plan / Edit a task / Plan in one pass selector. Table Edit actions open an Edit Project Task dialog with the existing task fields, Save Changes, Cancel and stale-revision checks. Batch planning stays in the top toolbar. Removed the repeated scheduling note.
- **Navigation:** pale rounded bar, icon/label spacing, white active tab and teal text. Supports the current Streamlit React Aria tab markup and removes the old underline indicator.
- **Dashboard:** isolated HTML/CSS cards, coverage summary, attention filters, ISO area breakdown and a paginated results table. Existing scope-aware evaluations and canonical control navigation remain authoritative.
- **Assess Control:** three visible sections for implementation/coverage, evidence/assurance and conclusion/recommendation. Header and bottom save/submit actions use the same existing draft and assessment services. Reference details and history remain optional expansions. All six assurance dimensions and existing criterion/effectiveness-test fields remain available.
- **SoA:** metric cards, search, filters, status chips and row-edit dialogs. Filtering is presentation-only; the snapshot action still receives the full working register. Working-row edits do not change historical versions. Scope-specific state resets when the canonical source changes.

## References and preserved behavior

Presentation follows the supplied September 30 Stitch HTML/CSS and screenshots, with the latest Project Plan reference preferred. Existing canonical field names, status choices, authorization and supported operations take precedence over illustrative mockup data. No new control model, risk workflow, scheduling calculation, database or persistence service was introduced.

The existing Streamlit shell and native validated editing controls are retained. This is an implementation of the supplied page structure and visual styling, not a pixel-identical copy of every mockup element. Unsupported mockup operations, such as arbitrary project task creation and recurring assessment cadence, were not invented.

## Verification

- Python regression suite: **642 passed, 4 skipped**. The skipped tests require an explicitly configured test PostgreSQL database.
- Frontend DOM suite: **46 passed**.
- Browser rendering: all four pages at **1440, 1280 and 390 pixels**, without reported page exceptions or JavaScript errors.
- Browser interactions: correct task loaded into Edit dialog; Cancel closes it; batch planning opens; SoA row edits update the working register; filtering and resetting retain all rows.
- Focused lint checks and `git diff --check` passed.
- Browser fixtures use synthetic records. Production database writes, scanners and external integrations were not exercised.

## Visual evidence

Screenshots are under `validation/assurance_redesign/`:

- `project-plan-full.png`
- `project-task-dialog.png`
- `assurance-full.png`
- `assess-control-full.png`
- `soa-full.png`

Viewport-specific screenshots and the browser-results JSON are included alongside them. Regression output is in `validation/fix-ui-ux-tests.txt` and `validation/fix-ui-ux-dom.txt`.


## October 1 continuation — Control Workspace and Assess Control

Implemented the two new supplied October 1 HTML/screenshot references in the existing pages.

- Control detail now uses a four-column summary strip, header configuration/requirement actions, a visible gap summary, teal section navigation, grouped requirements and a next-action card. Configuration dispatch opens the existing versioned profile dialog and retains authorization.
- Assessment uses requirement guidance cards, linked-proof cards, three visible numbered sections, effectiveness choices, evaluator rationale, confidence and sign-off. Existing scope/owner inputs, six independent dimensions, criterion results, optional tests, gap fields and historical assessments remain available.
- Draft saves and final submissions still use their existing repositories, optimistic revision checks and evidence/role guards. Confidence uses the already-supported Low/Medium/High field. No automatic save, automatic verification or unsupported export is claimed.
- Removed obsolete assessment tab CSS after checking call sites. New control-detail styles are isolated from Policies/Risk Management; native form styles are scoped to assessment containers. Existing global styles used elsewhere were preserved.
- Responsive browser checks: 1440, 1280 and 390 pixels; no browser/page exceptions. Screenshots in validation/assurance_redesign use synthetic records, not a live tenant.
- Verification: 642 Python tests passed, 4 database tests skipped (no test database configured); 47 frontend tests passed. Additional action regression verifies effectiveness choice mapping and confidence reaching the canonical assessment service.

This update adapts the reference designs to the existing Streamlit shell and canonical fields. It does not redesign every application page or claim live-database validation.


## October 1 evening — Compact assessment and consistency corrections

Latest reference: screen(20261001-210236).png and its HTML, plus the annotated table/navigation screenshots.

- Replaced the large three-step assessment presentation with SecureScope assessment, Needs your attention, Your assessment, Conclusion, Requirements & Evidence Details and Advanced Details & Dimensions. Primary implementation/effectiveness choices map to existing canonical status values. Existing drafts, criteria, evidence eligibility, target and validation checks remain in use.
- Removed the Control Assurance New assessment button. Retained Save Draft and the existing completion action.
- Moved native section-bar styling into the shared stylesheet. Programme Foundation, Governance, Risk lifecycle, native module tabs and the shared custom section bars use the Control Assurance treatment.
- Removed Type from the Control Profiles table; retained its useful filter. Removed the old 210px assurance-column rule, tightened columns and introduced semantic status badges.
- Fixed sidebar workspace-switch text/background rules including nested Markdown visibility. Browser verification checks the actual text and successful dialog callback.
- Traced SoA behavior: Apply Changes edits an unsaved working register; assurance reads the latest approved version in the selected scope. Scope-specific pending edits now appear as explicit draft applicability in Control Profiles, with dashboard/SoA guidance about publication. Formal assurance counts are intentionally not changed by unsaved or unapproved exclusions. Publishing a version resets the working baseline. This does not add a second persistence implementation or relax approval rules.

Validation: 644 Python tests passed; 4 database integration tests skipped because no test database was configured. 48 frontend tests passed. Desktop/mobile previews cover 1440, 1280 and 390px; separate browser assertions verify Programme Foundation bar styling and the client-switch callback. Synthetic records are used for previews. No live tenant database migration or validation was performed.

Restart Streamlit after replacing the project so registered custom components load the updated JavaScript and CSS.

## October 2 — app-wide consistency and accessibility

This correction supersedes the earlier pale rounded section-bar styling: Control Assurance's white-surface icon/label tabs are now the shared navigation treatment. Conflicting legacy tab rules and dark-sidebar overrides were removed. Foundation forms/workbench shells and identity displays reuse existing components. Architecture, domain fields, persistence, calculations and methodological disclaimers remain unchanged.

**Live verification completed after resolving the initial sandbox limitation through approved non-root execution.** Fresh PostgreSQL applied all 14 migrations. The real app was verified through normal local sign-in, with desktop screenshots, a visual navigation comparison and computed sidebar text-fill checks. Python: 654 passed including the database tests; frontend DOM: 48 passed. See `validation/consistency_live/REVIEW.md` for evidence, coverage limits and the two unchanged flag-only methodology findings. Older synthetic screenshots remain historical evidence only.
