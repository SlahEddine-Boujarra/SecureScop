# Current update: fix ui/ux desgin

The four-page update supersedes the checkpoint below. See `FIX_UI_UX_DESGIN.md` for changes, verification and limitations.

---

# Visual correction checkpoint — 1 October 2026

The previous four-page adaptation was rejected as visually too far from the supplied Stitch references. This checkpoint corrects **Project Plan only**. Assurance Dashboard, Assess Control and Statement of Applicability still require the deeper visual correction; the earlier report below is historical, not a claim that those pages now match.

Project Plan now uses an isolated Components v2 HTML/CSS presentation based on the supplied `code(20260930-223345).html` / screenshot. It provides four metric cards, a separate search/filter toolbar, pale table header, wrapped owner names, status pills, client-side pagination and row-level Edit actions. Desktop and mobile screenshots are in `validation/assurance_redesign/`.

Existing Python task calculations, fixed task catalogue, revision-bound editing, workspace isolation and batch scheduling remain authoritative. No arbitrary task-creation button or invented sprint metrics were added. The page still uses the existing native task and batch forms after a navigation action. The full application shell is unchanged. This is not pixel-identical implementation of all supplied screens.

Validation: 39 focused Python tests and three frontend DOM tests pass. Local browser fixtures render at 1440, 1280 and 390 pixels without reported exceptions. Browser actions verify that Edit task 2 opens its correct resource and Plan in one pass opens the existing planner. Fixtures use synthetic data and do not test production database writes.

---

## Previous delivery record

# Control Assurance redesign

## Delivered scope

Adapted the supplied Stitch exports for Assurance Dashboard, Project Plan, Assess Control and Statement of Applicability. The two Project Plan exports are treated as variants of one page. Kept the existing module navigation, context ownership, permissions, canonical repositories and workflow transitions.

This is an adaptation to existing Streamlit components, not a pixel-for-pixel replacement with the static HTML. Native editable grids remain native. The uploaded sidebar reorganization, illustrative client data, hardcoded counts, unsupported task creation, recurring review automation and new assessment status vocabulary were not imported.

## Changes

- Shared, responsive summary cards and a scoped assurance stylesheet use the existing teal, navy and neutral tokens. Tab surfaces, headings and detail panels follow the reference hierarchy.
- Dashboard: existing calculated counts; attention rows include useful explanations; main filters remain visible; optional result filters are secondary; area breakdown precedes the detailed results. No mockup blank spacer, fabricated priorities or certification claims.
- Project Plan: saved task register is visible by default, with search, owner/status filters and CSV export. Existing single-task correction and batch planning are reached via clear plan actions. Date calculation, summary-task handling, revision conflict checks and persistence are unchanged. All new widgets preserve the active project tab on rerun. No unsupported Add Implementation Task button was added.
- Assess Control: aligned draft action, current owner/target summary, scoped implementation/evidence/assurance summaries when available, explicit blocked-target feedback, clearer evidence and conclusion sections, and paired draft/completion actions. The existing four stages, six assurance dimensions and save/finalization handlers remain.
- SoA: summary metrics are derived from the scope-owned saved working rows. The existing complete editor is extracted into the existing SoA UI module for reuse and verification; editor identity, columns, permissions and returned records are retained. The editor is deliberately not filtered in a way that could remove hidden rows from a version save. Counts describe saved rows, not unsaved grid edits. No hardcoded 93-control count.

## Validation

- Full Python suite: 642 passed, 4 skipped. The skipped tests require SECURESCOPE_TEST_DATABASE_URL.
- Focused regression suite: 47 passed, covering existing project save/rerun, cross-workspace isolation and stale revision rejection, plus new summary escaping, filter/editor record retention and SoA scope-key preservation.
- Compile, focused fatal-error lint and whitespace checks passed.
- Browser fixtures: 4 screen families at 1440, 1280 and 390px; 12 checks with no recorded JavaScript errors or Streamlit exceptions. Top and lower-page screenshots are included under validation/assurance_redesign. Narrow screens stack cards and retain bounded scrolling for wide editable grids.
- Project/assessment/dashboard previews use production renderers with synthetic data and mocked repository reads. The SoA preview exercises the production working-register component, not a live approval submission. Visuals are not evidence of live database or scanner integration success.

## Remaining live checks

Run against the authorized deployment to verify real client/engagement/scope selection, task persistence, assessment draft/finalization and SoA version creation using its configured database and identities. No production database write, schema migration, scan execution or live approval was performed in this pass.

## Files

Production changes are confined to the existing assurance UI renderers, shared presentation helpers, a scoped stylesheet and the existing SoA UI module. Tests and preview scripts document the adaptation. The original application architecture and risk calculations remain unchanged.
