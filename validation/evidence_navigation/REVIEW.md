# Evidence scope and navigation correction

## Implemented

- Manual Evidence and Import Reports pass the current engagement/scope to the existing evidence service.
- The existing creation transaction validates active scope ownership and submitter membership, then saves the evidence, scope association, control mappings and audit event together. A partial context is rejected. No database schema or assessment rule changes.
- Explicit association uses the same insert helper as the existing Control Profile “Link Existing Evidence to this Scope” workflow. Historical unassigned records remain untouched and available client-wide; they are not guessed into a scope.
- Manual submissions and consultant decisions use one-time session messages displayed after rerun.
- The Register's selection key includes its context/view/filters and ignores stale out-of-range row selection.
- Programme Foundation (including Discovery/Governance), Evidence and Risk navigation render existing content inside the selected native tab panel. Previously the tabs were empty and content was rendered beneath them, so changing the client-side tab left the previous content visible during rerun. Canonical state values and existing callbacks remain intact.

## Verified in this run

- Full Python suite: **661 passed, 4 skipped**, 76 dependency warnings.
- Added submission-context, authorization, scope rejection, unassigned compatibility, atomic transaction boundary, real Streamlit form and Register rendering tests. Database transport is mocked in these tests.
- Both Evidence Register modes rendered persisted-shaped records in Streamlit AppTest; the broader reported blank client-wide view was **not reproduced** here.
- AppTest confirms section content belongs to the correct native tab panel before/after programmatic navigation. This is not visual animation validation.
- Python compilation and git diff whitespace checks passed.

## Blocked / not yet accepted

Fresh PostgreSQL startup failed at the unprivileged-account ownership step (OS rejected chown). The execution environment's approval policy rejected escalation. Chromium also exited during launch. Therefore this run does **not** claim:

- live PostgreSQL migration/transaction verification;
- end-to-end verification of the four consuming surfaces with persisted evidence;
- confirmed resolution of the reported blank All Client Evidence screen;
- video/screenshot confirmation of flashing or vertical scrolling behavior.

The earlier `validation/consistency_live` artifacts belong to the previous UI pass and are not evidence for this correction.

## Required live gate

Run `python scripts/verify_evidence_scope_postgres.py` with `SECURESCOPE_TEST_DATABASE_URL` pointing to an **empty disposable PostgreSQL database**. It refuses a nonempty database and retains test data for UI inspection. This script was compiled but could not be executed here.

Then launch the real app against that database and verify:

1. Submit evidence in Scope A; success message appears once; scoped and client-wide Register show it.
2. Scope B excludes it. Unassigned historical evidence remains client-wide until explicitly associated.
3. Consultant validation updates accepted counters and exposes validated evidence to Control Assurance.
4. Map evidence to a configured requirement with an explicit conclusion and rationale; verify appropriate coverage changes. Evidence validation alone must not mark a control assessed or implemented.
5. Repeat Register view/filter changes and inspect console/server errors if the reported blank grid persists.
6. Record rapid and ordinary tab switches at desktop width, including when the page is scrolled. Verify old-content mismatch, opacity transitions, and scroll stability.

No historical data was migrated/deleted. No new control model, treatment workflow, or automatic compliance conclusion was added.
