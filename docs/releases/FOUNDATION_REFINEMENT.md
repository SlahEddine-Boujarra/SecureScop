# Foundation refinement — 18 September 2026

This extends the Foundation consolidation on commit bd40266. It preserves canonical Risk Management, existing Control Profiles, Scope versions and all historical records.

## Implemented

- Seven primary Foundation sections: Overview, Discovery, Context, Interested Parties, ISMS Scope, Governance and Engagement. Governance contains Roles & RACI and Objectives. Risk and Policy remain linked Overview summaries.
- Administrator setup/sign-in moved to Client Workspace. Foundation shows an access notice and administration link when necessary.
- Scope workflow now requires Draft → Submitted for Review → Reviewed → Approved. Submission and review identities, timestamps and rationales are persisted. Only the latest reviewed version can be approved. Approved versions retain the existing database immutability protection; later edits create drafts.
- Human-readable scope version register, selected-version content, field comparisons and optional Administrator-only technical audit details.
- Compact scope boundary summaries and metadata. Migration identities display as “System migration” without rewriting historical data. Add boundary reuses the unit/site dialog or the corresponding existing scope-editor step for technology, products/services and other boundaries.
- Composer preview preserves existing manual text and unions boundary lists by default. Replacing text or lists requires explicit selection. Exclusions and dependencies are not generated over existing values.
- Compact Discovery selection with Select all, Clear selection, selected counts, Suggested/Selected/Already recorded/Dismissed states and optional supporting details. Dismissals are session-only and labeled accordingly. Existing transactional duplicate protection and structured party requirements remain intact.
- Context categories now offer internal/external taxonomies and Other. Context and party editing uses the existing canonical tables, validates domain fields, checks current membership and record freshness, and records change/review rationale in the existing audit trail. Context can be closed; parties can be made inactive.
- Interested-party requirement counts and grouped drawer information; readable requirement details.
- Objectives support explicit historical-date confirmation, evidence inspection, edit, review, history and archive/restore in versioned records.
- Empty registers avoid empty tables and filter bars. Pagination controls are hidden for single-page Foundation, risk, policy and control-profile lists.
- Canonical risks have an optional Primary ISMS Scope. Existing risks remain unassigned. Current ISMS Scope, All client risks and Unassigned scope filters apply across risk lifecycle views. Foundation risk summaries use current scope, and their navigation carries that filter. Treatment actions inherit the scope of their parent risk; no second treatment-scope model was created.
- Risk messages identify the operation. Matrices retain existing 5×5 scoring and colors, add a legend, and expose owner/score/level in cell drilldown. New “Accepted risk” treatment statuses are rejected while legacy saved values remain preserved; assessment approval is not formal risk acceptance.

## Database upgrade

Use the existing migration runner / normal application startup to apply `014_scope_review_and_risk_scope.sql`. Back up the deployment database before upgrading. The migration adds nullable risk-scope links, scope review metadata, a composite tenant-safe foreign key and review-transition enforcement. It does not guess scope assignments or rewrite old approved versions.

Historical approved versions may have no explicit submission/review metadata; the history view reports those values as not recorded. No historical approval evidence is fabricated.

## Validation

See `validation/refinement-tests.log`, `validation/refinement-dom.log`, and `validation/refinement-static.log` for the packaged checks. Tests exercise navigation, permissions, stale decisions, composer preservation, scope filtering, transactional link callbacks, historical-date validation, empty states, pagination and DOM interactions.

Live PostgreSQL migration/transaction execution and full browser visual verification were not available in this environment. Unit transaction tests use mocked cursors; they do not substitute for running the migration on a staging database. Python 3.11 syntax is checked with the parser compatibility mode; execution uses the available Python 3.12 environment.

## Explicit remaining work

- Formal risk-owner acceptance, approved methodology configuration and residual verification remain Coming Soon in the existing UI. A completed assessment is not an acceptance decision.
- Combined treatment/control/SoA readiness aggregation is labeled Coming Soon on Overview. Current risk and policy summaries and links to authoritative modules remain available.
- Future scripted control verification remains planned. No verification results are invented from answers or scanner data.
- Discovery dismissal is not a persisted organization-wide decision; it lasts for the current session only.
- This is a development build pending live database and browser acceptance testing.
