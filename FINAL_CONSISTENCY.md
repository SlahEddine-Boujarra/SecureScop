# SecureScope final consistency pass

This update extends the existing architecture. Programme Foundation retains its seven-section navigation and Governance grouping. Risk Management remains the canonical risk lifecycle; Policies remains the policy owner; Control Assurance keeps implementation, evidence, applicability and SoA responsibilities.

## Changes

- All eight Foundation Overview blocks use one card renderer with consistent spacing, metrics, status badges and actions. Scope displays its controlled version and boundary counts.
- Linked-module summaries use canonical records. Clause 6.1.3 shows treatment and control/SoA ownership separately.
- Scope submission, review and approval have distinct rationale fields, confirmations and actions. Existing server transitions and immutable approved versions remain in force.
- Composer explains whether to prepare, update or open a scope. Unchanged content returns the existing version; preserve/replace choices default to preserving formal content.
- Related treatments and control target risk choices default to the selected ISMS Scope. Treatment navigation preserves client, engagement and scope and resets stale all-client filters.
- Related treatments remain read-only, with clickable risk references and individual control tags. Historical treatment plans use readable audit cards; technical JSON is restricted to a collapsed Administrator view.
- Manual Interested Party forms use grouped fields. Structured Discovery requirement persistence is unchanged.
- Shared display labels, administration copy, neutral workflow copy and operation-specific feedback improve consistency.
- The seven-step Risk Scenario editor and matrix calculations are retained. Timescale without a due/review date produces a non-blocking notice. Blank progress with Not Started displays 0% without changing the stored null.

## SoA ownership and historical data

No second SoA model or new migration is introduced. Scope ownership uses the existing engagement-record association table from migration 005. New scoped versions and their association are written in one transaction. Scope-specific reads do not borrow another scope's SoA.

Legacy migration-backfilled associations are preserved but are not treated as confirmed scope ownership. Those versions remain accessible as legacy/unassigned. An Administrator can explicitly assign a version to the selected engagement/scope with a rationale; the operation validates tenant/context, locks the version, preserves existing items and legacy links, and writes an audit event. Existing explicitly assigned versions cannot be reassigned through this action. Version numbers retain their existing client-wide sequence.

The existing migration chain, including migration 014, is still required. This update does not run migrations against your installation or change your live records.

## Legacy UI isolation

Call-site inspection found the older Context, Interested Party, Scope, Roles and generic formal-register render paths were excluded by the current compact-record router. Their dead router branches/imports were removed. Compatibility functions are explicitly named legacy_* and labelled as excluded from the active router, reducing the risk of reconnecting duplicate workflows. Active engagement and climate helpers remain.

## Validation

- Python suite: 539 passed, 4 skipped.
- Browser-component DOM suite: 31 passed.
- Changed Python files: Black, isort and Flake8 checks passed.
- Python 3.11 syntax compatibility and diff whitespace checks passed.
- Added regression coverage for shared cards and scope metrics, distinct scope decisions, scope-filtered treatments and risk choices, navigation filter reset, scoped SoA reads/writes, safe legacy assignment and no-op scope saves.
- Existing scope state-machine, Discovery requirement, risk calculation, matrix and permission coverage remains passing.

Four PostgreSQL integration tests were skipped because SECURESCOPE_TEST_DATABASE_URL was not configured. Live database migration/persistence and full browser visual checks were not performed. The automated results are not a claim that the running localhost installation has been updated.

Formal Risk Acceptance and configurable Methodology remain explicitly unavailable/planned.
