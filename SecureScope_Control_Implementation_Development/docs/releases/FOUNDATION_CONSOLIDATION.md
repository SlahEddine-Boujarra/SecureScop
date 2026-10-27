# Programme Foundation consolidation

This development update extends the existing SecureScope build at source commit
`9875896`. It retains Streamlit, PostgreSQL, the canonical risk register, Control
Profiles, and the existing scope-version editor. No data migration or new model
is introduced by this update.

## Architecture decisions

| Feature | Decision | Result |
| --- | --- | --- |
| Foundation navigation | FIX | One segmented section selector replaces the Workspace area → Formal records hierarchy; existing section keys remain valid. |
| Context register | KEEP / MERGE | One compact register; its existing climate determination workflow opens separately. |
| Interested Parties | KEEP / MERGE | One register; selected-party requirements open through the row's workflow action. |
| Discovery suggestions | KEEP / FIX | Human-reviewed suggestions use the existing formal repositories. Retried matching suggestions reuse the same record under an engagement lock. |
| Scope Composer | LINK / FIX | Prepares the existing editor for the current scope. Preparation itself does not save another record. |
| ISMS Scope | KEEP / FIX | Separate Edit scope, Version history, and Review / approval actions. Existing editor and approval service are reused. |
| Scope review | FIX | Submitting for review checks membership, tenant, engagement, scope, and latest draft version; records an audit event. |
| Objectives | MERGE | Compact list and on-demand editor; saved-register review, approval and version history open separately. No second always-visible editor. |
| Roles & RACI | KEEP | Compact ISMS responsibility register remains in Foundation. |
| Workspace membership | MOVE | Application permissions are managed in Client Workspace, separate from ISO responsibilities. Existing access-role enums remain unchanged. |
| Engagement team | MOVE | Delivery roles are displayed in Engagement with milestones and cycle administration. |
| Foundation Risk assessment | REMOVE FROM UI / LINK | Canonical risk counts and a working Open Risk Management action replace the duplicate editor. |
| Foundation Policy | REMOVE FROM UI / LINK | Scoped policy metadata and Open Policies replace the embedded policy manager. |
| Foundation Overview | MERGE / LINK | Foundation records and linked modules are displayed in separate groups. Failed reads show an error rather than zero readiness. |
| Control Assurance treatment | REMOVE FROM UI / LINK | Related canonical treatments replace the independent plan-creation form. Historical plans remain read-only and their stored data is untouched. |
| Assess Control risk basis | FIX / LINK | A multi-select displays canonical R-number and scenario labels. Selected references are validated against the current client in the target write transaction. |
| Risk lifecycle | KEEP | Existing assessment, treatment, residual assessment, risk decisions and review workflows remain authoritative. |
| Matrix navigation | FIX | Aggregate Matrix View appears only in Registers & assessment and Residual assessment. Individual risk comparison remains available. |
| Product implementation status | REMOVE FROM UI | Removed from the normal Risk page; the diagnostics component and roadmap documentation remain in the source. |
| Empty tables | FIX | Empty Foundation and risk tables have no Previous/Next controls. |
| Component loading state | FIX | Foundation events receive success/error nonce acknowledgments, including read-only errors. Dialog requests are queued before rerender. |

## Data and compatibility

- No existing table, row, ID, version, approval or audit entry is deleted.
- Historical treatment plans are not automatically converted into canonical risk
  decisions. Their references may be ambiguous; reconcile them explicitly before
  reusing a decision. The archive displays stored plan fields and milestone counts;
  underlying milestone records remain in PostgreSQL.
- New control targets store validated `R-n` references in the existing `risk_basis`
  field. This is compatible with the current model, not a new foreign-key table.
  Historical free-text risk bases are preserved and not automatically interpreted.
- Scope exclusions and their justification remain in the existing scope text field;
  this update does not create a second structured exclusion register.
- Scope metadata displays existing values. A missing owner remains unassigned;
  the preparer is not silently treated as the accountable owner.
- The UI's scope review path uses Draft → Under review → Approved. The existing
  approval service retains its previously supported transitions for older callers.
- Policy readiness uses the selected engagement/scope. Canonical risks remain
  client-wide, and that limitation is stated on the Foundation summary. Preserving
  selected scope during navigation does not imply scope filtering of risk records.
- Membership roles remain Administrator, Consultant, Client contributor and Auditor.
  No access-control role migration was performed.

## Verification

- Full Python suite: **502 passed, 4 skipped**, with two dependency warnings,
  on Python 3.12.14.
- Frontend DOM suite: **26 passed**.
- Black, isort, flake8 and compilation checks passed.
- Python 3.11 grammar compatibility checked across source and test modules.
- New interaction checks cover scope editor routing, selected-scope history,
  acknowledged read-only failures, objective review using the saved revision,
  context-preserving Risk navigation, canonical risk-reference validation,
  stale scope-review rejection and idempotent Discovery retries.
- Frontend checks cover distinct scope actions, visible boundaries, loading-state
  release, empty pagination and lifecycle-appropriate Matrix View visibility.

The four skipped tests require `SECURESCOPE_TEST_DATABASE_URL`. This build has not
been exercised against a live PostgreSQL instance, in the user's Windows runtime,
or visually in a real browser. DOM checks and mocked Streamlit/repository tests
are not substitutes for those checks. Python 3.11 grammar validation is not a full
Python 3.11 runtime test. This is a development build, not a production sign-off.

## Installation and focused acceptance checks

Use the same installation and configuration as the preceding development package.
Retain the existing database, `.env`, and installation encryption key. This update
adds no dependencies or migration beyond the migrations already in the package
(including migration 013 from the previous risk lifecycle update).

1. In Foundation, verify one register is visible for each formal section.
2. In Scope, open Edit scope, cancel, open Version history, and confirm the same
   client/engagement/scope remains selected. Save a new draft, submit and approve
   with the appropriate test identities. Verify the audit and version records.
3. In Discovery, prepare a scope twice without saving: no new scope version should
   be written. Review an existing suggestion: it must not create a duplicate.
4. Save an objective, review the saved version and inspect its history.
5. Open Risk Management and Policies from Foundation and confirm the selected
   client/engagement/scope is unchanged.
6. Verify membership management in Client Workspace and delivery roles in Engagement.
7. Inspect canonical treatments in Control Assurance and historical plans in the
   archive. Confirm new treatment decisions are edited in Risk Management.
8. Approve a control target with selected risk references and verify its saved basis.
9. Check the layout at desktop and narrow widths, including long scope values.

## Still outside this update

Formal risk-owner acceptance, dedicated residual verification/sign-off, automated
monitoring, configurable versioned methodology/appetite, and complete cross-module
scope filtering remain unfinished. Their existing Coming Soon notices remain.
There is no automatic legacy treatment-plan reconciliation, historical free-text
risk-link conversion, or claim of ISO certification readiness.
