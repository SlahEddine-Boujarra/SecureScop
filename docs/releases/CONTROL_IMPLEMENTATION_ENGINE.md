# Control Implementation Engine — development checkpoint

This full-source package builds on SecureScope_Risk_Management_Development.zip.
It extends existing Control Profiles, assessments, documents and audit history;
it creates no duplicate control model and requires no new database tables.

## Included

- Evidence-based implementation results with a visible explanation for each gate.
- Required observable criteria and policy/procedure links saved in existing profile
  versions, with document versions and approved scope identity pinned.
- Evidence age, expiration, validation, criterion coverage and manual effectiveness
  tests checked before a positive result. Missing evidence does not prove failure.
- Current Evidence Hub records and approved control mappings checked for linked
  `Evidence #ID` references. Unrelated or revoked references cannot support a pass.
- Changed targets/scopes, omitted criteria and retired validators trigger review.
- Explicit Save buttons with errors/success feedback, stale-preview rejection and
  current membership checks. The existing local sign-in now works through the shared
  evidence/assessment UI identity helper as well as environment-based identity.
- Complete evaluation inputs encrypted with the existing installation key and
  appended to the existing immutable evidence audit history. Historical results
  remain unchanged while the live evaluation reflects new inputs or evidence age.
- Configured profiles feed the live result into the existing GAP dashboard engine.
  Legacy profiles retain their prior assessment logic until requirements are configured;
  the separate Implementation column shows Not Assessed for those profiles.

## Results

| Result | Meaning |
|---|---|
| Implemented | All configured implementation and operating-evidence gates pass |
| Partially Implemented | Validated evidence shows incomplete criteria, documents or operation |
| Not Implemented | All required implementation criteria have evidenced failures |
| Not Assessed | No assessment exists for this profile version |
| Verification Pending | Evidence/review is missing, stale or inconsistent, or relevant versions changed |
| Not Applicable | Approved justified Annex A SoA exclusion |

Approved documents alone do not establish implementation. The engine evaluates saved
records and human validation; it does not independently authenticate external document
contents or establish certification. Future verification scripts remain Coming Soon
and are not required for a complete manual evidence evaluation.

## Using it

1. Select the engagement and approve the ISMS scope in Programme Foundation.
2. Maintain policy/procedure documents in the existing Policy library and map them
   to the control. Assigning a document a Procedure role reuses its existing version
   and approval workflow; no parallel document store is introduced.
3. Open Control Assurance → Control Profiles → a row → **Implementation evidence**.
   The drawer closes and the evaluation panel opens below the retained table.
4. Open **Implementation requirements and document links**. Select the required
   documents, or explain why a separate policy/procedure is unnecessary. Declare
   observable criteria (one per line) and a review interval. Confirm and save.
5. This creates a new profile version. Approve its target and use Assess Control to
   record evidence, all criteria, the six assurance dimensions and an effectiveness
   test. Declared criteria are prefilled in the assessment editor.
6. Criterion and test references must cite current assessment evidence. Exact
   references and semicolon-separated reference lists are supported.
7. Reopen Implementation evidence, review the checks and use **Save implementation
   evaluation** to record the result and its input snapshot.

The initial 90-day interval is configurable and is a product default, not an ISO rule.
Changing requirements creates a new profile version; old answers do not automatically
establish that new version's implementation. Changing linked documents does not silently
update the versions previously reviewed in the profile.

## Permissions and persistence

The service resolves the actor's active workspace role on each read/write. Consultant
or Administrator membership is required to configure requirements and record an
evaluation. Profile-version writes also enforce this role within their client lock.
A save reloads client-scoped source records, compares the preview fingerprint and
recomputes the result; it does not trust a browser-supplied status.

Requirements live in `assessment_scope.implementation_requirements` on the existing
profile. Evaluations reuse the evidence audit-event store and its append mechanism;
the full snapshot is encrypted. Preserve the existing installation encryption key.
This does not claim that the broader authentication/security phase is complete.

## Validation and limitations

Validation: **476 Python tests passed, 7 skipped; 18 frontend test entries passed.**
Python 3.11 compilation, formatting, lint and dependency checks also passed.

The package includes exact Python/frontend test outputs and quality checks under
`validation/engine-*.log`. Tests cover stale/invalid evidence, required criteria,
failed tests, changed versions, authorized writes, client scoping, encrypted history,
stale saves, visible feedback and local identity resolution.

Live PostgreSQL, Windows execution, browser visual verification and external scanner
integrations remain unverified here. The database-dependent tests remain skipped;
DOM checks are not a browser visual pass. The user-deferred 60% coverage floor remains
deferred; no coverage threshold completion is claimed.

Supporting-record reads currently add queries per configured control. Large client
portfolios require a live-database performance pass; batched loading and production
performance are not claimed verified by unit tests.

## Remaining master-prompt work

This is the Control Implementation Engine step, not completion of the entire master
roadmap. Configurable risk methodology, formal risk acceptance, audit execution and
findings, Gap → Required Document tasks, objectives expansion, vendor automation and
complete security remediation remain outstanding. The risk-context/register-selection
fixes and broader Scope propagation review also remain separate follow-up work.

Use a separate development installation and a backed-up test database with the
existing Python 3.11 setup instructions. No credentials or client database are included.
