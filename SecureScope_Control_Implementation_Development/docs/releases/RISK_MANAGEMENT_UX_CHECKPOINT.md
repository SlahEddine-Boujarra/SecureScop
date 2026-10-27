# SecureScope risk management and assurance UX checkpoint

Development checkpoint, 17 September 2026. Base: Python 3.11 repaired 5.4.9.dev0
source, plus the recovered Assurance UI patch. This is a full source package.
This note supersedes the older patch-only handoff in
`docs/remediation/ASSURANCE_UI_CONTINUATION.md`.

The administrator launch-code sign-in shown in the supplied screenshots matches
this source. That working local access path is preserved. It does not mean the
full authentication/security remediation phase is complete.

## Included changes

- Risk Management now groups registers/assessment, treatment, residual assessment,
  acceptance, monitoring/review and methodology. Existing authorized repositories,
  client isolation checks, revision checks and review transitions remain in use.
- Add Risk Register is visible in Risk Management and the Foundation risk view.
  Administrators can name and save a register; it opens after saving. New scenarios
  created there inherit that register. Existing risks are not automatically moved.
- Risk tables show six principal columns with readable spacing and stage-specific
  fields. Narrow screens scroll horizontally rather than splitting words into tiny
  columns. Scenario details and Foundation full-value drawers retain other fields.
- Assess Control uses a guided, grouped editor. A top Save draft button persists
  the current form; Review & save retains draft and final assessment actions.
  Draft saving does not change assessment approval or claim implementation.
- Control Profiles retain the table behind an editable right-side drawer, with
  grouped fields, long-value handling, close/focus behavior and unsaved-change
  protection. Writes use the current client, server actor and opened version.
- Organization-specific control name and implementation description are editable
  and versioned with profile scope metadata. Catalog identity and reference text
  remain separate. The table uses the local name when supplied.
- Implementation status, measured values and assurance scores are displayed from
  saved assessment data. Use Assess this control to change conclusions/evidence;
  missing results are shown as Not assessed. There is no invented maturity score.
- Visible Save actions remain in the document/register editors. Ctrl+Enter may
  commit a text widget's value in Streamlit; it is not the sole persistence action.
- Incomplete phases have explicit availability labels in the sidebar and risk area.
  No new database migration is required by these UI changes.

## Reference versus organization-specific data

| Information | Editing path |
|---|---|
| Catalog control ID, reference name and guidance | Fixed reference |
| Local control name and implementation description | Control Profiles drawer |
| Owners, scope, methods, evidence requirements, automation/model | Control Profiles drawer; creates a version |
| Approved target and acceptance criteria | Existing target approval workflow |
| Current state, implementation conclusion, measurements, evidence and verification | Assess Control; existing assessment workflow |

## Honest delivery status

Statuses describe the whole phase; existing partial features remain available.
Coming Soon is not a delivery-date commitment or a certification claim.

| Phase | Status | Outstanding work |
|---|---|---|
| 0 Build and quality | Coming Soon | Hosted CI and live database verification; 60% coverage floor deferred by user |
| 1 Security | Not Implemented | Complete identity/MFA/API authorization/database-isolation remediation |
| 2 ISO workflows | Coming Soon | Configurable versioned methodology, formal scenario acceptance, remaining specialist workflows |
| 3 Architecture and data | Not Implemented | Planned data-model, restructuring and deployment work |
| 4 UX | Coming Soon | Full portal, localization and accessibility work |
| 5 Validation | Coming Soon | Complete live database, security, visual browser and accessibility gates |

The acceptance view is explicitly a preview of proposed Accept treatments.
An Approved assessment is not formal risk-owner acceptance. The formal acceptance
button is disabled and marked Coming Soon. Residual estimates remain estimates;
a dedicated verification/sign-off workflow is outstanding. Review dates/history
exist; automated reminder campaigns are outstanding. Methodology configuration
is disabled and marked Coming Soon. Current 1–5 scoring is an application default,
not an ISO-prescribed scoring scale.

The lifecycle organization is informed by the official ISO/IEC 27005 overview:
https://www.iso.org/standard/80585.html. The UI is a workflow aid, not a claim that
a client is certified or that every ISO requirement is implemented.

## Validation and limitations

Validation was performed using Python 3.11.16. See `validation/` in this package
for the exact local test outputs. Tests use isolated service fixtures; they do not
substitute for a live PostgreSQL integration run.

- Python suite: 432 passed, 7 skipped. Four tests need the test database; three
  tokenizer-specific checks require Python 3.12. Two dependency deprecation warnings.
- Frontend: 17 passing Node/DOM test entries, including drawer interactions,
  six-column risk views and preventing misleading acceptance labels.
- Python compilation, Black, isort, flake8 and dependency consistency checked.
- Browser visual verification and live PostgreSQL are not completed. Previous
  browser access to the local preview was blocked. Do not interpret DOM tests as
  a visual pass.
- Scanner integrations and external services were not exercised live.
- The existing security limitations remain; this is a development checkpoint,
  not a production-readiness claim. The waived coverage gate remains visible in CI.

## Use

Extract into a separate directory, retain a backup of the working installation and
database, and use the existing Python 3.11 setup/launch instructions in the project.
Install its requirements into the same environment used by the launcher. Supply
local connection configuration separately; no credentials or database are bundled.
Validate against a test database before adopting it for a client installation.

The source includes the prior profile/assessment/drawer changes as well as this
risk continuation. `scripts/preview_assurance_ux.py` provides a synthetic UI preview;
its data are examples, not client records. Review this note before using the older
patch-only handoff, whose request for a newer account ZIP is superseded.
