# SecureScope v5.3.8.2 — Experience Foundation

## Outcome

This UI-only release turns the v5.3.8 GRC foundation into a record-first ISO
27001 working experience. It does not change the PostgreSQL schema, published
migrations, scanners, workers, evidence collectors, or approval rules.

## Added

- Direct **ISO Command Center**, **Programme Setup**, and **Evidence Hub** routes.
- Persistent client → engagement → scope context bar.
- Conservative eight-item programme-foundation progress calculation.
- Five explicit progress dimensions; unscoped dimensions remain unmeasured.
- Clickable attention queue routing to the resolving setup section.
- Lazy section service that queries only the selected Programme Setup register.
- Reusable context, progress, attention, status, and register components.
- Ten on-demand action dialogs.
- Dedicated six-step scope-version editor.
- Responsive 1366×768-oriented programme styling.

## Changed

- GRC Workspace is no longer nested inside Gap Assessment.
- Evidence Hub is no longer nested inside the control-assessment form.
- Gap Assessment now focuses on Control profiles, Assess control, Gap actions,
  Statement of Applicability, and Risk Treatment Plan.
- Client Workspace selection opens the ISO Command Center.
- Sidebar groups now separate ISO programme work from Security Operations.

## Assurance rules

- The percentage is programme-foundation completion, not a compliance score.
- Scanner results never complete a foundation item or certify a control.
- Risk, controls, evidence, and audit-readiness dimensions are not counted until
  they can be filtered by the active engagement and scope.
- Approved scope versions remain immutable and approval remains human-only.

## Compatibility

- No migration was added.
- Migrations 001–005 are byte-identical to v5.3.8.1.
- Scanner modules are byte-identical to v5.3.8.1.
- `render_grc_workspace()` remains as a compatibility façade.
