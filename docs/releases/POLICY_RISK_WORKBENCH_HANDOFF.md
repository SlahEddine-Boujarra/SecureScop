# SecureScope v5.4.7 — Policy and risk workbenches

This update implements the core policy and scenario-detail interaction patterns from the supplied screenshots. It uses isolated JavaScript/CSS through the app's existing Streamlit Components v2 bridge. There is no React dependency or framework migration. The PostgreSQL repositories remain authoritative.

## What is connected

**Policies:** filterable library, click-through detail, four tabs, draft/approved cards, approval history, mapped controls, real audit links and threaded comments. The split builder places guidance and optional choices on the left and an editable formatted document on the right. Checked choices insert text; unchecking removes only unchanged matching suggestion paragraphs, preserving custom edits. Section navigation retains unsaved text. Saving writes a new encrypted draft version. Twenty-five distinct starter drafts are available through Add policy. Existing documents are not silently replaced.

The editor supports paragraphs, lists, headings imported from documents, and paragraph-level bold/italic controls. It is a structured editor, not an embedded Microsoft Word application. Word and PDF exports use the saved document; after generation, the download button appears below the workbench. The UI shows real assigned/approved counts. All assigned Administrators must approve before the policy becomes Approved. Editing an approved document creates a draft and resets its approvals.

**Risk:** register cards and menus, searchable/filterable/paginated scenario table, template/blank creation, JSON import preview and explicit commit. Clicking a scenario opens the inherent-risk, treatment/control/task, residual-risk, owner and approval cards. Likelihood and impact change scores immediately; saving uses the canonical risk register. Tasks, comments and review events are persisted. Approval checks both the assessment and supporting-metadata revisions and the assigned Administrator. Planned residual values remain explicitly unverified. Risk data export is JSON; existing assurance workbook exports remain available elsewhere.

Register access displays actual inherited workspace memberships. Change grants through Programme Foundation → Workspace access. Named-register deletion requires confirmation and refuses nonempty registers. This does not change the separately guarded client-workspace deletion feature from v5.4.6.

## Installation

1. Stop the existing Streamlit process. Back up PostgreSQL and retain the installation's original encryption key and configuration.
2. Extract the full build into a new directory; keep your configured environment and evidence storage paths. Alternatively, apply the change bundle only to v5.4.6.
3. Install the updated requirements using the same Python interpreter used to run SecureScope. `python-docx>=1.2,<2` is new.
4. Start using the existing Windows launcher. The normal migration runner applies `012_workbench_review_history.sql`, extending the supporting-record type constraint for comments and server-generated review history. No opportunity table is created.
5. Open Policies or Risk in the menu. If you have not created an Administrator, use Programme Foundation → Administrator setup / local sign-in with the host operator's setup code. This build does not bypass that setup.

## Deliberate limits / outstanding work

- This is the core redesign, not a verified pixel-identical Vanta reproduction. Browser visual review on the deployed app is still required.
- Enterprise-risk rollups, vendor/finding links and verified inventory relationships are not implemented. Impacted assets currently displays the existing descriptive asset field, clearly labeled as such.
- Risk registers inherit workspace access; there are no separate per-register grants. New scenarios and JSON imports start in Default; saved scenarios can be moved with Edit register and category.
- The original toolkit XLSX import/export path is separate from this JSON risk import. This pass does not claim to finish the remaining faithful pivot-table/template regeneration work.
- SOC 2/GDPR requirement guidance is not invented. The builder offers editable ISO-oriented general guidance and mapped control identifiers, not licensed standards text or a compliance determination.
- The custom workbenches do not yet expose all legacy native-screen functions, such as the previous action-tracker view or bulk policy upload. The legacy renderer functions remain in source for comparison and regression coverage.
- PostgreSQL was not configured in this execution environment. The migration and live database round trip have not been run here. No live client records were changed while preparing this build.

## Validation

Focused Python tests cover authorization, stale revisions, separate policy approvals, encrypted document persistence, Word round trips, forged review events, cross-risk replies, and Streamlit routing to the new components. JavaScript DOM tests exercise actual row selection, safe text rendering, suggestion insertion/removal, preservation of manual edits across sections and failed saves, score updates and read-only controls. These tests do not substitute for a browser visual check or live PostgreSQL test.

The change bundle contains replacement files and a unified patch against the delivered v5.4.6 archive. Exposure Overview's rendering module and the shared theme are checked byte-for-byte against that archive.
