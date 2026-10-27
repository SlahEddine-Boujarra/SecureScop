# SecureScope v5.4.6 — Policy, Risk and Calendar workspace update

This source release builds on v5.4.5. Exposure Overview's rendering module and shared theme are unchanged. The sidebar adds Risk and Calendar and adjusts only workspace-switcher contrast. This is a Streamlit application, not a frontend framework migration.

## Upgrade

1. Stop SecureScope and its workers; back up PostgreSQL and your evidence directory.
2. Extract the new release into a separate directory. Preserve your host configuration, existing encryption key, evidence and runtime data. The archive intentionally excludes secrets, virtual environments, scan outputs and client records.
3. Use the supplied launcher to install/run this version. Migration `011_workspace_planning.sql` adds one client-scoped supporting-record table. Existing policies remain in Foundation versions; risk assessments remain in the canonical risk register.
4. Complete the existing controlled Administrator setup in Programme Foundation if no Administrator exists. Policy upload and risk editing require an active contributor membership. Workspace deletion and approval require Administrator membership.
5. Preserve `SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY`. It encrypts policy documents and original uploads; changing or losing it prevents decryption. See `POLICY_EXPERIENCE_HANDOFF.md` for initial key configuration and `PROGRAMME_FOUNDATION_HANDOFF.md` for controlled first-admin setup.

No production database was connected or modified during this work. Migration execution and visual review should be verified on your installation before replacing a production deployment.

## Implemented behavior

### Workspace deletion

Client Workspace → Delete this client workspace targets the active client. To delete another client, open that client first. Exactly two checkboxes confirm the target and permanent loss. Both are checked again by the server, alongside Administrator membership and the expected client ID. Active or queued scan/evidence jobs block deletion.

The client deletion and retained administrative audit event share a database transaction. Foreign-key cascades remove dependent database records. Local evidence beneath that client's numeric directory is removed after commit; a cleanup failure or unsafe symlink produces a visible host-action warning. External scanner systems and integration configuration are retained.

Session caches are cleared. Empty installations no longer silently recreate Default Client after deletion, and scanner lookups/asset data access no longer create a missing client. Explicit workspace creation remains available.

### Policies

- Upload and save draft now extracts and **persists** an encrypted policy immediately, then opens the saved document. Previously Extract created only transient session state, which looked like an upload failure because no saved policy appeared.
- Read-only users receive an explicit membership/setup explanation. Extraction, stale-version and encryption failures are shown instead of silently failing.
- Single DOCX/TXT/Markdown uploads retain encrypted original bytes. Bulk import previews the filenames and creates independent drafts, without replacing existing policies. Bulk imports report partial completion if a later document fails.
- The optional starter catalog creates missing entries from the requested 25-policy set. These are unfinished guidance documents, with suggested control mappings, purpose and annual cadence. They are not approved policy assertions or an ISO-prescribed document list. Existing matching titles are preserved.
- List views include All, Needs my approval, Needs approval and Needs reassignment, plus search and metadata filters, renewal dates, latest state, approver, approval completion and control count.
- Selecting a row opens a detail view with Back navigation. Current and historical approved versions remain available. The existing rich editor retains structured text and escaped rendering.
- Guided drafting edits actual document sections, previews the result and preserves untouched section formatting. Completion checkboxes record the analyst's own review, not automatic compliance verification.
- Review submission requires an assigned reviewer and date. Administrator approval applies only to a saved submitted version. Approval history remains versioned.
- Narrative comments, calendar notes, register descriptions and snapshot contents are encrypted with the existing host key; indexed identities and dates remain queryable.
- Threaded comments and links to existing client audit scopes are persistent and validate the policy/client/scope relationship.

### Risk

- New Risk navigation offers Overview, Risks, Risk library and Action tracker.
- The existing canonical register supplies assessment records. Named scenario registers organize those records through metadata; they do not duplicate assessments.
- Search and filters cover register, owner, review status, inherent level, category and approver. Selecting a row opens assessment, treatment, residual inputs and review details.
- Shared risk colors use the existing 1–5 likelihood/impact methodology. Blank scores remain Not assessed. Editing an assessment clears residual verification and invalidates approval of the prior revision.
- Human submission and approval are bound to the canonical revision. An Administrator cannot approve an outdated submission or silently modify submitted review metadata during approval.
- Library suggestions create explicit drafts and clear example measurements. Treatment tasks have owners, due dates and persisted status updates.
- Named registers support editing and deletion only when empty. The access dialog shows actual workspace grants and reuses existing membership administration. Permissions are inherited from the client workspace; no separate restrictive register ACL is claimed.
- Dated risk snapshots are stored; JSON and the existing charted assurance workbook are downloadable. Export generation does not create or approve an assessment.

### Calendar

- Client-scoped month/week views project policy renewals, risk reviews, treatment actions and planned audit dates.
- Queued Nuclei/OpenVAS jobs appear at their actual queue timestamp. This is not a scheduled execution promise, and this pass does not introduce a scan scheduler.
- Manual events have title, UTC date/time, type, notes and optional policy/risk/asset links. Links are checked against the current client.
- Clicking an event opens its detail; Open source record routes to the policy, risk, asset or scan destination. Audit events route to Control Assurance.

## Implementation locations

| Area | Files |
| --- | --- |
| Delete controls and server checks | `ui/workspace_deletion.py`, `persistence/workspace_deletion.py` |
| Startup and stale-job behavior | `app.py`, `persistence/db_service.py`, Nuclei/OpenVAS persistence `_client_id()` |
| Policy creation and catalog | `policies/repository.py`, `policies/catalog.py` |
| Guided section edits | `policies/builder.py`, `ui/policy_workspace.py` |
| Discussion/audit links | `ui/policy_collaboration.py`, `persistence/workspace_planning.py` |
| Risk workspace | `ui/risk_workspace.py`, `ui/components/risk_score.py`, canonical risk repository authorization hook |
| Calendar | `ui/calendar_workspace.py`, `persistence/calendar_repository.py` |
| Navigation/contrast | `ui/navigation.py`, `ui/securescope_sidebar.py`, `ui/styles/sidebar.css` |
| Supporting schema | `database/migrations/011_workspace_planning.sql` |

## Validation and practical limits

Focused tests exercise encrypted TXT/Markdown/DOCX creation, the Upload button and saved-detail routing, section editing, client deletion authorization and both confirmations, active-job blocking, scoped cleanup, stale risk approval, foreign-client links, new route rendering, calendar event selection, and existing policy/Foundation/scanner behavior. Validation: 86 focused tests passed; 18 dependency deprecation warnings.

Source compilation succeeded. Exposure Overview and its shared theme were compared directly with v5.4.5 and are unchanged. A source-only patch is supplied against that exact release, including a machine-readable changed-file list.

This environment has no live PostgreSQL connection and cannot verify the Windows deployment or browser-rendered layout. Native Streamlit interaction tests do not execute the custom editor's browser JavaScript. The supplied Vanta references guided structure; pixel-level fidelity is not claimed.

The builder uses text sections and human completion checks, not a full framework-specific questionnaire engine. Register permissions inherit workspace membership. Related vendor/open-issue/enterprise-risk graph relationships and a separate scan scheduler are not introduced by this pass. These require integration with their canonical ownership and access models rather than decorative links.
