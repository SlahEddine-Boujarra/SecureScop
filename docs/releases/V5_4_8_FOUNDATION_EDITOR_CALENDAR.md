# SecureScope v5.4.8 — Foundation, document editing and client planning

## Changes

- New risks created from blank or template within a named register retain that register. Canonical assessment and register placement are committed together. JSON imports retain the register selected at upload and still require preview/confirmation. Invalid or deleted registers block the write instead of silently falling back to Default.
- Impacted assets has a searchable, selectable table from the active client's saved discovery inventory. Unsaved scan previews are not treated as inventory. Asset IDs are checked against the client before saving; links also retain client/IP identities because the existing inventory refresh replaces numeric IDs. Missing assets are labeled and their prior links retained. IP reuse is not proof that the same physical device remains present; consultants should review inventory changes.
- Policies have a continuous document surface with a compact toolbar, selected-text bold/italic, heading/list formatting, undo/redo, editable headings, visible unsaved state and collapsible suggestions. Draft document labels and card alignment are improved. This is a structured rich-text editor with DOCX export, not embedded Microsoft Word or an AI rewriting service. Existing version and approval guards remain.
- Calendar now has clickable month tiles and a day panel. Add creates an activity with client, UTC time, type and notes; saved manual activities can be edited. Client choices and displayed events are limited to active workspace memberships. Open client workspace calls the application's existing context-switch function. No email invitations are sent.
- Programme Foundation uses the supplied Stitch design patterns: compact filterable tables, scope cards, objective summary cards and right-side detail panels. Objectives can be added/edited in a dialog and saved as versioned drafts. Context/party/unit/RACI creation reuses the existing dialogs. Original approval, climate, party-requirement and version tools remain in an expandable section to preserve functionality. Existing engagement/overview flows and the main navigation are unchanged.

Only source-backed fields and counts are shown. The design's sample organizations, people, impact ratings and objective completion percentages are not inserted as client data. This pass does not add a new cross-register traceability model.

## Existing risks already in Default

Open each affected scenario, choose **Edit register and category**, select its intended register and save. The update fixes future placement; it does not guess where previously misfiled records belong.

## Install

Stop SecureScope, back up PostgreSQL, and preserve your configuration and original encryption key. Extract the full v5.4.8 build or apply the change bundle to v5.4.7. Install requirements using the same Python interpreter as your launcher, then restart normally. This update introduces no database migration and no new Python dependency beyond v5.4.7.

If no Administrator exists, complete the existing host-controlled Administrator setup in Programme Foundation. Role checks are not bypassed by this release.

## Verification and limits

Focused Python tests exercise register placement, stale link revisions, ownership validation, existing review/version guards and routing. DOM tests exercise the actual component's selection, edits, undo/redo, asset picker, calendar day panel and Foundation drawers.

No live PostgreSQL connection is configured in the build environment. The local preview server starts, but the remote browser reports `ERR_BLOCKED_BY_CLIENT`; therefore no deployed browser visual pass or live database round trip is claimed. This is a Stitch-inspired implementation, not a verified pixel-identical reproduction.

To review without a database, run `streamlit run scripts/workbench_preview.py` in the installed environment. It uses synthetic records and does not save data. Review the actual app with a nonproduction client before adopting the build.

The main sidebar, shared theme and Exposure Overview module are compared byte-for-byte with v5.4.7. Application scale and global typography rules are unchanged. `app.py` changes only the Calendar call to pass the existing client-switch callback.
