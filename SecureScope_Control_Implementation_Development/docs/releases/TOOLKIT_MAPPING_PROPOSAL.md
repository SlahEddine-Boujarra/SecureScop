# Toolkit mapping and schema proposal — approval required

Source schemas and supplied files are inspected; live PostgreSQL metadata is
unavailable. This document precedes any new database importer. Upload previews
cannot commit. Opportunity persistence/reference storage await your decision.

## Read-only database verification

From the installed folder using its configured environment:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m securescope.cli.inspect_toolkit_schema --output toolkit_schema.json
```

Share toolkit_schema.json, not credentials. This reads columns, constraints and
migration metadata in public; no migrations or client-data queries run. If you
use a different database schema, that schema must be inspected explicitly.
Here the command stopped without querying because no connection was configured.
All types below are verified against **source SQL only**.

## Statement of Applicability — migration 001

Source: ISO27001 Annex A Applicability, header row 12; 93 control rows among
section headings. Target securescope_soa_items, client/version scoped.

| Toolkit input | Source field/type | Mapping |
| --- | --- | --- |
| CONTROL | control_id TEXT, control_name TEXT; both NOT NULL | Split A.5.1 ID/name; resolve catalogue ID, skip headings/totals |
| CONTROL APPLICABLE? | applicability TEXT NOT NULL, Applicable/Not applicable CHECK | Yes/No; missing or unknown value is an error |
| CONTROL APPLICABLE? | necessary_control BOOLEAN NOT NULL | Preview suggestion; human reviews necessity against requirements |
| JUSTIFICATION FOR INCLUSION OR EXCLUSION | inclusion_justification TEXT / exclusion_justification TEXT | Matching nonblank justification |
| CONTROL IMPLEMENTED? | implementation_status TEXT NOT NULL; **no source enum CHECK** | Yes → Implemented; No → Not implemented; Partial → Partially implemented; blank → Not assessed |
| COMMENTS | effectiveness_review TEXT NOT NULL DEFAULT '' | Preserve as notes, not approval |
| Absent owner | control_owner TEXT NOT NULL | Resolve in UI before persistence; do not invent owner |
| Absent relationships | related_risks, related_treatment_plans, evidence JSONB arrays | Preserve existing links; new drafts empty |
| Absent review | reviewer TEXT, review_date DATE, approved BOOLEAN DEFAULT FALSE | Human review; no auto-approval |

Applicable requires inclusion justification. Not applicable requires exclusion
justification **and approved true**; setting approved false does not bypass it.
Preview reports row-level errors. Future writes must hold exclusions outside
the constrained table until an authorized human approves the version.
The sample's Yes values with blank justifications are not approved client data.
No imported declared status can replace live evidence-based Gap assessment.

## Asset/scenario risks — one canonical register

Source Risk Assessment headers row 13, input slots 14–33.
Target securescope_risk_register, migration 008.

| Toolkit input | Source target/type |
| --- | --- |
| Ref | risk_ref INTEGER NOT NULL CHECK > 0, unique per client |
| Asset Group / optional subcategory / Asset | asset_group / asset_subcategory / asset TEXT |
| Threat / Vulnerability | threat / vulnerability TEXT |
| Risk Type / Owner / Existing Controls | risk_type / risk_owner / existing_controls TEXT |
| Likelihood / Rationale | pre_likelihood INTEGER CHECK 1–5 / pre_likelihood_rationale TEXT |
| Impact / Rationale | pre_impact INTEGER CHECK 1–5 / pre_impact_rationale TEXT |
| Risk Score / Level | Derived; never import cached calculated values |
| Treatment Option | treatment_option TEXT CHECK Modify, Accept, Avoid, Transfer / Share |
| Proposed Treatment Action | treatment_action TEXT |
| Annex A/Control Reference | control_references JSONB array |
| Treatment Cost | treatment_cost NUMERIC(14,2); validate finite nonnegative |
| Treatment Action Owner / Timescale / Progress | treatment_action_owner / treatment_action_timescale / treatment_action_progress TEXT |
| Treatment Action Status | treatment_action_status TEXT CHECK Not Started, In Progress, Completed, Rejected, Accepted risk |
| Post-Treatment Likelihood / Rationale | post_likelihood INTEGER CHECK 1–5 / post_likelihood_rationale TEXT |
| Post-Treatment Impact / Rationale | post_impact INTEGER CHECK 1–5 / post_impact_rationale TEXT |
| Post-Treatment Score / Level | Derived; blank inputs remain unassessed in app |
| Comments | comments TEXT |
| Absent verification | Migration 009: residual_verified BOOLEAN DEFAULT FALSE, residual_evidence / residual_verified_by TEXT |
| Absent audit fields | revision INTEGER > 0, updated_by TEXT, creation/update timestamps |

Nullable likelihood/impact means unassessed, not zero. Planned post-treatment
values cannot become verified residual risk on import.

Migration 008/009 status: previously uncommitted .sql.disabled files were
explicitly included by the runner. Apparent missing commas are valid column-
level CHECKs. They are now normal .sql files with unchanged contents; disabled
files are ignored. History does not explain the old names. No live migration
was run here.

Scenario gap: no risk_summary or risk_description columns exist in source.
Propose additive risk_summary TEXT NOT NULL DEFAULT '' and risk_description
TEXT NOT NULL DEFAULT '' on the SAME risk table. Current generic JSON scenario
worksheets are labeled drafts; they are not promoted to canonical records.

## Opportunities — schema proposal only

Opportunity Assessment header row 14, input slots 15–34.
No dedicated table is present in source. Generic JSON opportunity worksheets
remain drafts. This SQL is a document proposal, **not a migration file**:

```sql
CREATE TABLE securescope_opportunity_register (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL
        REFERENCES securescope_clients(id) ON DELETE CASCADE,
    opportunity_ref TEXT NOT NULL CHECK (btrim(opportunity_ref) <> ''),
    summary TEXT NOT NULL CHECK (btrim(summary) <> ''),
    description TEXT NOT NULL DEFAULT '',
    opportunity_type TEXT NOT NULL DEFAULT '',
    opportunity_owner TEXT NOT NULL DEFAULT '',
    likelihood SMALLINT CHECK (likelihood BETWEEN 1 AND 5),
    likelihood_rationale TEXT NOT NULL DEFAULT '',
    impact SMALLINT CHECK (impact BETWEEN 1 AND 5),
    impact_rationale TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    action_owner TEXT NOT NULL DEFAULT '',
    due_date DATE,
    status TEXT NOT NULL DEFAULT 'Draft'
        CHECK (status IN ('Draft', 'Planned', 'In progress', 'Completed', 'Declined')),
    comments TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, opportunity_ref)
);
```

| Toolkit input | Proposed target |
| --- | --- |
| Ref | opportunity_ref |
| Opportunity Summary / Description | summary / description |
| Opp Type / Owner | opportunity_type / opportunity_owner |
| Likelihood / Impact and rationales | likelihood / impact and matching rationale fields |
| Opportunity Score / Level | Derived from inputs/agreed opportunity policy; no cached score storage |
| Action / Action Owner | action / action_owner |
| Comments | comments |
| Extra app fields | due_date, status, revision/audit fields |

Use revision conflict checks and immutable history following the existing
working-register repository. Promotion of draft worksheets needs explicit
preview and confirmation. High opportunity means potential benefit, not
high-severity threat.

Approval requested: this table after live-schema review, plus the two scenario
text columns on the existing risk register. Nothing is silently migrated.

## Reference content proposal

Keep source sheets intact. Propose versioned read-only
config/iso27001_reference_data.json, following the bundled catalogue pattern.
Suggestions are selected/reviewed by users, never seeded as client facts.
No extraction has run. Confirm this location first; tenant-editable references
would need a different decision.

## Import contract

1. Bounded workbook read and strict input type validation.
2. Preview creates/updates/errors within selected client, matching references
   and using a new SoA version.
3. Explicit review, role checks and revision checks before atomic persistence.
   Never delete absent rows or overwrite validated assessments silently.
4. Shared spreadsheet sanitizer on every later export; parameterized repository
   methods remain the SQL boundary.
5. Never import formula/cached score cells into canonical calculated fields.
6. Apply controls remain disabled until the live schema is reviewed.

## Export placement, preservation and scoring

reporting/template_toolkit.py belongs beside the existing reporting generators.
UI triggers sit beside asset/scenario/opportunity registers and SoA. Existing
clean exports use iso_assurance_export/register_exchange. All reuse
reporting/spreadsheet_safety.py.

Copy original archive, write inputs only, recalculate and check formulas,
caches, errors and chart/pivot preservation before download. XML population
has preservation tests; native end-to-end fidelity is not verified here.
A configured converter may still fail the strict checks and refuse download.

Numeric scores are likelihood × impact. Template levels are Low 1–4 / Medium
5–11 / High 12–25; app levels Low 1–4 / Medium 5–9 / High 10–16 / Critical
17–25. UI discloses this difference while retaining original formulas. Agree
and version the business scoring policy before making template labels
canonical. Live Gap scores remain based on the app's control assessments.
