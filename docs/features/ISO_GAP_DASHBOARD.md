# ISO gap dashboard and ISMS project plan

## Assessment basis

The dashboard uses one unit per ID in the existing SecureScope catalog. These
are assessment units, not a universal count of ISO requirements. The supplied
140-item spreadsheet decomposes clauses more finely; its detailed checklist
was not provided and is not interchangeable with the 123-unit catalog.

| Area | Catalog units |
| --- | ---: |
| 4 Context | 4 |
| 5 Leadership | 3 |
| 6 Planning | 5 |
| 7 Support | 7 |
| 8 Operation | 3 |
| 9 Performance evaluation | 6 |
| 10 Improvement | 2 |
| A.5 Organizational controls | 37 |
| A.6 People controls | 8 |
| A.7 Physical controls | 14 |
| A.8 Technological controls | 34 |
| Total | 123 |

The catalog references ISO/IEC 27001:2022 and Amendment 1:2024. See
[ISO's publication reference](https://www.iso.org/standard/27001) and
[ANAB's account of the 2022 revision](https://blog.ansi.org/anab/iso-iec-27001-2013-2022-comparison/).
Existing short identifiers and labels are reused; requirement text is not reproduced.

## Rules

| Dashboard result | Source rule |
| --- | --- |
| Met | Latest profile's latest assessment is Implemented and effective, validated, with current validated evidence |
| Partially met | Partially implemented |
| Not met | Gap identified or Not implemented |
| Not assessed | No record, Not assessed or Manual assessment required |
| Review required | Other conclusions, missing validation/evidence, or unapproved applicability exclusions |
| Excluded | Justified, approved Annex A exclusion in the latest approved SoA |

Current evidence may come from a consultant-approved Evidence Hub mapping or
evidence attached to the latest manual assessment. Both the assessment and its
evidence must have Current/Approaching expiration freshness; evidence expiration
is checked at query time. Mandatory clauses cannot be excluded. Duplicate versions
cannot inflate totals. Missing catalog entries remain unassessed. Custom controls
outside this catalog are outside this dashboard's denominator.

`in_scope = catalog_entries - approved_annex_exclusions`

`conformity = met / in_scope * 100`

`assessment_coverage = (in_scope - not_assessed) / in_scope * 100`

Assessment coverage includes recorded outcomes that need review; it does not imply
completed verification. All charts use the same snapshot. The total is weighted by
entry counts, not an average of section percentages. An excluded-only area is N/A,
its radar point is omitted, and no polygon is drawn across a missing axis. Fresh
workspaces show no entries met. These measures are not certification decisions.

## Navigation and presentation

Gap dashboard and Project plan precede the six existing lazy Control Assurance
tabs. The selected dashboard entry opens the existing assessment workflow.
All state is client-scoped; task drafts retain their original revision.

Charts are native Vega-Lite specifications, with fixed 0–100 percentage axes,
hover details and adjacent numeric tables. There is no new runtime dependency
or CDN requirement. References: [Vega-Lite lines](https://vega.github.io/vega-lite/docs/line.html)
and [Streamlit charts](https://docs.streamlit.io/develop/api-reference/charts/st.vega_lite_chart).

## Project plan

Tasks and resources follow the supplied 30-task plan. More specific references
are used for policies (5.2/A.5.1), risk assessment (6.1.2/8.2) and risk treatment
(6.1.3/8.3). Certification stages are project milestones. Scheduling allows
parallel work; row order does not impose task dependencies.

Default rows are calculated without writes on page view. Saved fields are keyed
by `(client_id, task_ref)`. Task 15 summarizes tasks 16–20 and is not independently
stored or counted in effort totals. Dates count Monday–Friday inclusively and
do not subtract public holidays. Overall progress measures planned effort;
unplanned tasks remain separately visible.

On save, the repository locks the client, compares the expected task revision,
upserts the task and appends before/after audit snapshots in one transaction.
Conflicts or failed audit appends roll back. Actor names are entered attribution,
not a new authentication system. CSV downloads preserve dates, quotes/newlines and
Unicode, while neutralizing spreadsheet formula prefixes in text cells.

Migration 007 is additive. Previous migrations and tables are unchanged. Client
deletion cascades only the selected client's project tasks and audit history.

## Modules

- `grc/gap_dashboard.py`: classification and aggregation.
- `grc/isms_project_plan.py`: template, validation, weekdays and rollup.
- `persistence/isms_project_repository.py`: atomic task saves and history.
- `persistence/grc_repository.py`: direct evidence and approved SoA metadata.
- `ui/gap_charts.py`: chart specifications.
- `ui/gap_dashboard_ui.py`: dashboard, filters, exports and task editor.
