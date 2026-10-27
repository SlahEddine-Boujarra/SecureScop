# SecureScope v5.4.2 — ISO Gap Dashboard

Adds the requested assessment dashboard and 30-task project tracker to v5.4.1.

- New default Gap dashboard in Control Assurance: 11-area summary, four KPIs,
  radar, count bars, percentage bars, filters and assessment drilldown.
- Uses 123 actual catalog units, with visible unassessed results and justified,
  approved Annex A exclusions. Does not seed example scores.
- Includes current validated manual-assessment evidence and the latest approved
  SoA when calculating dashboard results.
- New Project plan: resources, weekday dates, planned/completed days, progress,
  rollup task, timeline and client-isolated change history.
- Atomic saves reject stale revisions and inconsistent task durations.
- Formula-safe CSV exports of the summary, filtered entries and project plan.
- Additive migration 007; no new runtime dependencies.
- Updated Windows setup avoids copying a virtual environment between folders.
- Domain, chart-schema and Streamlit interaction tests; optional PostgreSQL
  integration tests are wired to a dedicated CI service.

See the feature documentation for calculation rules and the release validation
report for tested behavior and local limitations.
