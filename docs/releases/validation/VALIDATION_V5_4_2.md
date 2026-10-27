# v5.4.2 validation — 8 September 2026

## Passed locally

- Full Python suite: **265 passed**. Ten existing environment metadata
  deprecation warnings were emitted by Streamlit-related tests.
- Streamlit AppTest workflows: default dashboard, three chart elements, lazy
  project loading, filters, matching assessment navigation, save/rerun, weekday
  finish calculation, client isolation and stale-draft rejection.
- Assessment rules: 123-unit denominator, missing units, duplicate/latest
  profiles, weighted totals, incomplete states, manual and mapped evidence,
  approved Annex A exclusions and mandatory clause retention.
- All four chart specifications validate through installed Altair/Vega-Lite
  schemas. Undefined percentages do not become numeric radar points.
- Workday calculation, invalid task input, parent rollup and safe CSV round trips.
- New production Python modules pass flake8 at the project's 100-character limit.
- Python compilation, dependency consistency and Sphinx API documentation build.
- Release builder verifies ZIP CRCs and every SHA-256 manifest entry.

## Performance sample

cProfile ran catalog aggregation and the three dashboard chart specifications
1,000 times using a synthetic unassessed 123-entry workspace: **0.526 seconds**
total, about **0.53 ms per iteration** under profiling. Database, Streamlit and
browser time are excluded. This is not an end-to-end latency benchmark.

## Not verified locally

- **4 PostgreSQL integration tests skipped**: `SECURESCOPE_TEST_DATABASE_URL`
  was not configured. They exercise actual SQL isolation, stale revisions,
  audit rollback and workspace deletion. CI provisions a dedicated PostgreSQL
  service, but the remote workflow was not executed in this local build.
- Cloud Browser could not access `http://127.0.0.1:8502`, returning
  `net::ERR_BLOCKED_BY_CLIENT`. Screenshots and visual layout verification were
  not completed. Chart-schema and Streamlit tests are distinct from visual QA.
- Windows launcher, a production PostgreSQL upgrade, OpenVAS/Nuclei/ZAP,
  Wazuh and CISO Assistant were not exercised in the user's environment.

This build measures recorded internal assessment progress. It does not verify
that a client conforms to ISO/IEC 27001 or has obtained certification.
