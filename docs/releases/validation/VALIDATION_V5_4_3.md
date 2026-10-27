# SecureScope v5.4.3 validation

Validated on 9 September 2026 in the source worktree.

| Check | Result |
| --- | --- |
| Full pytest suite | 289 passed, 4 skipped in 6.03 seconds |
| Skips | Four PostgreSQL project-persistence tests; SECURESCOPE_TEST_DATABASE_URL unset |
| Warnings | 11 dependency metadata DeprecationWarnings |
| Wazuh security regressions | Host plus Administrator authorization, independent TLS flags, encrypted replacement/preservation, atomic-write failure behavior passed |
| Vulnerability intelligence | Partial/missing/failed feed states remain unavailable; tested cache attachment |
| Toolkit preservation | Four original-template namespace checks; formulas and chart/pivot part preservation; unsafe XML rejection |
| Toolkit download state | Streamlit interaction test invalidates old downloads after input edits |
| Recalculation guards | Reject no-op/stale conversion and removed chart objects |
| Migration discovery | Versions 1–9; disabled files ignored; existing alias compatibility tested |
| Other regression coverage | Shared presentation, scanner output, project planning, risk/SoA and workbook generation |

Compilation, dependency consistency and git whitespace checks are release gates.
The source archive builder checks ZIP CRC and every packaged file digest.

No live PostgreSQL connection was configured. The read-only schema inspector
stopped before querying; no migrations or imported client-data writes ran here.
Passing offline tests does not confirm deployed schema compatibility.

A browser connection to the sandbox preview was unavailable. Streamlit
interaction tests cover behavior, not final pixel appearance. Live scanner/
Wazuh services and a Windows installation were not exercised.

The available LibreOffice process did not finish even a tiny workbook.
Original-template population is tested, but full recalculation and preserved
pivot/chart output are unverified. Downloads refuse output that cannot pass
strict validation. No faithful populated workbook is claimed as complete.

See [the audit](../SECURESCOPE_UI_HARDENING_AUDIT.md) and
[the mapping proposal](../TOOLKIT_MAPPING_PROPOSAL.md).
