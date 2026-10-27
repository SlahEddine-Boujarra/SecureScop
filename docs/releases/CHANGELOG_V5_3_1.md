# SecureScope v5.3.1 - Dual-engine PDF reports

## Fixed

- Fixed repeated PyArrow serialization errors in the Nuclei live table by using
  nullable integer types for `Runner PID` and `Requests`.
- Included the corrected workspace argument in `nuclei_diagnostics.py`.

## Added

- Official Material `picture_as_pdf` row action in the OpenVAS and Nuclei live
  scan tables inside Scan Center only.
- Provider PDF copy download directly from the selected scan row.
- Embedded PDF preview using Streamlit's native iframe support.
- Deterministic consolidated OpenVAS + Nuclei PDF for the same client asset.
- Engine attribution on every consolidated finding.
- Assessment coverage table with provider scan dates and finding counts.
- `dual_engine_report.py` and `docs/DUAL_ENGINE_REPORTS.md`.

## Preserved

- Client/workspace isolation.
- Batch, job, attempt, task, report, and source identities.
- Existing OpenVAS and Nuclei provider-generated PDFs.
- Existing worker lifecycles and scan execution behavior.
