# Validation results for v5.3.2

Validated on 2026-08-03 against the exact uploaded v5.3.1 archive with SHA-256
`9d24bb5dcde3a3809a33779c8a2d21804cc213af1480fd7287677883e6a35d08`.

## Passed

- 77 Python source files compiled from source without writing bytecode.
- 23 targeted standard-library unit tests passed.
- Gap calculation `27/100` against target `80%` returned coverage `27%`, gap
  `53` and additional effort `53`.
- Missing scope remained Not assessed rather than `0%`.
- Low severity did not default to Critical; confirmed KEV could justify it.
- Two findings with the same identity and action grouped into one candidate
  while retaining both finding and asset links.
- Informational findings were excluded from remediation by default.
- Both reviewed remediation recipe checksums matched their artifacts.
- Default-off execution and empty command allow-list were confirmed.
- Worker code stops at Pending verification and does not mark findings
  Verified.
- Two migrations were statically validated: 31 tables, 29 indexes, no `DROP`,
  `TRUNCATE` or `DELETE FROM` statement.
- New persistence and mutation queries retain `client_id` workspace scoping.
- 14 new Python modules contain no undocumented function or class and no line
  longer than 99 characters.
- 16 scanner, reporting and integration modules are byte-identical to the
  uploaded v5.3.1 archive.

## Failed

None among the checks that could run in the build environment.

## Skipped

- The existing pytest suite: pytest is not installed in the build runtime.
- PostgreSQL migration execution: no PostgreSQL service or configured `.env`.
- Streamlit smoke test and browser screenshots: Streamlit is not installed.
- PowerShell parsing and Windows launch: PowerShell is unavailable.
- Live OpenVAS, Nuclei, Wazuh and CISO Assistant integration tests.

Run on Windows after configuring `.env`:

```powershell
.\.venv\Scripts\python.exe .\run_migrations.py
.\.venv\Scripts\python.exe -m pytest -q
.\start_securescope.ps1
```
