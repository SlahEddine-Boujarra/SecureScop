# Validation results for v5.3.3

Validated on 2026-08-03 against SecureScope v5.3.2 with SHA-256
`649eb55efcd6d2ad96457299d37c3b3235c470609e63406a946f5fbc77c7e8ac`.

## Passed

- 78 Python source files compiled successfully.
- 28 dependency-free unit and static contract tests passed.
- Expanded-sidebar buttons explicitly use left alignment and a fixed icon gap.
- Tab lists use non-zero spacing, wrapping, borders and a clear active state.
- Asset Management contains no workflow-bar call, clock columns, clock detail
  fields or clock-synchronization panel call.
- NTP services, clock-evidence persistence, Wazuh collection and ISO A.8.17
  source code remain present.
- Source comparison shows that only the intended application/theme files and
  release documentation differ from v5.3.2.

## Failed

None among the dependency-free checks.

## Not executed in this build environment

- Nine legacy test modules require packages not installed here: Streamlit,
  psycopg2, python-dotenv or requests.
- Streamlit runtime and browser screenshots.
- PostgreSQL migration execution.
- Windows PowerShell parsing and application launch.
- Live OpenVAS, Nuclei, Wazuh and CISO Assistant integrations.

Run the full validation on the configured Windows host:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\start_securescope.ps1
```
