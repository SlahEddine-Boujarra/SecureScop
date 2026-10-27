# Contributing

## Workflow

1. Create a focused branch from the protected default branch.
2. Keep scanner, workspace, database, and UI changes in separate commits when
   practical.
3. Add or update regression tests for every behavior change.
4. Run compilation, tests, and the relevant offline diagnostics.
5. Open a pull request describing scope, risk, evidence, and rollback.

## Python standards

- Python 3.11 and PEP 8 naming conventions.
- Type hints for public interfaces.
- Docstrings for public functions and classes, including parameters, return
  values, and raised exceptions.
- Specific exceptions and structured logging; avoid bare `except` clauses.
- No secrets, hard-coded credentials, or client data in source or tests.

## Required checks

```powershell
python -m compileall -q src tests
python -m pytest -q
python -m pip check
```

Changes to PostgreSQL must use additive, ordered migrations. Changes to scan
dispatch or remediation must preserve workspace isolation and default-off
safety controls.

