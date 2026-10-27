# Development quality guide

## Local environment

Use Python 3.11 in `.venv`. Runtime dependencies are recorded in
`requirements.txt`; review tooling is in `requirements-dev.txt`.

## Validation order

1. `python -m compileall -q src tests`
2. `python -m pytest -q`
3. `python -m pip check`
4. Relevant offline diagnostics under `scripts/windows/`
5. Authorized integration tests against PostgreSQL and configured scanners

## Code conventions

- PEP 8 names and four-space indentation.
- Type hints and complete docstrings on public interfaces.
- Specific exceptions with contextual logs.
- Parameterized SQL and workspace identifiers on every client-owned mutation.
- No shell construction from user, scanner, AI, or external finding text.

Black, isort, Flake8, and Pylint configurations are provided. Because the
application contains preserved legacy code, adopt formatting and lint cleanup
incrementally per touched module; do not mix large formatting rewrites with
functional scanner changes.

## Performance

Profile expensive changes with `cProfile` against representative asset and
finding volumes. Scanner concurrency must remain bounded by configuration and
database claims, not browser sessions.

## Documentation

Sphinx configuration is under `docs/api/`. Build it with:

```powershell
sphinx-build -b html docs/api docs/api/_build/html
```

