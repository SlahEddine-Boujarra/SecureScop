# SecureScope v5.4.1 validation results

Validation was run from the v5.4.1 source tree with the supplied v5.4.0
application as the baseline.

## Automated checks

| Check | Result |
| --- | --- |
| `python -m pytest -q` | **229 passed**, 5 interpreter deprecation warnings |
| `python -m compileall -q src tests` | **Passed** |
| `npm test --prefix tests/frontend` | **7 passed** |
| `python -m sphinx -b html docs/api build/docs` | **Passed** |
| `python -m pip check` | **Passed** |
| `git diff --check` | **Passed** |

The Python suite includes 27 new interaction and data-quality checks in
`tests/test_assurance_runtime.py`. The frontend suite uses the production table
HTML/JavaScript assets in `tests/frontend/table.test.mjs` and covers search,
pagination, stable selection, keyboard access, sorting, empty states, filtered
CSV export, formula escaping, status tones and data shrinkage.

The Streamlit tests run the real Streamlit 1.62.0 runtime with synthetic records.
They verify that the default register does not render hidden forms, a selected
control opens the matching assessment editor, a workspace switch clears the
selected control, an invalid row event is ignored, and a draft value does not
transfer to another control.

## Release integrity

`scripts/build_release.py` reads the version from `pyproject.toml`, excludes
secrets, runtime output, virtual environments and generated caches, writes a
SHA-256 manifest, creates a deterministic ZIP, verifies ZIP CRCs and checks every
packaged member against the manifest.

## Limits

No test contacted a real PostgreSQL instance, OpenVAS/GVM, Nuclei, Wazuh or
CISO Assistant. The Windows launcher and live scanner workers require local
verification. The cloud browser could not access the local Streamlit preview,
so visual browser verification was unavailable in this environment. The
synthetic Streamlit interaction tests are the evidence for control-page behavior
covered by this release.
