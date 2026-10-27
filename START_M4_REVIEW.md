# Review the merged M4.1 delivery

Start with `docs/milestones/M4_1_DEVELOPMENT_REVIEW.md` for the exact changes, executed results and remaining gates. Read `docs/milestones/M4_1_KIMI_REVIEW.md` for the supplied fixes and the Docker/bootstrap exclusion. The application remains the existing SecureScope implementation; no migration is required by this UI slice.

## Reproduce available tests

From this source directory, with Python 3.12 and Node installed:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
PYTHONPATH=src python -m pytest -q -ra
npm --prefix tests/frontend ci
npm --prefix tests/frontend test
PYTHONPATH=src python validation/m4_1/profile_presentation.py
```

Database tests require a separately authorized, disposable PostgreSQL test database configured according to the existing M1–M3 test instructions. Do not point test URLs at production. Skipped tests are not passes.

## Reproduce the synthetic UI demonstration

```bash
npm --prefix validation/m4_1 install
cd validation/m4_1
npx playwright install chromium
cd ../..
PYTHON="$PWD/.venv/bin/python" node validation/m4_1/browser_check.mjs
```

The runner starts a loopback-only Streamlit fixture, opens Chromium, executes the actual SIEM route/component checks and shuts the server down. It writes `browser-results.json`, which records either pass or failure. It does not collect live evidence or change database records. The fixture clearly labels its synthetic data. Do not expose this test fixture as the production application.

For manual inspection:

```bash
PYTHONPATH=src python -m streamlit run validation/m4_1/siem_fixture.py --server.address=127.0.0.1
```

Inspect FIXTURE-02 for positive collection-health evidence with zero security alerts, and FIXTURE-03 for active status without verified telemetry. Try search, the state filter, provenance/scope sections, the keyboard and a narrow viewport. Connection/collection actions in this fixture are synthetic. Clock collection is excluded from the fixture demonstration.

In this execution environment the standard Chromium download was incomplete, so the recorded run used the local Chromium binary from `@sparticuz/chromium@153.0.0` with Playwright 1.62.1. The runner supports `PLAYWRIGHT_MODULE`, `M4_BROWSER_EXECUTABLE` and `CHROMIUM_ARGS_MODULE` overrides for that alternative. No browser binaries or Node dependencies are bundled with the application. Screenshots are optional through `M4_SCREENSHOT_DIR` and are not included in the delivery.

The source ZIP contains the restored full application, the exact baseline-to-delivery patch, checksums, test logs and a local Git bundle. The restore commit is a new local snapshot of the verified M3 delivery, not a recreation of its original Git history. Production recurring collection must remain disabled until the existing production security gates are verified.
