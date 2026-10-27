# SecureScope 5.4.9.dev0 — continuation checkpoint

Date: 2026-09-15. Baseline: the user-supplied SecureScope_v5_4_9_py311_fixed.zip.
Governing specification: Pasted markdown(8).md, preserved in FULL_REMEDIATION_BRIEF.md.

## Outcome

Phase 0 remains incomplete. This is a development checkpoint, not completion of
the requested risk-methodology, SoA or nonconformity redesign. The supplied brief
makes build and security gates blocking; the continuation did not bypass them.
No new authentication mechanism or risk acceptance criteria were invented.

## Code changes

- Starter risk examples now use one atomic batch transaction. Previously each
  example committed independently; a later conflict could leave a partial set,
  and a retry would skip seeding because the register was no longer empty.
- Added 17 risk transaction cases exercising the real repository and transaction
  manager with a simulated connection pool: batch rollback, stale revisions,
  denied authorization, link-save failure, invalid scores, duplicate references,
  actor attribution, client filtering, and successful/failed starter imports.
  These do not prove PostgreSQL isolation, SQL execution, or production login.
- Extended the Python syntax guard to inspect root Python launchers if present
  and detect nested multiline single-quoted f-strings. Valid multiline expressions
  in triple-quoted f-strings remain allowed. Added three guard tests.
- CI compilation now includes scripts as well as src and tests on Python 3.11
  and 3.12. Existing migration files, dependency constraints, version metadata,
  app navigation, layout scale, Exposure Overview and UI styles were not changed.
- Preserved the brief and the latest risk methodology, SoA and nonconformity HTML
  references in this directory so the next implementation has concrete inputs.

## Verification

| Check | Observed result |
| --- | --- |
| Full Python suite, actual CPython 3.11.16 | 415 passed, 7 skipped, 2 warnings |
| Coverage command with required 60% floor | FAIL: 32.26% overall coverage |
| Risk repository statement coverage | 96% (72 of 75 statements) |
| PostgreSQL integration cases | Four skipped: no test database configured |
| Remaining three skips | Python 3.12 token-specific guards; real 3.11 parsing runs |
| Focused risk and syntax cases on Python 3.12 | 22 passed |
| Frontend | Both files execute; 8 tests pass |
| Python 3.11 compileall, src/tests/scripts | PASS |
| Black, isort, flake8 | PASS |
| python -m pip check | No broken requirements found |
| pip-audit -r requirements.txt | No known vulnerabilities found at verification time |
| Hosted CI / Gitleaks | Not executed here |
| Windows launchers and browser visual review | Not verified here |

The isolated environment runs Python 3.11 on Linux, not Windows. PostgreSQL
installation was attempted and failed because system UID/group operations are
not available in this runtime. The connection-pool tests are not substitutes for
live database tests. Two dependency deprecation warnings concern Starlette/httpx and AnyIO; they do not fail the suite.

Reproduce the blocking gate in a project virtual environment:

```powershell
python -m pip install -r requirements-dev.txt
python -m compileall -q src tests scripts
python -m pytest -q --cov=securescope --cov-report=term-missing --cov-fail-under=60
python -m pip check
npm ci --prefix tests/frontend
npm test --prefix tests/frontend
```

Set SECURESCOPE_TEST_DATABASE_URL only to a dedicated disposable test database
before enabling integration cases; do not point tests at client production data.
See the existing START_HERE.md for normal application startup. This checkpoint
adds no database migration and changes no dependency requirement.

## Exact continuation order

1. Finish Phase 0: raise meaningful whole-package coverage to 60%, execute the
   database tests and hosted security gates. Keep the existing coverage scope.
2. Phase 1: resolve the explicit login choice (local accounts with administrator
   MFA, or a named identity provider), then implement authenticated actors,
   session lifecycle, tenant isolation, encryption requirements and audit checks.
   Current environment/header identities are not verified authentication.
3. Risk methodology: client-scoped, versioned and approved methodology records;
   references from assessments; configurable impact dimensions and criteria.
   The mockup's thresholds and approval authority are not accepted defaults.
4. SoA editor: reuse the existing applicability/justification schema, add the
   designed filters, detail editing, risk links, approval history and exports.
5. Nonconformity: independent records for containment, root cause, corrective
   actions, dated effectiveness verification and sign-off. Do not substitute
   gap-remediation actions for this workflow.

## Design-to-code mapping

| Reference | Source upload | Implementation target |
| --- | --- | --- |
| risk_methodology_reference.html | code(20260915-005053).html | New versioned methodology persistence and risk workbench integration |
| soa_reference.html | code(20260915-005106).html | Existing SoA model and component editor |
| nonconformity_reference.html | code(20260915-005046).html | New nonconformity workflow, linked corrective actions and verification |
| DESIGN_REFERENCE.md | DESIGN(3).md | Content-area component styling; retain the agreed navigation and application scale |

These are original supplied reference files, not running application pages. Their
sample percentages, dates, actors, thresholds and standards labels must not be
copied as live data or treated as authoritative rules. The templates use external
assets and may require internet access when opened. The live Figma file has not
been accessed during this continuation.
