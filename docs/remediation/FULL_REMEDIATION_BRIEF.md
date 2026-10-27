# SecureScope v5.4.x — Full Remediation Brief

Paste this whole document as the opening message to a coding agent working in the SecureScope repository.

---

## ROLE

You are a senior engineer performing a full remediation of **SecureScope**, a Windows-hosted, Streamlit + FastAPI + PostgreSQL platform used by ISO/IEC 27001 consultants to run gap assessments, collect technical and governance evidence, and produce auditor packages for multiple client organisations.
The codebase is \~79,000 lines of Python across 232 modules, 12 SQL migrations, 58 Python test files and 2 JS test files. It works. Your job is not to rewrite it — it is to close verified gaps without regressing what already functions.

## GROUND RULES

1. **Additive migrations only.** Never edit an applied migration file. New work goes in `013_*.sql` onward. Every migration must be idempotent (`IF NOT EXISTS`) and must not drop or rename existing columns.
2. **Preserve the layering that is already correct.** `src/securescope/app.py` contains 741 Streamlit calls and zero raw SQL. Keep that boundary: no SQL in `ui/`, no Streamlit imports in `persistence/`, `grc/`, `core/`, `compliance/`, `evidence/` or `reporting/` (this is currently clean — verify it stays clean).
3. **Do not reproduce ISO standard text.** `grc/control_catalog.py` deliberately stores only short labels and assessment metadata. Preserve that and the `CATALOG_NOTICE` wording.
4. **Every phase ends green.** `python -m pytest -q`, `python -m compileall -q src tests`, `python -m pip check`, and `npm test --prefix tests/frontend` must all pass before you move on.
5. **Work in the order given.** Phase 0 and 1 are blocking. Do not start Phase 3 while Phase 1 is open.
6. **Report, don't assume.** If a required decision is ambiguous (identity provider choice, retention periods, risk methodology), stop and ask rather than inventing a default.

## ALREADY VERIFIED CLEAN — DO NOT "FIX" THESE

I ran these checks. They came back clean. Do not spend time on them and do not introduce changes that claim to fix them:

- **No SQL injection.** Zero f-string / `%` / `.format()` interpolation into SQL across `src/`. All queries are parameterised.
- **No command injection.** Zero `shell=True`.
- **No unsafe deserialisation.** Zero `eval`, `exec`, `pickle`.
- **No weak hashing.** Zero `md5`/`sha1`. Evidence uses SHA-256.
- **HTML escaping is correct.** `core/presentation.py::safe_text` escapes with `html.escape(..., quote=True)` and is applied at the `unsafe_allow_html` sinks in `app.py`. `ui/components/html_renderer.py` documents the caller-escapes contract. No `innerHTML` in `components_v2/*.js`.
- **The SoA data model is good.** `securescope_soa_items` in `001_v6_exposure_grc.sql` has separate inclusion/exclusion justification, `necessary_control`, related risks and treatment plans, and a DB-level CHECK refusing an unjustified or unapproved exclusion. Extend it; do not redesign it.
- **Optimistic locking exists** on `securescope_risk_register` and `securescope_isms_project_tasks` via `revision`. Reuse this pattern; don't replace it.
- **Immutability triggers exist** on `securescope_evidence_audit_events`, `securescope_scope_versions` and `securescope_grc_approvals`. Keep them; Phase 1 adds a hash chain *on top*.

---

# PHASE 0 — BUILD IS BROKEN (do this first, it is small)

### 0.1 The shipped test suite fails

`python -m pytest -q` currently gives **2 failed, 382 passed, 4 skipped**. (Note: `START_HERE.md` claims "289 Python tests passed" — that figure is stale and wrong. Correct it.)
Both failures are the same root cause:

- `tests/test_grc_workspace_v5_3_8.py::MigrationContractTests::test_migration_discovery_selects_known_bridge_and_new_migration`
- `tests/test_iso_evidence_hub_v5_3_7.py::ArchitectureRegressionTests::test_migration_three_variants_reconcile_through_migration_four`

Both assert `discover_migrations()` returns versions `[1..10]`. It returns `[1..12]` because `011_workspace_planning.sql` and `012_workbench_review_history.sql` were added without updating the contract tests.
**Fix:** rewrite both assertions so they are not a hardcoded list. Assert instead that discovered versions are contiguous from 1, contain no duplicates, and that the alias-resolution behaviour still selects `003_legacy_iso_evidence_bridge.sql` and `006_organization_knowledge_compat.sql`. A migration contract test must never need editing when a migration is added.

### 0.2 Vulnerable cryptography pin — this one is urgent

`requirements.txt` pins `cryptography>=45,<47`, which resolves to **46.0.7**. `pip-audit` reports **7 known vulnerabilities** in that version:

| ID Fixed in         |        |
| ------------------- | ------ |
| GHSA-537c-gmf6-5ccf | 48.0.1 |
| PYSEC-2026-3553     | 49.0.0 |
| PYSEC-2026-3554     | 49.0.0 |
| PYSEC-2026-3552     | 50.0.0 |

This is the library that encrypts your evidence artifacts and stored connector credentials. Bump to `cryptography>=50,<51`, run the full suite, and confirm Fernet encrypt/decrypt round-trips still pass in `evidence/storage.py` and `integrations/credential_store.py`.

### 0.3 CI never runs the security tooling it already declares

`.github/workflows/ci.yml` runs `compileall`, `pytest`, `pip check` and `npm test`. `requirements-dev.txt` declares `pip-audit`, `black`, `flake8`, `isort` and `pylint` — **none of them run in CI.** That is why 0.2 went unnoticed.
Add to the workflow: `pip-audit -r requirements.txt` (fail on findings), `black --check`, `isort --check-only`, `flake8`, `pytest --cov` with a coverage floor, and secret scanning. Enable Dependabot.

### 0.4 A frontend test never executes

`tests/frontend/package.json` has `"test": "node --test table.test.mjs"`. The file `assurance_workbench.test.mjs` exists and is never run. Change to `node --test *.test.mjs` (or `node --test .`) and fix whatever it surfaces.

### 0.5 Version metadata contradicts itself four ways

ZIP name says `v5_4_8`, `VERSION.txt` says `5.4.5`, `README.md` says `v5.4.3`, `SECURITY.md` says `v5.3.6`. Make `VERSION.txt` the single source, have `securescope.__version__` read from it, and add a test asserting README and SECURITY.md agree.
**Phase 0 acceptance:** suite green, `pip-audit` clean, CI runs all five gates, both JS test files execute, one version string everywhere.

---

# PHASE 1 — SECURITY (blocking; nothing else ships before this)

### 1.1 There is no authentication anywhere

This is the single defect that invalidates the product's core promise.
**FastAPI** (`src/securescope/api/app.py:274`): `workspace_context()` resolves identity from two plaintext headers, `X-SecureScope-Workspace` and `X-SecureScope-User`. No token, no signature, no secret. Anyone who can reach the port is any user in any client workspace, with full mutation rights.
**Streamlit**: identity comes from the `SECURESCOPE_CURRENT_USER_EMAIL` environment variable, read at `ui/grc_workspace/context.py:36`, `ui/evidence_hub_ui.py:49`, `ui/wazuh_settings_ui.py:29`, `ui/workspace_inputs.py:24` and `integrations/wazuh_service.py:58`. One identity per process. Every `updated_by`, `approved_by`, `reviewer` and `recorded_by` value in the database is self-asserted and unprovable.
I confirmed by booting the app headless: it serves HTTP 200 on `/` with no credential of any kind.
**Build:**

- A real login: OIDC/SAML preferred; if that is out of scope for this release, server-side sessions with Argon2id password hashing, account lockout, and a forced-rotation admin bootstrap.
- Server-side session store with absolute and idle timeout, secure/HttpOnly/SameSite cookies, and session invalidation on role change.
- API: signed short-lived bearer tokens (JWT or opaque+introspection). **Delete the header-based identity path entirely** — do not leave it behind a feature flag.
- Actor attribution sourced **only** from the authenticated server session. Make it structurally impossible for `updated_by` to come from a header, env var, form field or client payload. Add a test that proves a forged header cannot influence a persisted actor field.
- MFA for the Administrator role.
- Keep `WorkspaceRole` / `role_can()` — it is sound. Wire it to the real session.

### 1.2 Tenant isolation is application-level only

There is **zero** `ROW LEVEL SECURITY` in `database/`. Every repository must independently remember `WHERE client_id = %s` — across a 2,529-line `grc_workspace_repository.py`, a 2,246-line `grc_repository.py`, a 1,918-line `openvas_persistence.py` and a 1,877-line `exposure_repository.py`. One missed predicate leaks one consulting client's audit evidence into another client's workspace.
**Build:** enable RLS on every table carrying `client_id`, with policies keyed on `current_setting('securescope.client_id', true)::bigint`. Set that GUC on connection checkout in the existing threaded pool (`persistence/db_service.py`) and reset on return. Add a negative test per repository proving that a query issued under client A's GUC returns zero rows belonging to client B — this is the test that must never be deleted.

### 1.3 Encryption at rest is optional

`evidence/storage.py::_encrypt_if_configured` returns plaintext when `SECURESCOPE_EVIDENCE_ENCRYPTION_KEY` is unset. The same optional pattern applies to credential storage. A tool holding client vulnerability scans and audit evidence must not start unencrypted.
**Build:** fail-fast at boot if a key is absent. Move the key out of `.env` — Windows DPAPI or an external KMS. Add key versioning (`key_id` column on artifacts), a rotation command and a re-wrap job. Document the recovery procedure; an unrecoverable key means unrecoverable client evidence.

### 1.4 No transport security and no security headers

I booted the app and captured response headers: no `Content-Security-Policy`, no `X-Frame-Options`, no `Strict-Transport-Security`, no `X-Content-Type-Options`, no `Referrer-Policy`. `.streamlit/config.toml` sets no `server.address` (so it binds `0.0.0.0`), no XSRF or CORS hardening.
**Build:** bind to loopback by default, put a TLS-terminating reverse proxy in front (document it, ship the config), set all five headers, enable Streamlit XSRF protection, lock CORS on the FastAPI app to an explicit allow-list.

### 1.5 Tamper-evidence stops at triggers

Your immutability triggers are good instinct, but any superuser can `ALTER TABLE ... DISABLE TRIGGER`. There is no way to *detect* that afterwards.
**Build:** add a `previous_hash` / `entry_hash` chain to `securescope_evidence_audit_events`, `securescope_grc_audit_events` and `securescope_admin_audit_events`, computed on insert over the row payload plus the prior hash. Add a verification command that walks the chain and reports the first break. Include the chain head in the auditor package export so a broken chain is visible to the auditor, not just to you.

### 1.6 Segregation of duties is UI-only

A.5.3 and your own approval model assume author ≠ approver. Nothing in the schema enforces it. Add DB-level CHECK/trigger constraints on `securescope_grc_approvals`, `securescope_scope_versions` and SoA approval so a self-approval is rejected by PostgreSQL, not by a Streamlit `if`.

### 1.7 Smaller security items

- `integrations/ciso_assistant_service.py:95` disables `InsecureRequestWarning`. Make TLS verification mandatory with an explicit, logged, per-connector opt-out for self-signed lab hosts.
- 147 environment variables in `.env.example` with no validation. Replace with a `pydantic-settings` `Settings` class that validates and fails fast at boot. This is what would have caught 1.3.
- 8 uses of naive `datetime.now()` / `utcnow()`. Make every timestamp timezone-aware UTC; audit evidence with ambiguous timestamps is weak evidence.
- Add rate limiting and brute-force protection on the new auth endpoints.
- Add an evidence retention and secure-deletion policy (A.5.33, A.8.10, and GDPR if any client data is EU-linked). There is currently no deletion path for artifacts at all.

**Phase 1 acceptance:** no unauthenticated route exists; a forged header cannot set an actor field; cross-tenant query returns zero rows under RLS; boot fails without an encryption key; all five headers present; chain verification detects a manually tampered audit row.

---

# PHASE 2 — ISO 27001:2022 COMPLETENESS

**Standard status (confirmed current):** ISO/IEC 27001:2022 plus Amd 1:2024 remains the certifiable edition; there is no 2025 or 2026 revision of the requirements. ISO/IEC 27000:2026 (published 3 July 2026) is an *overview* standard only — it does not change Clause 4–10 or Annex A. Your `FRAMEWORK_REFERENCE = "ISO/IEC 27001:2022 + Amd 1:2024"` is correct. Do not change it.
Two secondary alignment tasks: review terminology against ISO/IEC 27000:2026 (its Clause 3 dropped from 77 defined terms to 12), and check that SoA screen wording matches the reference-set model used in Clause 6.1.3.

### 2.1 The catalog is complete; the registers are not

`control_catalog.py` correctly carries 30 clause entries (4.1 → 10.2) and 93 Annex A controls. But a certification-body auditor asks for **documented information**, and roughly a third of the mandatory items have nowhere to live in your schema. Build each of these as a proper relational register — client-scoped, versioned, with the same approval and audit-event pattern you already use for scope versions.
**Mandatory clause records — currently absent:**

| Register Requirement What it must capture |             |                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Management review                         | 9.3.1–9.3.3 | Meeting, attendees, each 9.3.2 input (a–f, **including climate**), decisions, actions, outputs. Mandatory record.                                                                                                                                                                                                     |
| Internal audit findings                   | 9.2.2(e)(f) | Audit report per engagement, findings classified (major NC / minor NC / observation / OFI), auditor independence, link to the programme you already have in `securescope_audit_scopes`.                                                                                                                               |
| Nonconformity & corrective action         | 10.2        | **`securescope_improvement_actions`** **is not this** — it is gap-driven remediation. 10.2 requires: source (audit/incident/complaint), immediate reaction, evaluation of need to eliminate cause, **root cause**, action taken, **review of effectiveness with a date and a result**, and any resulting ISMS change. |
| Risk criteria & methodology               | 6.1.2(a)    | Risk acceptance criteria and criteria for performing assessments. Mandatory documented information — you have a risk register but no documented method behind it.                                                                                                                                                     |
| Information security objectives           | 6.2         | What, who, what resources, when, how evaluated — and a link to the 9.1 results that evaluate them.                                                                                                                                                                                                                    |
| Monitoring & measurement                  | 9.1         | Metric definitions (what, method, when, by whom, when results are evaluated) and the results themselves. Mandatory record.                                                                                                                                                                                            |
| Competence & awareness                    | 7.2(d), 7.3 | Competence matrix per ISMS role, training records, awareness campaign evidence.                                                                                                                                                                                                                                       |
| Communication                             | 7.4         | What, when, with whom, how — internal and external.                                                                                                                                                                                                                                                                   |
| Documented information control            | 7.5.3       | Document register: owner, approver, version, review cycle, **next review date**, retention period, classification, distribution. This is usually an auditor's *first* request and you only have policy versioning.                                                                                                    |

**Annex A registers — currently absent:**

| Register Controls                                       |                                                                                                   |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Legal, statutory, regulatory & contractual requirements | A.5.31 — always requested; link it to the interested-party requirements you already model         |
| Supplier & ICT supply chain                             | A.5.19–A.5.23 — criticality, agreements, cloud services, monitoring and review dates              |
| Incident management                                     | A.5.24–A.5.28 — incident register, classification, response, evidence collection, lessons learned |
| Business continuity                                     | A.5.29–A.5.30 + Clause 8.1 — BIA, continuity plans, **test records**, ICT readiness               |
| Access rights review                                    | A.5.18, A.8.2 — periodic review campaigns with results and revocations                            |
| Change management                                       | A.8.32 + Clause 6.3 — change records linked to risk                                               |
| Control exceptions                                      | expiring exceptions with owner and review date, distinct from `securescope_risk_acceptances`      |

### 2.2 Asset model is host-shaped, not information-shaped

`app.py` holds an asset inventory with CIA classification (`classify_information`, `normalize_asset`, `merge_asset_records`) — that part is good. But A.5.9–A.5.13 needs **information** assets, not just discovered hosts: asset owner, classification scheme, labelling, acceptable-use linkage, return-of-assets on exit. Extend the model; keep the Nmap enrichment path.

### 2.3 Risk methodology is locked to one shape

`securescope_risk_register` is strictly asset–threat–vulnerability. Clause 6.1.2 permits that, but many organisations use scenario-based or event-based assessment, and a consulting tool that supports only one method will lose clients. Make the risk model pluggable behind a methodology record (see 2.1).

### 2.4 Certification lifecycle is missing

Add Stage 1 / Stage 2 / surveillance / recertification milestones, external auditor CAR tracking, and evidence-sampling lists per audit.

### 2.5 Keep the honest framing

`START_HERE.md` already says the gap score is an internal metric and not a certification decision. Make sure that statement propagates into every exported report and PDF. No tool makes anyone compliant — certification assesses the organisation's actual ISMS, and overstating this is both a commercial and an ethical risk.
**Phase 2 acceptance:** every mandatory documented-information item in the tables above has a client-scoped table, a UI surface, an export path into the auditor package, and a test. A consultant can produce a complete Stage 2 evidence set from the tool alone.

---

# PHASE 3 — ARCHITECTURE & DATA MODEL

### 3.1 `securescope_working_registers` is a JSONB blob — reverse this decision

`009_isms_working_registers.sql` stores an entire register as one JSONB array with a single shared `revision`. Consequences: two consultants editing different rows clobber each other; you cannot index, query, join, filter or report on contents; and register data is invisible to SQL-based assurance queries.
**Build:** migrate to relational tables per register, one row per record, with per-row `revision` optimistic locking matching the `securescope_risk_register` pattern. Write a forward migration that unpacks existing JSONB into rows. Keep `securescope_working_register_versions` as the version-snapshot mechanism.

### 3.2 `app.py` is 10,562 lines

Good news: zero SQL, so the layering boundary held. The problem is what is packed in beside the UI:

- `PlainSocketConnection` and `make_gmp_connection` — OpenVAS GMP transport → extract to `scanners/openvas/gmp_transport.py`
- `classify_information`, `normalize_asset`, `merge_asset_records`, `make_discovery_asset`, `cia_summary` — asset domain logic → extract to `core/asset_domain.py`
- `get_nmap_hostname`, `get_nmap_mac_and_vendor`, `get_os_details`, `get_services` — Nmap parsing → extract to `scanners/nmap/nmap_result_parser.py`
- Client workspace file handling (`load_clients`, `save_clients`) → move to `persistence/`

All of this is imported at startup on every rerun. Target: `app.py` under 2,000 lines, pure composition and routing.

### 3.3 Migration history is accreting shims

Duplicate `003`/`004` with identical content, a `003_legacy_iso_evidence_bridge.sql`, a `006_organization_knowledge_compat.sql`, and a runner in `persistence/migration_service.py` that special-cases published checksums and logs alias warnings on every run. Plan a squashed v6 baseline with a documented one-way upgrade path.

### 3.4 Deployment is Windows-PowerShell-only

24 `.ps1` files, local-filesystem evidence store, no container, no TLS, no documented backup/restore. Critically: the PostgreSQL dump and the filesystem evidence store **can drift** — a DB restore will not match the artifact directory.
**Build:** Docker Compose for app + API + worker + Postgres; a reverse proxy with TLS; a consistent backup procedure covering both stores; a reconciliation job that detects artifacts present in one store and absent from the other.

### 3.5 No observability

No structured logging, no correlation IDs, no metrics, no health/readiness beyond a static `/health`. You ask clients to satisfy Clause 9.1 while the tool measures nothing about itself. Add structured JSON logging with request/session correlation IDs, and basic metrics.

### 3.6 Legacy driver

`psycopg2-binary` is in maintenance mode. Plan a migration to `psycopg` (v3) for async support and better connection handling.

---

# PHASE 4 — UI/UX

### 4.1 Four coexisting styling systems

I measured them:

| Source Lines               |       |
| -------------------------- | ----- |
| `ui/styles/legacy.css`     | 1,810 |
| `ui/components_v2/*.css`   | 150   |
| `ui/styles/sidebar.css`    | 80    |
| `ui/styles/components.css` | 67    |
| `ui/styles/tokens.css`     | 64    |

Plus `ui/design_system/tokens.py` and `ui/securescope_ui_theme.py` as *separate* token sources. **89% of your CSS is still legacy.** The modernisation is announced in the README but barely started.
**Build:** one token source of truth, one component layer, delete `legacy.css` incrementally with visual checks per page. Reconcile `design_system/tokens.py` against `tokens.css` — they must not both define colour.

### 4.2 Accessibility is thin

Measured across the whole `ui/` tree: 11 `focus-visible` rules, 1 `prefers-reduced-motion`, **0** `prefers-color-scheme`, **0** `sr-only`, 28 `aria-` attributes, 47 `role=`.
**Build:** WCAG 2.2 AA pass — visible focus on every interactive element, screen-reader-only labels for icon-only controls, verified contrast ratios (check `#00685f` primary against every background it lands on), keyboard-only navigation through the SoA and risk register, and a dark theme (`.streamlit/config.toml` hardcodes `base = "light"`; security teams work in dark rooms).

### 4.3 Navigation serves two personas from one flat menu

Roughly 23 top-level destinations mixing a technical scanner operator (Scan Center, Vulnerabilities, SIEM, Asset Discovery, Exposure Overview) with an ISO consultant (Programme Foundation, Control Assurance, Evidence Hub, Policies). Split into two modes, or scope navigation by role.

### 4.4 Naming has drifted

"Gap Assessment" vs "Control Assurance". "Command Center" vs "ISO Command Center". "Evidence Hub" vs "ISO Evidence Hub". Your own README acknowledges the first pair. Pick one name each, migrate, and add a test asserting no deprecated label appears in the navigation registry.

### 4.5 Streamlit is the wrong tool for the heavy editing surfaces

119 `session_state` keys in `app.py` alone, fighting the rerun model. A 93-row SoA editor, the risk register and the working registers are the screens that hurt. You already have a FastAPI control plane with 30+ endpoints — use it. Keep Streamlit for dashboards and reports; move the register editors to `components_v2` or a small React app against the existing API. Do this for **one** surface first (the SoA editor) and measure before committing to the rest.

### 4.6 The biggest missing workflow is not visual

There is a `securescope_evidence_requests` table and **no client-facing surface**. Chasing evidence is where consultants actually lose their hours. Build the loop: consultant raises a request → client receives a scoped, authenticated upload link → submission lands as evidence pending review → reviewer approves or rejects with a reason → the SoA and control assessment update. This is probably the highest commercial-value item in this entire document.

### 4.7 Zero internationalisation

Not a single `gettext` / `babel` / locale call in 79,000 lines. Every string is hardcoded English. For a Tunisia-based consultancy, French and Arabic are near-certain requirements — and Arabic means RTL layout, which will be far more expensive to retrofit later than to plan for now. Introduce an i18n layer and externalise strings, even if you only ship English at first.

### 4.8 Template export fidelity is unverified

`START_HERE.md` admits no end-to-end faithful populated workbook was ever verified, and that original-template download depends on a working LibreOffice binary. Consultants live in Word and Excel — this is a delivery risk, not a nice-to-have. Build a fixture-based fidelity test that round-trips a populated SoA and risk register through the export path and asserts formulas, charts and pivots survive.

---

# PHASE 5 — TESTING

Current state: 6,575 test lines against 78,963 source lines (**\~8%**), 388 tests. Many are named for releases (`test_ui_fix_v5_3_3.py`, `test_compact_ui_v5_3_8_1.py`, `test_stitch_ui_v5_3_8_13.py`) rather than for behaviour — that naming is why the migration contract tests rotted unnoticed. Type hints cover roughly 896 of 1,349 function definitions (\~66%).
Build out, in this order:

1. **Security tests** (Phase 1 gates): forged header cannot set an actor; cross-tenant RLS returns zero rows; boot fails without an encryption key; audit hash chain detects tampering; self-approval rejected by the database; unauthenticated request to every API route returns 401.
2. **ISO completeness tests**: each mandatory documented-information item has a table, a write path and an export path — one test per row of the Phase 2 tables.
3. **Migration tests**: every migration applies to an empty DB and to a DB at each prior version; idempotency verified by applying twice.
4. **Concurrency tests**: two simultaneous register edits; optimistic locking rejects the stale write rather than silently clobbering.
5. **Property tests** for the risk scoring and gap calculation (Hypothesis) — the arithmetic behind a client's certification readiness should not rest on example-based tests alone.
6. **Accessibility tests**: axe-core against rendered pages in CI.
7. **Visual regression** on the dashboard and register surfaces.
8. **Rename release-named tests** to behaviour-named ones. Set a coverage floor of 60% and raise it each release.
9. **Type coverage**: add `mypy --strict` on `core/`, `grc/` and `persistence/` first, then widen.

---

# DELIVERABLES

For each phase, produce: the code, the tests, a migration (if schema changed), updated docs, and a short report stating what changed, what you verified, and what you could not verify in this environment. Be explicit about the last one — the existing release notes claim a passing test count that is wrong, and that kind of drift is exactly what a consulting tool cannot afford.
Start with Phase 0. It is roughly a day's work and it makes everything after it measurable.