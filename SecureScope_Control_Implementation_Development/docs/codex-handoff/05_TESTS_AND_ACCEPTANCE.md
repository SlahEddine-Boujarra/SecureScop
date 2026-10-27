# Security, auditability and UX acceptance tests

## Mandatory test matrix

### Wazuh/monitoring
- No exact matching agent: **Not verified**; never assume unmonitored.
- Matched active agent with recent heartbeat but no verified collection: **Agent active — telemetry unverified**.
- Matched agent disconnected: **Agent disconnected**, carrying last-observed time.
- Previously verified observation outside configured policy: **Monitoring stale**.
- Current relevant log/telemetry from exact asset: **Monitoring verified** according to explicit rules and source-health policy.
- No security alerts but valid health/collection data: do not incorrectly downgrade to unmonitored.
- Duplicate IP, fuzzy hostname, changing IP, unknown scope, missing agent ID: do not silently map to arbitrary asset or scope.
- API/indexer timeouts: show source error/unknown; no stale success masquerading as current.
- A.8.16 support not conflated with final Implemented/effective; A.8.15/A.8.17 explicit source-specific proof only.

### Nuclei/evidence
- Successful zero-finding authorized scan creates one canonical completed-scan evidence record with verified artifact/source and tested asset reference. No inferred universal PASS.
- Same scan result processed twice: idempotent, no duplicate canonical evidence or extra control links.
- JSONL retained, protected and hash-verifiable; failed and cancelled jobs never count as successful collection.
- Run to different workspace: no cross-tenant evidence/view or scope links.
- A.8.8 current scan evidence vs separate triage and remediation verification; A.8.9/A.8.24/A.8.5 positive findings can indicate a gap, not lack-of-finding compliance.
- Freshness by requirement/source policy with explicit stale handling; backfill is repeatable and safe.

### Governance / user access
- SoA draft vs approved applicability cannot be confused, unjustified exclusions never treated approved.
- Approved Scope / Policy versions stay immutable; version history remains accessible even if library view is compact.
- Human assessment persisted with actor/time/rationale, distinct from source evidence and auto-checks.
- Tenant/engagement/scope access boundaries checked for reads, filters, exports, mutations, scheduled jobs.
- Controlled administrator bootstrap: no open self-grant path; don't assume an admin exists.
- Audit scope, management reviews, internal audits and corrective actions have appropriate human sign-off if supported.

### UX regressions
- Policy suggestions pane inserts into editable document, saves draft and preserves approved version; actual Word/PDF exports use existing services.
- Asset tag, asset classification (criticality vs information class), sync state, Nmap discovery admission, safe scan builder and Nuclei Scan Workspace function.
- SIEM full-width table with single compact Wazuh actions menu. Detailed evidence inspector shows source, mappings, provenance, freshness, scope and record hash.
- Original risk register + inherent/residual matrices clickable; three compact risk KPIs and scope context selector.
- Responsive desktop and mobile screenshots; no horizontal clipping, icon collisions, orphaned buttons or inaccessible menu states.

## Commands (adapt to actual checked-out repo)
```powershell
$env:PYTHONPATH = '.\\src'
python -m compileall -q src tests
python -m pytest -q
python -m pip check
```
The source README and `START_HERE.md` may describe additional validations. Database tests must point to a dedicated test DB, **never production**. If tests are blocked by missing runtime services, state the blocker and avoid marking the feature passed.

## Definition of done / review evidence
Provide changed-file list, migrations, before/after behavior, authorized demo/test data only, permission and tenant-isolation results, failure/retry behavior, screenshots, and exact test commands with pass/fail output. Do not claim ISO certified, compliant, or fully automatic for untested checks.
