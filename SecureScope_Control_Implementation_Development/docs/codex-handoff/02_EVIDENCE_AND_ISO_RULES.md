# Evidence-first functional specification and ISO safety rules

## Minimal evidence processing contract
`authorized_source -> source health/check -> collection job -> source artifact/observation -> canonical event -> normalized evidence + SHA-256/provenance -> verified asset + verified approved scope -> requirement-specific deterministic check -> coverage/gap UI -> human ISO assessment`

Canonical source/evidence attributes to retain or link: client/workspace ID, engagement ID, known scope ID, stable asset ID, source/provider and stable external ID, collection time, scan/execution ID, ingestion time, raw artifact pointer (protected), sha256, normalized record schema version, check ID/version, matched requirement/control IDs, effect (`supports`,`gap`,`informational`), mapped scope confidence/justification, freshness/expiry policy, collector outcome, audit actor/process. Reuse existing schema; introduce fields additively only if necessary.

### Scanner specifics
- Nmap finds candidates, services and exposures; asset admission must be authorized and reviewed. Nmap discovery by itself does not prove a control passed or an asset is approved in scope.
- Nuclei: worker executes authorized targets only; JSONL is kept as raw source; scan is completed even with zero findings; canonical coverage evidence is recorded per successfully scanned asset and deduplicated by source/job identity. Preserve template IDs, CVE, severity and scope context.
- A.8.8: completed scan supports **current vulnerability assessment**. Separately require vulnerability triage and remediation verification. Found CVE can show a gap; zero findings are not sufficient to pass a negative test unless that test actually ran.
- A.8.9: observed configuration weaknesses can show a **gap**. A.8.24: observed TLS/certificate weaknesses can show a **gap**. A.8.5: observed default-authentication weakness can show a **gap**. No issue reported != compliant.
- Only classify allowlisted template IDs and defensible semantic mappings. Avoid overclaiming for arbitrary broad Nuclei tags.

### Wazuh and SIEM asset monitoring
1. Obtain Wazuh agent registry and current state using existing connector. Identity matching: explicit stable source identifiers or unambiguous exact mappings to inventory; duplicate IPs, DHCP, NAT, hostname collisions or fuzzy candidates -> `Not verified / Needs mapping`.
2. Determine independent dimensions: `agent_registered`, `agent_connection`, `last_keepalive`, `telemetry_collected`, `last_verified_observation`, `collection_health`, `monitoring_state`, `reason`, `freshness`, and `scope_verified`. Do not collapse them into one boolean.
3. Suggested derived states:
   - `Monitoring verified`: exact asset/agent match, current healthy connection AND authenticated relevant telemetry/collection-health evidence within policy window.
   - `Agent active — telemetry unverified`: heartbeat verified; required security observations/health not established.
   - `Monitoring stale`: previously confirmed monitoring no longer current per configured interval.
   - `Agent disconnected`: explicitly matched and API reports disconnected.
   - `Not verified`: no match, conflicting identity, missing data, failed API access, or insufficient proof.
4. Absence of security **alerts** alone does not imply failed monitoring; use heartbeat, log-source collection metadata and explicit health/synthetic check when available. Do not assume indexer endpoints/permissions are configured; support API-only evidence honestly.
5. Produce snapshots, collection errors, freshness status and change log per workspace/asset. UI shows *why* status is what it is and last verified timestamp; no unknown-to-red false assertion.
6. Wazuh bridge supports A.8.15 Logging only for actual relevant log-source/event evidence; A.8.16 Monitoring only for actual monitoring evidence; A.8.17 Clock synchronization only for actual clock synchronization observations. Agent presence does not prove any other ISO requirement.
7. Periodic collection through existing approved job/evidence infrastructure; no new dedicated Wazuh worker unless current code and scaling justify it and user approves. Retry with backoff; deduplicate; no cross-tenant bleed.

### ISO/IEC 27001:2022 business semantics
- ISO clauses 4–10 constitute the ISMS lifecycle. Annex A has 93 controls (A.5=37, A.6=8, A.7=14, A.8=34), *not 93 automatic scan tests*. The SoA must justify applicability and exclusions; additional selected controls outside Annex A may be relevant.
- Keep controlled SoA drafts separate from approved versions. Risk treatment/acceptance remains human reviewed. Requirements mapping includes asset/scope links and a human assessment record; automatic facts affect *coverage and gaps*, never auto-finalize approval.
- Clause 9.1 performance monitoring/measurement, 9.2 internal audit, 9.3 management review, 10.2 corrective action, 7.2 competence, 7.3 awareness, 7.4 communications, 6.3 changes, and 7.5 documented-information control should be assessed for real lifecycle support; do not assume these are absent if repo has partial features.
- Organizational classification of assets: operational criticality and information sensitivity separate; audit trail/owner/methodology, no automatic scope inference.

### Data and UI consistency
- Technical checks use truth categories: Not assessed, Not verified, Current evidence, Partial coverage, Evidence gap, Source unavailable, Stale evidence. A human status is separate (e.g. draft / assessed / approved and implementation/effectiveness).
- The consultant sees: what was tested, on which scoped assets, when, by which source, which artifact/check supports this, what remains missing, and what action follows.
- Verified automated provenance should not require consultant reapproval solely to enter the Evidence Register. Manual/imported proof may require review.
