# M3 rule catalogue and eligibility

Registry version 3. These are SecureScope-authored technical criteria; the ISO standard's normative text is not reproduced.

| Check | Control | Predicate | Permitted conclusion |
|---|---|---|---|
| `nuclei.scan.completed` | A.8.8 | Canonical completed scan; retained valid JSONL; exact approved asset/criterion; current source | PASS/PARTIAL/NO EVIDENCE for scan coverage, including empty JSONL |
| `nuclei.web.configuration` | A.8.9 | Reviewed IDs: `http-missing-security-headers`, `weak-content-security-policy`, `weak-csp`, `missing-x-frame-options`, `cookies-without-httponly` | Positive exact finding identifies a technical gap in that approved criterion |
| `nuclei.tls.configuration` | A.8.24 | Reviewed IDs: `ssl-expired`, `ssl-mismatched`, `ssl-self-signed`, `ssl-weak-cipher`, `ssh-weak-algo` | Positive exact condition supports a narrow gap; self-signed/mismatched requires context review |
| `nuclei.authentication` | A.8.5 | Reviewed IDs: `grafana-default-login`, `tomcat-default-login` | Positive exact finding identifies a default-credential gap; no claims about MFA or all authentication |
| `nuclei.vulnerability` | A.8.8 | Exact identifier matching `cve-YYYY-NNNN...` | Vulnerability observation only; no automatic remediation or whole-control failure |

Catalogue IDs are not a promise that a particular installed Nuclei template release supplies each ID. Unsupported/renamed IDs are not guessed. The Grafana ID is grounded in the ProjectDiscovery template repository (`https://github.com/projectdiscovery/nuclei-templates/blob/main/http/default-logins/grafana/grafana-default-login.yaml`); the Tomcat ID appears in its release history (`https://github.com/projectdiscovery/nuclei-templates/releases`). No remote template execution was performed.

Template choice plus rule version is stored in the reviewed criterion. Version 3 defaults apply only to these four controls. Upgrading a customized version-2 profile preserves its edits and removed criteria, marks review pending and requires the reviewer to choose approved exact predicates. Other templates retain version 2, including A.8.17.

## Eligibility truth table

| Candidate condition | Current automated use | History |
|---|---|---|
| Correct tenant + canonical asset + completed source + valid bytes + pinned current criterion | Eligible, subject to freshness and exact supported predicate | Retained |
| Another workspace, asset, engagement, scope, requirement or profile | Denied | No cross-owner association created |
| Same IP in another workspace | Denied by canonical tenant/asset identity | Independent records |
| Originating requirement in scope A, same asset also in B | Only captured origin A | No scope B fan-out |
| Generic scan with multiple explicitly approved criteria | Each exact captured criterion may receive attribution | Separate immutable attributions |
| New profile appears while a job is running | Old snapshot cannot target new profile | Canonical source retained, no current new-profile use |
| New disabled/review-pending profile | Denied; no older-profile fallback | Old attribution retained |
| New draft scope with unchanged approved pointer | Existing approved version remains current | Draft retained separately |
| Approved scope pointer replaced | Old version denied | Old source and association retained |
| Criterion changed in place | Digest mismatch denies use | Source facts retained |
| Artifact altered/missing, source/job identity changed, job no longer Completed | Denied on read | Record retained for investigation |
| Foreign or missing endpoint, invalid/future finding timestamp | Finding excluded; scan completeness not asserted from suspect rows | Raw bytes retained |
| Unsupported template or misleading tags | No technical predicate authorization | Raw finding retained; an otherwise valid completed scan can still support coverage |
| No configured assets | UNKNOWN; candidate observations may be inspected | No invented denominator |
| Source expired, future-dated or absent | No current coverage | Original time never refreshed by replay |
| Successful empty artifact | A.8.8 coverage only | New observation; no remediation closure |
| Arbitrary user `technical_checks` or negative-result JSON | Not trusted as Nuclei proof | Retained artifact is independently parsed |
| More than 500 relevant summaries | UNKNOWN for optimistic automated coverage | Complete evidence history remains in Evidence Register |
| Manual criterion / unsupported provider claim | Existing human-review path | Decisions remain authoritative |

Control Profile version selection is intentionally **per workspace, control and ISMS scope**, not one global version across controls/scopes. Engagement and the scope's current approved version must match. Selecting the latest scoped profile before testing its enabled/review state prevents fallback to an older enabled profile.

## Output contract

Each M3 technical result includes criterion/version, rule/version, profile/version, engagement/scope/version, expected/evaluated/missing/affected asset IDs, evidence IDs, exact source keys, retained SHA-256, source and acquisition times, effective expiration, freshness, reason code and recommended action. JSON asset-result keys are strings. Observations and exclusions are separate. Current technical traces do not overwrite source artifacts or saved human decisions.

Main reason codes: `assets_unassigned`, `mapping_review_required`, `observed_technical_gap`, `explicit_negative_test_unavailable`, `incomplete_evidence_window`, `scan_coverage`, `eligible_evidence_missing`. Artifact/job failures and stale findings additionally appear in per-evidence exclusion reasons. Advisory implementation and recorded human status are separate fields.

A.8.15/A.8.16 continue using existing M2 contracts. A quiet agent supports A.8.16 only with qualified collection-health/event proof; active status and zero-alert queries alone do not qualify. A.8.17 uses its existing dedicated clock path unchanged.
