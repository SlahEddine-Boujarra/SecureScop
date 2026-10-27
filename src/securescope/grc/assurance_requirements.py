"""Requirement-level rules for existing Control Profile implementation configuration."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from securescope.evidence.automated_checks import usable_evidence
from securescope.evidence.freshness import evidence_freshness
from securescope.grc.control_implementation import as_datetime, input_fingerprint

REQUIREMENT_TYPES = (
    "Technical",
    "Operational",
    "Governance",
    "Policy",
    "Documentary",
    "Process",
    "Physical",
    "Human",
)
RESULTS = ("PASS", "PARTIAL", "FAIL", "NO EVIDENCE", "UNKNOWN", "NOT APPLICABLE")
RULE_PROVIDERS = {
    "Manual validation": {"manual", "interview", "observation"},
    "Approved policy": {"policy"},
    "Recent vulnerability scan": {"nuclei", "openvas"},
    "Asset discovery": {"nmap", "asset_inventory"},
    "Log source coverage": {"wazuh", "siem"},
    "Monitoring coverage": {"wazuh"},
    "Clock synchronization": {"wazuh"},
    "Secure web configuration baseline": {"nuclei"},
    "Transport encryption configuration": {"nuclei"},
    "No default credentials on in-scope services": {"nuclei"},
    "Classification coverage": {"classification", "asset_inventory"},
    "Explicit configuration test": {"wazuh", "siem", "openscap", "prowler"},
}
AUTOMATED_METHODS = {"Existing worker", "Authenticated API", "Defensive local CLI"}
GROUPS = (
    "Control Implementation",
    "Policy / Governance",
    "Interested Party",
    "Legal / Regulatory",
    "Contractual",
    "Risk Treatment",
    "Internal Security",
)


def validate_requirements(requirements: list[dict]) -> list[dict]:
    """Validate structured profile criteria without accepting client-supplied results.

    Args:
        requirements: Criteria being versioned in an existing profile.
    Returns:
        Validated copies with normalized fields.
    Raises:
        ValueError: For invalid IDs, rules, types, thresholds or duplicate criteria.
    """
    if not isinstance(requirements, list) or len(requirements) > 100:
        raise ValueError("A profile supports at most 100 requirements.")
    result, identities = [], set()
    for item in requirements:
        row = dict(item)
        identity = str(row.get("id") or "")
        if not identity or len(identity) > 100 or identity in identities:
            raise ValueError("Each requirement needs a unique stable ID.")
        identities.add(identity)
        for key in ("title", "expected_result"):
            if not isinstance(row.get(key), str) or not row[key].strip() or len(row[key]) > 4000:
                raise ValueError(
                    f'Requirement {key.replace("_", " ")} is required (max 4000 characters).'
                )
        if row.get("type") not in REQUIREMENT_TYPES or row.get("rule") not in RULE_PROVIDERS:
            raise ValueError("Choose a supported requirement type and assessment rule.")
        if type(row.get("mandatory")) is not bool:
            raise ValueError("Choose whether the requirement is mandatory.")
        if type(row.get("allow_collection_health", False)) is not bool or (
            row.get("allow_collection_health") and row.get("rule") != "Monitoring coverage"
        ):
            raise ValueError("Collection-health proof is only valid for a monitoring requirement.")
        days = row.get("max_age_days", 90)
        threshold = row.get("threshold", 100)
        if type(days) is not int or not 1 <= days <= 3650:
            raise ValueError("Evidence maximum age must be 1–3650 days.")
        if type(threshold) not in (int, float) or not 1 <= threshold <= 100:
            raise ValueError("Coverage threshold must be between 1 and 100 percent.")
        if row.get("group", GROUPS[0]) not in GROUPS:
            raise ValueError("Choose a supported requirement group.")
        assets = row.get("asset_ids", [])
        policies = row.get("policy_ids", [])
        links = row.get("evidence_links", [])
        if (
            not isinstance(assets, list)
            or len(assets) > 1000
            or any(type(i) is not int or i <= 0 for i in assets)
        ):
            raise ValueError("Choose up to 1000 canonical asset IDs.")
        if (
            not isinstance(policies, list)
            or len(policies) > 100
            or any(not isinstance(i, str) or len(i) > 100 for i in policies)
        ):
            raise ValueError("Choose valid policy identities.")
        if not isinstance(links, list) or len(links) > 100:
            raise ValueError("Choose up to 100 evidence references.")
        for link in links:
            if (
                not isinstance(link, dict)
                or type(link.get("evidence_id")) is not int
                or link["evidence_id"] <= 0
            ):
                raise ValueError("Choose canonical evidence IDs.")
            if len(str(link.get("rationale") or "")) > 4000:
                raise ValueError("Evidence rationale must be at most 4000 characters.")
        row.pop("status", None)
        row.pop("result", None)
        from securescope.evidence.nuclei_assurance import RULE_VERSION, RULES

        if "nuclei_rule_version" in row or "nuclei_template_ids" in row:
            check = RULES.get(row["rule"])
            templates = row.get("nuclei_template_ids", [])
            if (
                not check
                or row.get("nuclei_rule_version") != RULE_VERSION
                or not isinstance(templates, list)
                or any(not isinstance(t, str) or t not in check.template_ids for t in templates)
            ):
                raise ValueError(
                    "Choose reviewed exact template predicates from the supported rule catalogue."
                )
        result.append(row)
    return result


def evaluate_requirement(requirement: dict, bundle: dict, now: datetime) -> dict:
    """Evaluate a criterion and expose incomplete source windows without a false PASS.

    Args:
        requirement: Authored criterion; bundle: Authorized scoped inputs; now: Aware clock.
    Returns:
        Derived check result; never modifies the inputs or a human decision.
    Raises:
        ValueError: Invalid evaluation input.
    """
    result = _evaluate_requirement(requirement, bundle, now)
    if (
        result.get("automated")
        and result["result"] == "PASS"
        and requirement["rule"] not in {"Approved policy", "Clock synchronization"}
        and any(e.get("evidence_window_incomplete") for e in bundle.get("requirement_evidence", []))
    ):
        result.update(
            result="UNKNOWN",
            reason_code="incomplete_evidence_window",
            reason="The bounded evidence window is incomplete; full coverage cannot be concluded.",
            recommended_action="Review the complete evidence history or narrow the selected context.",
        )
    return result


def _evaluate_requirement(requirement: dict, bundle: dict, now: datetime) -> dict:
    """Evaluate one requirement using approved mappings and provider-supported facts.

    Args:
        requirement: Versioned criterion configuration, including canonical evidence IDs.
        bundle: Authorized context, evidence metadata, policies and normalized observations.
        now: Explicit timezone-aware clock.
    Returns:
        Explainable result with evidence IDs, freshness and machine-verifiability.
    Raises:
        ValueError: If the clock is naive.
    """
    output = dict(
        requirement,
        result="NO EVIDENCE",
        reason="Collect and validate evidence for this requirement.",
        evidence_ids=[],
        automated=False,
        freshness="Missing",
    )
    rule = requirement["rule"]
    if rule == "Approved policy":
        documents = [
            d
            for d in bundle.get("documents", [])
            if d["policy_id"] in requirement.get("policy_ids", [])
        ]
        accepted = [
            d
            for d in documents
            if d.get("status") == "Approved"
            and (
                not d.get("review_date")
                or (
                    as_datetime(d["review_date"])
                    and as_datetime(d["review_date"]).date() >= now.date()
                )
            )
        ]
        if accepted:
            output.update(
                result="PASS",
                reason="Supported by approved policy: "
                + ", ".join(f"{d['title']} v{d['policy_version']}" for d in accepted),
                policy_versions=[
                    {"id": d["policy_id"], "version": d["policy_version"]} for d in accepted
                ],
                automated=True,
                freshness="Current",
            )
        else:
            output.update(
                reason="Create or link an approved policy. Drafts do not satisfy this requirement."
            )
        return output
    if rule == "Manual validation":
        assessment = bundle.get("assessment") or {}
        reviewed_at = as_datetime(assessment.get("created_at"))
        if (
            assessment.get("validation_status") == "Validated"
            and bundle.get("validator_authorized")
            and reviewed_at
            and now - timedelta(days=requirement.get("max_age_days", 90)) <= reviewed_at <= now
        ):
            criterion = next(
                (
                    c
                    for c in bundle.get("criteria", [])
                    if c.get("criterion_identifier") == requirement["id"]
                    and c.get("evidence_reference")
                ),
                None,
            )
            if criterion and criterion.get("result") in {"Pass", "Partial", "Fail"}:
                output.update(
                    result=criterion["result"].upper(),
                    reason="Authorized assessment: " + criterion["evidence_reference"],
                    freshness="Current",
                    assessment_id=assessment.get("id"),
                    automated=False,
                )
                return output
    if (
        rule not in {"Manual validation", "Approved policy"}
        and requirement.get("machine_verifiable") is not True
    ):
        output.update(
            result="UNKNOWN",
            reason="Candidate provider evidence requires a human review for this criterion.",
        )
        return output
    from securescope.evidence.nuclei_assurance import RULES, evaluate_nuclei

    if rule in RULES and (
        rule != "Recent vulnerability scan"
        or not any(e.get("tool_id") == "openvas" for e in bundle.get("requirement_evidence", []))
    ):
        return evaluate_nuclei(requirement, bundle, now, output)
    technical_rules = {
        "Secure web configuration baseline",
        "Transport encryption configuration",
        "No default credentials on in-scope services",
        "Monitoring coverage",
        "Clock synchronization",
        "Log source coverage",
    }
    if rule in technical_rules:
        return evaluate_technical_requirement(requirement, bundle, now, output)
    if rule in {"Recent vulnerability scan", "Asset discovery"} and not requirement.get(
        "asset_ids"
    ):
        output.update(
            result="UNKNOWN",
            reason="No assets are assigned to this requirement. "
            "Choose the assets this scan must cover.",
        )
        return output
    candidates = {e["id"]: e for e in bundle.get("requirement_evidence", [])}
    results = []
    covered_assets = set()
    coverage_evidence = []
    bindings = requirement.get("evidence_links", [])
    if requirement.get("follow_provider") and rule != "Manual validation":
        latest = {}
        for evidence in sorted(
            candidates.values(), key=lambda e: str(e.get("collected_at") or ""), reverse=True
        ):
            if str(evidence.get("tool_id", "")).lower() in RULE_PROVIDERS[rule]:
                latest.setdefault(
                    (evidence["tool_id"], evidence.get("source_asset_or_system", "")), evidence
                )
        bindings = [{"evidence_id": e["id"]} for e in latest.values()]
    # Deterministic system mappings need no per-scan manual requirement binding.
    bindings = list(bindings)
    bound_ids = {b.get("evidence_id") for b in bindings}
    for evidence in candidates.values():
        if (
            evidence.get("verification_origin") == "System collector"
            and evidence["id"] not in bound_ids
        ):
            metadata = (evidence.get("normalized_payload") or {}).get("metadata", {})
            if any(
                c.get("effect") == "supports" and rule in c.get("mapped_requirements", [])
                for c in metadata.get("automated_checks", [])
            ):
                bindings.append({"evidence_id": evidence["id"]})
    for binding in bindings:
        evidence = candidates.get(binding.get("evidence_id"))
        if (
            not evidence
            or evidence.get("scope_id") != bundle.get("scope_id")
            or evidence.get("engagement_id") != bundle.get("engagement_id")
        ):
            continue
        if (
            "eligible_requirement_ids" in evidence
            and requirement["id"] not in evidence["eligible_requirement_ids"]
        ):
            continue
        if not usable_evidence(evidence, RULE_PROVIDERS[rule]):
            continue
        if evidence.get("verification_origin") == "System collector":
            checks = (
                (evidence.get("normalized_payload") or {})
                .get("metadata", {})
                .get("automated_checks", [])
            )
            if not any(
                c.get("effect") == "supports"
                and rule in c.get("mapped_requirements", [])
                and (
                    not evidence.get("control_id")
                    or evidence["control_id"] in c.get("mapped_controls", [])
                )
                for c in checks
            ):
                continue
        provider = str(evidence.get("tool_id", "")).lower()
        if provider not in RULE_PROVIDERS[rule]:
            continue
        freshness = evidence_freshness(evidence, requirement.get("max_age_days", 90), now)
        if freshness in {"Unknown", "Stale"}:
            output.update(
                freshness=freshness,
                reason=(
                    "Evidence is stale or its collection time is unknown. Refresh " "and review it."
                ),
            )
            continue
        result, reason = "UNKNOWN", "The source does not provide the facts required by this rule."
        automated = (
            evidence.get("collection_method") in AUTOMATED_METHODS
            and requirement.get("machine_verifiable") is True
        )
        facts = (evidence.get("normalized_payload") or {}).get("metadata", {}).get(
            "assurance"
        ) or {}
        # Provider facts are not guessed from a clean/empty scanner report.
        if rule == "Manual validation":
            result = binding.get("conclusion", "UNKNOWN")
            reason = binding.get("rationale") or "No validation rationale recorded."
            if result not in {"PASS", "PARTIAL", "FAIL"} or not binding.get("rationale"):
                result = "UNKNOWN"
            automated = False
        elif rule in {"Recent vulnerability scan", "Asset discovery"}:
            if (
                facts.get("complete") is True
                and facts.get("asset_ids")
                and requirement.get("asset_ids")
            ):
                expected = set(requirement["asset_ids"])
                matching = expected.intersection(facts["asset_ids"])
                if matching:
                    covered_assets.update(matching)
                    coverage_evidence.append(
                        dict(evidence_id=evidence["id"], freshness=freshness, automated=automated)
                    )
            elif facts.get("complete") is False:
                result, reason = "PARTIAL", "The provider reports an incomplete collection."
        elif rule in {"Log source coverage", "Classification coverage"}:
            fact_key = "logging" if rule == "Log source coverage" else "classification"
            coverage = facts.get(fact_key) or {}
            expected = set(requirement.get("asset_ids") or [])
            observed = set(coverage.get("evaluated_asset_ids") or [])
            positive = set(coverage.get("satisfied_asset_ids") or [])
            if expected and expected.issubset(observed):
                ratio = 100 * len(expected & positive) / len(expected)
                result = (
                    "PASS"
                    if ratio >= requirement.get("threshold", 100)
                    else "PARTIAL" if ratio else "FAIL"
                )
                reason = (
                    f"{len(expected & positive)} / {len(expected)} "
                    "configured assets satisfy the requirement."
                )
                output.update(
                    affected_assets=sorted(expected - positive),
                    verified_assets=len(expected & positive),
                    applicable_assets=len(expected),
                )
        elif rule == "Explicit configuration test":
            test = (facts.get("tests") or {}).get(requirement.get("test_key"))
            if type(test) is bool:
                result, reason = (
                    ("PASS", "Provider explicitly reports the configured test passed.")
                    if test
                    else ("FAIL", "Provider explicitly reports the configured test failed.")
                )
        results.append(
            dict(
                result=result,
                reason=reason,
                evidence_id=evidence["id"],
                collected_at=evidence.get("collected_at"),
                automated=automated,
                freshness=freshness,
            )
        )
    if rule in {"Recent vulnerability scan", "Asset discovery"} and requirement.get("asset_ids"):
        expected = set(requirement["asset_ids"])
        percent = 100 * len(covered_assets) / len(expected)
        output.update(
            verified_assets=len(covered_assets),
            applicable_assets=len(expected),
            affected_assets=sorted(expected - covered_assets),
            coverage_percent=round(percent, 1),
            result=(
                "PASS"
                if percent >= requirement.get("threshold", 100)
                else "PARTIAL" if covered_assets else "NO EVIDENCE"
            ),
            reason=f"{len(covered_assets)} / {len(expected)} configured assets "
            "have a current completed collection. "
            "This proves collection coverage, not absence of vulnerabilities.",
            evidence_ids=[r["evidence_id"] for r in coverage_evidence],
            automated=bool(coverage_evidence) and all(r["automated"] for r in coverage_evidence),
        )
        if coverage_evidence:
            output["freshness"] = (
                "Expiring Soon"
                if any(r["freshness"] == "Expiring Soon" for r in coverage_evidence)
                else "Current"
            )
        return output
    if results:
        # Contradictory current evidence wins over a positive observation; it cannot be hidden.
        rank = {"FAIL": 0, "PARTIAL": 1, "UNKNOWN": 2, "PASS": 3}
        selected = min(results, key=lambda r: rank[r["result"]])
        output.update(
            selected,
            evidence_ids=[r["evidence_id"] for r in results],
            observations=results,
            automated=all(r["automated"] for r in results),
        )
    return output


def evaluate_assurance(bundle: dict, *, now: datetime) -> dict[str, Any]:
    """Calculate separate applicability, implementation, evidence and assurance dimensions.

    Args:
        bundle: Canonical scoped profile, evidence, policies, assessment and blockers.
        now: Explicit evaluation clock.
    Returns:
        Explainable derived state; this never approves governance decisions.
    Raises:
        ValueError: For invalid criteria or timestamp.
    """
    config = (bundle["profile"].get("assessment_scope") or {}).get(
        "implementation_requirements"
    ) or {}
    requirements = validate_requirements(config.get("requirements", []))
    results = [evaluate_requirement(r, bundle, now) for r in requirements]
    mandatory = [r for r in results if r["mandatory"]]
    measured = [r for r in mandatory if r["result"] in {"PASS", "PARTIAL", "FAIL"}]
    passed = sum(r["result"] == "PASS" for r in mandatory)
    failures = sum(r["result"] == "FAIL" for r in mandatory)
    coverage = round(100 * len(measured) / len(mandatory), 1) if mandatory else None
    implementation = "Insufficient Evidence" if requirements else "Not Assessed"
    if mandatory and passed == len(mandatory):
        implementation = "Implemented"
    elif measured and len(measured) == failures == len(mandatory):
        implementation = "Not Implemented"
    elif any(r["result"] in {"PASS", "PARTIAL", "FAIL"} for r in mandatory):
        implementation = "Partially Implemented"
    advisory_implementation = implementation
    soa = bundle.get("soa") or {}
    applicability = (
        "Not Applicable"
        if soa.get("applicability") == "Not applicable"
        and soa.get("approved")
        and soa.get("exclusion_justification")
        else "Applicable" if soa.get("applicability") == "Applicable" else "Pending"
    )
    blockers = list(bundle.get("blockers", []))
    if config.get("baseline_review_pending") or config.get("baseline_preview"):
        blockers.append(
            "Review the authored baseline requirements for this organization and scope."
        )
    if not config.get("continuous_auto_assurance"):
        blockers.append("Continuous Auto-Assurance is off.")
    if applicability != "Applicable":
        blockers.append("Formal applicability is not confirmed as Applicable.")
    if not mandatory or passed != len(mandatory):
        blockers.append("Mandatory requirements are unresolved.")
    if any(not r["automated"] for r in mandatory):
        blockers.append("A mandatory requirement requires human validation.")
    if any(r["freshness"] != "Current" for r in mandatory):
        blockers.append("Mandatory evidence is missing, stale or expiring.")
    if not config.get("scope_version_id") or config.get("scope_version_id") != (
        bundle.get("scope") or {}
    ).get("id"):
        blockers.append("Requirements must be reviewed against the current scope version.")
    if not (bundle.get("scope") or {}).get("status") == "Approved":
        blockers.append("The ISMS Scope is not approved.")
    if not bundle.get("safety_signals_complete"):
        blockers.append(
            "Contradictory findings, exceptions or remediation coverage is not verified."
        )
    assessment = bundle.get("assessment") or {}
    recorded_at = as_datetime(assessment.get("created_at"))
    current_human = bool(
        assessment.get("validation_status") == "Validated"
        and bundle.get("validator_authorized")
        and recorded_at
        and now - timedelta(days=config.get("review_days", 90)) <= recorded_at <= now
    )
    if (
        current_human
        and assessment.get("assessment_status") in {"Implemented and effective", "Target achieved"}
        and not failures
    ):
        implementation = "Implemented"
    if applicability == "Not Applicable":
        implementation = "Not Applicable"
    assurance = "Not Assessed" if not assessment else "Needs Review"
    if not blockers:
        assurance = "Effective"
    elif (
        assessment.get("validation_status") == "Validated"
        and bundle.get("validator_authorized")
        and as_datetime(assessment.get("created_at"))
        and now - timedelta(days=config.get("review_days", 90))
        <= as_datetime(assessment["created_at"])
        <= now
    ):
        if (
            assessment.get("assessment_status") == "Implemented and effective"
            and implementation == "Implemented"
            and coverage == 100
            and all(r["freshness"] == "Current" for r in mandatory)
            and not bundle.get("blockers")
        ):
            assurance = "Effective"
        elif failures:
            assurance = "Ineffective" if failures == len(mandatory) else "Partially Effective"
    if not current_human:
        if implementation == "Implemented":
            implementation = "Not Assessed"
        if bundle.get("requirement_evidence"):
            assurance = "Needs Review"
        blockers.append(
            "Evidence supports facts; a human must record the final assurance decision."
        )
    assessed_at = as_datetime(assessment.get("created_at"))
    policy_changed = any(
        as_datetime(d.get("updated_at"))
        and (not assessed_at or as_datetime(d["updated_at"]) > assessed_at)
        for d in bundle.get("documents", [])
        if any(d["policy_id"] in r.get("policy_ids", []) for r in requirements)
    )
    if policy_changed and assessment:
        assurance = "Needs Review"
    m3_checks = [r for r in results if r.get("rule_version") == 3]
    changed_technical_facts = bool(
        m3_checks
        and assessment
        and any(
            r["result"] != "PASS"
            or r["freshness"] != "Current"
            or any(
                (as_datetime(f.get("acquired_at")) or now) > (recorded_at or now)
                for f in r.get("observations", [])
            )
            for r in m3_checks
        )
    )
    if changed_technical_facts:
        assurance = "Needs Review"
        blockers.append(
            "Technical evidence requires review; the recorded human decision is unchanged."
        )
    return dict(
        applicability=applicability,
        implementation=implementation,
        advisory_implementation=advisory_implementation,
        human_assessment=dict(
            status=assessment.get("assessment_status") or "Not assessed",
            validation_status=assessment.get("validation_status") or "Not assessed",
            recorded_at=recorded_at.isoformat() if recorded_at else None,
            current=current_human,
        ),
        technical_review_required=changed_technical_facts,
        assurance=assurance,
        evidence_status=(
            "Not Configured"
            if not requirements
            else (
                "Stale"
                if any(r["freshness"] == "Stale" for r in mandatory)
                else "Sufficient" if coverage == 100 else "Partial" if measured else "Missing"
            )
        ),
        evidence_coverage=coverage,
        requirements=results,
        mandatory_count=len(mandatory),
        satisfied=passed,
        assessed=bool(assessment),
        auto_verified=not blockers,
        automation_blockers=blockers,
        policy_changed=policy_changed,
        evaluated_at=now.isoformat(),
        input_fingerprint=input_fingerprint(bundle),
        baseline_preview=bool(config.get("baseline_preview")),
        engine_version=2,
    )


def assurance_metrics(results: list[dict]) -> dict:
    """Aggregate independent metrics without reporting missing assessments as noncompliance.

    Args:
        results: Current scoped assurance evaluations.
    Returns:
        Counts and percentages; missing denominators remain None.
    Raises:
        KeyError: For malformed evaluation results.
    """
    applicable = [r for r in results if r["applicability"] == "Applicable"]
    assessed = [r for r in applicable if r["assessed"]]
    required = sum(r["mandatory_count"] for r in applicable)
    return dict(
        applicable=len(applicable),
        assessed=len(assessed),
        implementation_coverage=(
            100 * sum(r["implementation"] == "Implemented" for r in applicable) / len(applicable)
            if applicable
            else None
        ),
        assessment_coverage=100 * len(assessed) / len(applicable) if applicable else None,
        evidence_coverage=(
            sum((r["evidence_coverage"] or 0) * r["mandatory_count"] for r in applicable) / required
            if required
            else None
        ),
        effectiveness_rate=(
            100 * sum(r["assurance"] == "Effective" for r in assessed) / len(assessed)
            if assessed
            else None
        ),
    )


def apply_safety_signals(bundle: dict, now: datetime) -> None:
    """Derive safety prerequisites identically for workspace, dashboard and worker.

    Args:
        bundle: Scoped normalized evidence plus canonical contradiction/action blockers.
        now: Current timezone-aware evaluation timestamp.
    Returns:
        None; adds complete-signal and provider-blocker fields to the input bundle.
    Raises:
        ValueError: For a naive timestamp.
    """
    config = (bundle["profile"].get("assessment_scope") or {}).get(
        "implementation_requirements"
    ) or {}
    asset_ids = {i for r in config.get("requirements", []) for i in r.get("asset_ids", [])}
    bundle["safety_signals_complete"] = False
    bundle.setdefault("blockers", [])
    for evidence in bundle.get("requirement_evidence", []):
        facts = (evidence.get("normalized_payload") or {}).get("metadata", {}).get(
            "assurance"
        ) or {}
        safety = facts.get("safety") or {}
        if (
            asset_ids
            and asset_ids.issubset(safety.get("evaluated_asset_ids", []))
            and evidence.get("validation_status") == "Validated"
            and evidence.get("mapping_approved")
            and evidence.get("collection_method") in AUTOMATED_METHODS
            and evidence.get("scope_id") == bundle.get("scope_id")
            and evidence.get("engagement_id") == bundle.get("engagement_id")
            and evidence_freshness(evidence, 30, now) == "Current"
        ):
            checks = (
                "exceptions_present",
                "critical_remediation_overdue",
                "contradictory_findings_present",
            )
            if all(type(safety.get(check)) is bool for check in checks):
                bundle["safety_signals_complete"] = True
                bundle["blockers"].extend(
                    check.replace("_", " ") for check in checks if safety[check]
                )


def evaluate_technical_requirement(requirement, bundle, now, output):
    """Evaluate explicit per-asset facts, never infer a pass from absent findings.

    Args:
        requirement: Canonical criterion with rule and configured asset IDs.
        bundle: Authorized scope evidence and context.
        now: Aware evaluation time.
        output: Initial presentation result.
    Returns:
        Requirement result with per-asset states and current evidence references.
    Raises:
        ValueError: If the evaluation clock is naive.
    """
    rule = requirement["rule"]
    expected = set(requirement.get("asset_ids") or [])
    states = {asset: "NOT COLLECTED" for asset in expected}
    used, fresh = [], []
    candidate_seen = False
    discovered_gaps = set()
    for evidence in bundle.get("requirement_evidence", []):
        if (
            "eligible_requirement_ids" in evidence
            and requirement["id"] not in evidence["eligible_requirement_ids"]
        ):
            continue
        if (
            evidence.get("scope_id") != bundle.get("scope_id")
            or evidence.get("engagement_id") != bundle.get("engagement_id")
            or not usable_evidence(evidence, RULE_PROVIDERS[rule])
        ):
            continue
        if (
            evidence.get("verification_origin") != "System collector"
            and not requirement.get("follow_provider")
            and evidence["id"]
            not in {b["evidence_id"] for b in requirement.get("evidence_links", [])}
        ):
            continue
        currency = evidence_freshness(evidence, requirement.get("max_age_days", 90), now)
        if currency in {"Stale", "Unknown"}:
            output["freshness"] = currency
            continue
        metadata = (evidence.get("normalized_payload") or {}).get("metadata", {})
        facts = metadata.get("assurance") or {}
        checks = [
            c
            for c in metadata.get("automated_checks", [])
            if rule in c.get("mapped_requirements", [])
            and (
                not evidence.get("control_id")
                or evidence["control_id"] in c.get("mapped_controls", [])
            )
        ]
        candidate_seen = True
        observations = {}
        if evidence.get("tool_id") == "nuclei":
            if any(c.get("effect") == "gap" for c in checks):
                observations = {a: "FAIL" for a in facts.get("asset_ids", [])}
                discovered_gaps.update(observations)
            # Explicit tested asset results may support a pass; a clean JSONL alone cannot.
            test = (facts.get("technical_checks") or {}).get(rule, {})
        else:
            key = {
                "Log source coverage": "logging",
                "Monitoring coverage": "monitoring",
                "Clock synchronization": "clock",
            }[rule]
            test = facts.get(key, {}) if checks or evidence.get("mapping_approved") else {}
        for asset in test.get("evaluated_asset_ids", []):
            observations.setdefault(
                asset, "PASS" if asset in test.get("satisfied_asset_ids", []) else "FAIL"
            )
        if observations:
            used.append(evidence["id"])
            fresh.append(currency)
            for asset in expected.intersection(observations):
                if states[asset] != "FAIL":
                    states[asset] = observations[asset]
    failed = [a for a, state in states.items() if state == "FAIL"]
    passed = [a for a, state in states.items() if state == "PASS"]
    result = (
        "FAIL"
        if (failed and not passed) or discovered_gaps.intersection(expected)
        else (
            "PASS"
            if states and len(passed) == len(states)
            else "PARTIAL" if passed else "NO EVIDENCE"
        )
    )
    reason = f"{len(passed)} / {len(expected)} configured assets meet the technical criterion."
    if not expected:
        result = "FAIL" if discovered_gaps else "UNKNOWN"
        reason = ("Technical gaps detected. " if discovered_gaps else "") + (
            "No assets are assigned to this requirement. Choose the assets this scan must cover."
        )
    elif not used:
        result = "UNKNOWN" if candidate_seen else "NO EVIDENCE"
        reason = "NOT COLLECTED: no current explicit check results cover the configured assets."
    output.update(
        result=result,
        reason=reason,
        asset_results=states,
        evidence_ids=sorted(set(used)),
        verified_assets=len(passed),
        applicable_assets=len(expected),
        affected_assets=sorted(a for a, state in states.items() if state != "PASS"),
        automated=bool(used),
    )
    if fresh:
        output["freshness"] = "Expiring Soon" if "Expiring Soon" in fresh else "Current"
    return output
