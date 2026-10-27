"""Versioned, source-backed Nuclei facts; no inferred negative tests or human decisions."""

import hashlib
import json
from datetime import timedelta, timezone
from urllib.parse import urlsplit

from securescope.evidence.automated_checks import CHECKS, SCAN_COMPLETED, classify_nuclei
from securescope.grc.control_implementation import as_datetime

RULE_VERSION = 3
RULES = {r: c for c in (SCAN_COMPLETED, *CHECKS) for r in c.mapped_requirements}
CONTROLS = {c for check in RULES.values() for c in check.mapped_controls}


def canonical_digest(value: dict) -> str:
    """Hash JSON-compatible source facts; return SHA-256; raise TypeError for invalid values."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def source_facts(content: bytes, asset_id: int, target: str, observed_at) -> dict:
    """Derive bounded facts from retained JSONL, never from submitted assurance JSON.

    Args:
        content: Exact retained bytes; asset_id: Canonical job asset; target: Exact job address.
        observed_at: Canonical source collection timestamp.
    Returns:
        Coverage facts and qualified positive observations with excluded-observation reasons.
    Raises:
        ValueError: On malformed JSONL, missing time or an oversized source.
    """
    observed = as_datetime(observed_at)
    if not observed or len(content) > 25 * 1024 * 1024:
        raise ValueError("Unsupported Nuclei source size or timestamp.")
    observed = observed.astimezone(timezone.utc)
    facts = dict(
        version=RULE_VERSION,
        asset_id=asset_id,
        target=target,
        observed_at=observed.isoformat(),
        complete=True,
        observations=[],
        excluded=[],
    )
    for index, line in enumerate(content.decode("utf-8").splitlines()):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or not isinstance(item.get("template-id"), str):
            raise ValueError("A Nuclei finding must have a template identity.")
        identity = item["template-id"].strip().lower()
        endpoint = str(item.get("matched-at") or item.get("host") or "")
        try:
            host = urlsplit(endpoint if "://" in endpoint else "//" + endpoint).hostname
        except ValueError:
            host = None
        # An IP supplied alongside a foreign endpoint does not authorize that endpoint.
        exact = host == target or (not endpoint and item.get("ip") == target)
        timestamp = as_datetime(item.get("timestamp")) if item.get("timestamp") else observed
        if timestamp:
            timestamp = timestamp.astimezone(timezone.utc)
        checks = classify_nuclei(identity)
        reason = (
            "target_unverified"
            if not exact
            else (
                "timestamp_invalid"
                if not timestamp or timestamp > observed
                else "unsupported_template" if not checks else ""
            )
        )
        if reason:
            facts["excluded"].append(dict(line=index + 1, template_id=identity, reason=reason))
            if reason in {"target_unverified", "timestamp_invalid"}:
                facts["complete"] = False
            continue
        for check in checks:
            facts["observations"].append(
                dict(
                    line=index + 1,
                    template_id=identity,
                    check_id=check.check_id,
                    rule_version=RULE_VERSION,
                    rules=list(check.mapped_requirements),
                    controls=list(check.mapped_controls),
                    effect="gap",
                    endpoint=endpoint or target,
                    observed_at=timestamp.isoformat(),
                    timestamp_basis="source" if item.get("timestamp") else "collection",
                    context_review_required=identity in {"ssl-self-signed", "ssl-mismatched"},
                )
            )
    return facts


def evaluate_nuclei(requirement: dict, bundle: dict, now, output: dict) -> dict:
    """Evaluate only repository-verified attribution and retained source facts.

    Args:
        requirement: Reviewed scoped criterion; bundle: Authorized evidence/context.
        now: Aware evaluation clock; output: Initial result fields.
    Returns:
        Traceable technical coverage/gap result; never a human approval.
    Raises:
        ValueError: If the evaluation clock is naive.
    """
    from securescope.evidence.freshness import evidence_freshness

    if now.tzinfo is None:
        raise ValueError("Evaluation time must include a timezone.")
    rule = requirement["rule"]
    expected = set(requirement.get("asset_ids") or [])
    coverage_rule = rule == "Recent vulnerability scan"
    allowed = set(requirement.get("nuclei_template_ids") or [])
    measured, gaps, traces, excluded = set(), set(), [], []
    candidates = []
    output.update(
        result_layer="Technical requirement check",
        rule_version=RULE_VERSION,
        criterion_version=requirement.get("template_version"),
        engagement_id=bundle.get("engagement_id"),
        scope_id=bundle.get("scope_id"),
        profile_id=(bundle.get("profile") or {}).get("id"),
        profile_version=(bundle.get("profile") or {}).get("profile_version"),
        scope_version_id=(bundle.get("scope") or {}).get("id"),
        expected_assets=sorted(expected),
        recommended_action="Collect current evidence for the approved targets.",
    )
    for row in bundle.get("requirement_evidence", []):
        if row.get("tool_id") != "nuclei":
            continue
        proof = row.get("nuclei_verified_source") or {}
        candidates.extend(
            dict(f, evidence_id=row["id"], asset_id=proof.get("asset_id"))
            for f in proof.get("observations", [])
            if rule in f.get("rules", [])
        )
        reason = row.get("source_review_reason", "source_not_verified")
        eligible = (
            row.get("source_verification_current") is True
            and proof.get("version") == RULE_VERSION
            and row.get("validation_status") == "Validated"
            and row.get("scope_id") == bundle.get("scope_id")
            and row.get("engagement_id") == bundle.get("engagement_id")
            and requirement["id"] in row.get("eligible_requirement_ids", [])
            and proof.get("asset_id") in expected
            and (
                not (bundle.get("profile") or {}).get("id")
                or any(
                    a["profile_id"] == bundle["profile"]["id"]
                    and a["requirement_id"] == requirement["id"]
                    for a in row.get("attribution_contexts", [])
                )
            )
        )
        freshness = evidence_freshness(row, requirement.get("max_age_days", 90), now)
        if not eligible or freshness in {"Unknown", "Stale"}:
            excluded.append(
                dict(
                    evidence_id=row["id"],
                    reason=reason if not eligible else "source_" + freshness.lower(),
                )
            )
            if freshness == "Stale":
                output["freshness"] = "Stale"
            continue
        acquired = as_datetime(row.get("collected_at"))
        days = requirement.get("max_age_days", 90)
        deadline = acquired + timedelta(days=min(days, row.get("max_age_days") or days))
        expires = as_datetime(row.get("expires_at"))
        if expires:
            deadline = min(deadline, expires)
        timing = dict(acquired_at=acquired.isoformat(), effective_expires_at=deadline.isoformat())
        asset = proof["asset_id"]
        checks = (
            (row.get("normalized_payload") or {}).get("metadata", {}).get("automated_checks", [])
        )
        if (
            coverage_rule
            and proof.get("complete") is True
            and any(c.get("check_id") == SCAN_COMPLETED.check_id for c in checks)
        ):
            measured.add(asset)
            traces.append(
                dict(
                    evidence_id=row["id"],
                    asset_id=asset,
                    check_id=SCAN_COMPLETED.check_id,
                    rule_version=RULE_VERSION,
                    source_key=row.get("source_key"),
                    observed_at=proof["observed_at"],
                    sha256=row.get("sha256"),
                    freshness=freshness,
                    **timing,
                )
            )
        elif requirement.get("nuclei_rule_version") == RULE_VERSION and allowed:
            for fact in proof.get("observations", []):
                stamp = as_datetime(fact["observed_at"])
                if rule not in fact["rules"] or fact["template_id"] not in allowed:
                    continue
                fact_freshness = evidence_freshness(dict(row, collected_at=stamp), days, now)
                if not stamp or fact_freshness in {"Stale", "Unknown"}:
                    excluded.append(dict(evidence_id=row["id"], reason="finding_stale"))
                    continue
                fact_timing = dict(
                    timing,
                    effective_expires_at=min(
                        deadline, stamp + timedelta(days=min(days, row.get("max_age_days") or days))
                    ).isoformat(),
                )
                traces.append(
                    dict(
                        fact,
                        evidence_id=row["id"],
                        asset_id=asset,
                        source_key=row.get("source_key"),
                        sha256=row.get("sha256"),
                        freshness=fact_freshness,
                        **fact_timing,
                    )
                )
                measured.add(asset)
                if not fact["context_review_required"]:
                    gaps.add(asset)
    incomplete = any(
        e.get("evidence_window_incomplete") for e in bundle.get("requirement_evidence", [])
    )
    if not expected:
        result, code = "UNKNOWN", "assets_unassigned"
    elif not coverage_rule and (
        requirement.get("nuclei_rule_version") != RULE_VERSION or not allowed
    ):
        result, code = "UNKNOWN", "mapping_review_required"
    elif not coverage_rule:
        result, code = (
            ("FAIL", "observed_technical_gap")
            if gaps
            else ("UNKNOWN", "explicit_negative_test_unavailable")
        )
    elif incomplete:
        result, code = "UNKNOWN", "incomplete_evidence_window"
    else:
        ratio = 100 * len(measured) / len(expected)
        result = (
            "PASS"
            if ratio >= requirement.get("threshold", 100)
            else "PARTIAL" if measured else "NO EVIDENCE"
        )
        code = "scan_coverage" if measured else "eligible_evidence_missing"
    output.update(
        result=result,
        reason_code=code,
        reason=(
            f"{len(measured)} / {len(expected)} configured assets have eligible scan evidence. "
            "Scan coverage does not prove absence of vulnerabilities or remediation."
            if coverage_rule
            else (
                "A supported finding identifies a scoped technical gap; validate context and triage it."
                if gaps
                else "No verified negative test proves this criterion. Empty scans cannot establish a technical PASS."
            )
        ),
        evaluated_assets=sorted(measured),
        missing_assets=sorted(expected - measured),
        affected_assets=sorted(gaps or expected - measured),
        verified_assets=len(measured) if coverage_rule else 0,
        applicable_assets=len(expected),
        coverage_percent=round(100 * len(measured) / len(expected), 1) if expected else None,
        evidence_ids=sorted({t["evidence_id"] for t in traces}),
        observations=traces,
        excluded_evidence=excluded,
        automated=bool(traces),
        historical_findings_preserved=True,
        candidate_observations=candidates,
        asset_results={
            str(a): (
                "FAIL"
                if a in gaps
                else (
                    "PASS"
                    if coverage_rule and a in measured
                    else "UNKNOWN" if a in measured else "NOT COLLECTED"
                )
            )
            for a in expected
        },
    )
    if traces:
        output["freshness"] = (
            "Expiring Soon" if any(t["freshness"] == "Expiring Soon" for t in traces) else "Current"
        )
    actions = {
        "assets_unassigned": "Assign approved canonical assets to this requirement.",
        "mapping_review_required": "Review the exact template predicates in the requirement settings.",
        "observed_technical_gap": "Assign an owner, validate the finding, record treatment and perform an authorized targeted retest.",
        "explicit_negative_test_unavailable": "Review source findings and obtain explicit test-execution evidence; no automatic clean result is available.",
        "incomplete_evidence_window": "Narrow the evidence context or review the complete source history before concluding coverage.",
    }
    output["recommended_action"] = actions.get(code, output["recommended_action"])
    if code in {"assets_unassigned", "mapping_review_required", "incomplete_evidence_window"}:
        output["reason"] = output["recommended_action"]
    return output
