"""Behavioral coverage for evidence semantics, scope isolation and automatic assurance."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from securescope.evidence.assurance_facts import normalize_assurance_facts
from securescope.grc.assurance_requirements import (
    assurance_metrics,
    evaluate_assurance,
    evaluate_requirement,
    evidence_freshness,
    validate_requirements,
)

NOW = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)


@pytest.fixture
def bundle():
    """Return one scoped requirement with explicit affirmative provider observations."""
    requirement = dict(
        id="logging",
        title="Centralized logging",
        expected_result="All configured systems report security logs.",
        type="Technical",
        mandatory=True,
        rule="Log source coverage",
        machine_verifiable=True,
        max_age_days=30,
        asset_ids=[1, 2],
        evidence_links=[{"evidence_id": 7}],
        threshold=100,
    )
    evidence = dict(
        id=7,
        tool_id="wazuh",
        scope_id=9,
        engagement_id=2,
        mapping_approved=True,
        validation_status="Validated",
        collection_method="Authenticated API",
        collected_at=NOW.isoformat(),
        normalized_payload={
            "metadata": {
                "assurance": {
                    "logging": {"evaluated_asset_ids": [1, 2], "satisfied_asset_ids": [1, 2]}
                }
            }
        },
    )
    return dict(
        profile={
            "control_id": "A.8.15",
            "assessment_scope": {
                "implementation_requirements": {
                    "requirements": [requirement],
                    "continuous_auto_assurance": True,
                    "scope_version_id": 20,
                }
            },
        },
        requirement_evidence=[evidence],
        scope_id=9,
        engagement_id=2,
        scope={"id": 20, "status": "Approved"},
        soa={"applicability": "Applicable"},
        safety_signals_complete=True,
        documents=[],
    )


def requirement(bundle):
    """Return the fixture's existing structured criterion."""
    return bundle["profile"]["assessment_scope"]["implementation_requirements"]["requirements"][0]


def facts(bundle):
    """Return normalized provider facts without replacing their source record."""
    return bundle["requirement_evidence"][0]["normalized_payload"]["metadata"]["assurance"]


def test_machine_coverage_requires_human_final_assessment(bundle):
    result = evaluate_assurance(bundle, now=NOW)
    assert result["implementation"] == "Not Assessed"
    assert result["assurance"] == "Needs Review"
    assert not result["auto_verified"]
    assert result["evidence_coverage"] == 100


@pytest.mark.parametrize("positive,expected", [([1, 2], "PASS"), ([1], "PARTIAL"), ([], "FAIL")])
def test_explicit_coverage_results(bundle, positive, expected):
    facts(bundle)["logging"]["satisfied_asset_ids"] = positive
    result = evaluate_requirement(requirement(bundle), bundle, NOW)
    assert result["result"] == expected
    assert result["evidence_ids"] == [7]
    assert result["applicable_assets"] == 2


def test_missing_evidence_is_not_implementation_failure(bundle):
    bundle["requirement_evidence"] = []
    result = evaluate_assurance(bundle, now=NOW)
    assert result["implementation"] == "Insufficient Evidence"
    assert result["requirements"][0]["result"] == "NO EVIDENCE"
    assert not result["auto_verified"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_id", 10),
        ("engagement_id", 3),
        ("mapping_approved", False),
        ("validation_status", "Rejected"),
        ("validation_status", "Pending"),
        ("tool_id", "nmap"),
    ],
)
def test_foreign_unreviewed_or_incapable_evidence_cannot_satisfy(bundle, field, value):
    bundle["requirement_evidence"][0][field] = value
    assert evaluate_requirement(requirement(bundle), bundle, NOW)["result"] == "NO EVIDENCE"


def test_missing_provider_fact_is_unknown_not_pass(bundle):
    facts(bundle).clear()
    assert evaluate_requirement(requirement(bundle), bundle, NOW)["result"] == "UNKNOWN"
    assert not evaluate_assurance(bundle, now=NOW)["auto_verified"]


def test_partial_observation_does_not_prove_whole_boundary(bundle):
    facts(bundle)["logging"]["evaluated_asset_ids"] = [1]
    result = evaluate_requirement(requirement(bundle), bundle, NOW)
    assert result["result"] == "PARTIAL"
    assert result["verified_assets"] == 1


@pytest.mark.parametrize("days,expected", [(1, "Current"), (27, "Expiring Soon"), (31, "Stale")])
def test_freshness_is_computed_from_actual_time(bundle, days, expected):
    evidence = bundle["requirement_evidence"][0]
    evidence["collected_at"] = (NOW - timedelta(days=days)).isoformat()
    assert evidence_freshness(evidence, 30, NOW) == expected


def test_staleness_degrades_auto_assurance_without_deleting_evidence(bundle):
    previous = evaluate_assurance(bundle, now=NOW)
    later = evaluate_assurance(bundle, now=NOW + timedelta(days=31))
    assert previous["evidence_coverage"] == 100
    assert later["evidence_coverage"] == 0
    assert not previous["auto_verified"] and not later["auto_verified"]
    assert later["evidence_status"] == "Stale"
    assert len(bundle["requirement_evidence"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        "disabled",
        "unapproved_scope",
        "pending_applicability",
        "incomplete_safety",
        "contradiction",
        "manual_import",
    ],
)
def test_auto_assurance_requires_all_configured_safety_conditions(bundle, change):
    if change == "disabled":
        bundle["profile"]["assessment_scope"]["implementation_requirements"][
            "continuous_auto_assurance"
        ] = False
    elif change == "unapproved_scope":
        bundle["scope"]["status"] = "Draft"
    elif change == "pending_applicability":
        bundle["soa"] = {}
    elif change == "incomplete_safety":
        bundle["safety_signals_complete"] = False
    elif change == "contradiction":
        bundle["blockers"] = ["Critical finding remains unresolved."]
    else:
        bundle["requirement_evidence"][0]["collection_method"] = "Report import"
    assert not evaluate_assurance(bundle, now=NOW)["auto_verified"]


def test_negative_evidence_wins_over_contradictory_positive(bundle):
    negative = deepcopy(bundle["requirement_evidence"][0])
    negative["id"] = 8
    negative["normalized_payload"]["metadata"]["assurance"]["logging"]["satisfied_asset_ids"] = []
    bundle["requirement_evidence"].append(negative)
    requirement(bundle)["evidence_links"].append({"evidence_id": 8})
    assert evaluate_requirement(requirement(bundle), bundle, NOW)["result"] == "FAIL"


def test_optional_missing_evidence_does_not_block_mandatory_success(bundle):
    optional = dict(requirement(bundle), id="optional", mandatory=False, evidence_links=[])
    bundle["profile"]["assessment_scope"]["implementation_requirements"]["requirements"].append(
        optional
    )
    result = evaluate_assurance(bundle, now=NOW)
    assert not result["auto_verified"]
    assert result["mandatory_count"] == 1


def test_policy_draft_never_satisfies_approved_policy_requirement(bundle):
    requirement(bundle).update(rule="Approved policy", policy_ids=["p1"], type="Governance")
    bundle["documents"] = [
        dict(policy_id="p1", title="Logging policy", policy_version=2, status="Draft")
    ]
    assert evaluate_requirement(requirement(bundle), bundle, NOW)["result"] == "NO EVIDENCE"
    bundle["documents"][0]["status"] = "Approved"
    result = evaluate_requirement(requirement(bundle), bundle, NOW)
    assert result["result"] == "PASS"
    assert result["policy_versions"] == [{"id": "p1", "version": 2}]


def test_no_universal_policy_requirement(bundle):
    assert not bundle["documents"]
    assert evaluate_assurance(bundle, now=NOW)["requirements"][0]["result"] == "PASS"


def test_not_applicable_requires_governed_exclusion(bundle):
    bundle["soa"] = {
        "applicability": "Not applicable",
        "approved": False,
        "exclusion_justification": "No systems",
    }
    assert evaluate_assurance(bundle, now=NOW)["applicability"] == "Pending"
    bundle["soa"]["approved"] = True
    assert evaluate_assurance(bundle, now=NOW)["applicability"] == "Not Applicable"


def test_metrics_separate_assessment_and_evidence(bundle):
    result = evaluate_assurance(bundle, now=NOW)
    metrics = assurance_metrics([result])
    assert metrics["implementation_coverage"] == 0
    assert metrics["evidence_coverage"] == 100
    assert metrics["assessment_coverage"] == 0
    assert metrics["effectiveness_rate"] is None


def test_no_assessments_is_not_zero_conformity():
    from securescope.grc.gap_dashboard import summarize_entries

    assert summarize_entries([{"result": "Not assessed"}])["conformity"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("mandatory", "yes"),
        ("threshold", 0),
        ("max_age_days", -1),
        ("rule", "Run arbitrary code"),
        ("title", ""),
    ],
)
def test_invalid_requirement_configuration_is_rejected(bundle, field, value):
    requirement(bundle)[field] = value
    with pytest.raises(ValueError):
        validate_requirements([requirement(bundle)])


def test_provider_capability_allowlist():
    assert (
        normalize_assurance_facts(
            "nuclei", {"logging": {"satisfied_asset_ids": [1]}, "tests": {"mfa": True}}
        )
        == {}
    )
    assert normalize_assurance_facts("wazuh", {"tests": {"mfa": True, "fake": "yes"}}) == {
        "tests": {"mfa": True}
    }


def test_report_envelope_retains_traceable_supported_facts():
    from securescope.evidence.normalization import normalize_report

    report = (
        b'{"metadata":{"assurance":{"complete":true,"asset_ids":[1],'
        b'"logging":{"satisfied_asset_ids":[1]}}},"results":[]}'
    )
    normalized = normalize_report("nuclei", "scan.json", report)
    assert normalized.metadata["assurance"] == {"complete": True, "asset_ids": [1]}


def test_explicit_expiration_cannot_be_overridden_by_recent_collection(bundle):
    bundle["requirement_evidence"][0]["freshness_status"] = "Expired"
    assert evidence_freshness(bundle["requirement_evidence"][0], 90, NOW) == "Stale"
    assert not evaluate_assurance(bundle, now=NOW)["auto_verified"]


def test_changed_scope_requires_profile_review(bundle):
    bundle["scope"]["id"] = 21
    result = evaluate_assurance(bundle, now=NOW)
    assert not result["auto_verified"]
    assert any("scope version" in message for message in result["automation_blockers"])


def test_safety_signals_require_complete_current_scoped_machine_observations(bundle):
    from securescope.grc.assurance_requirements import apply_safety_signals

    facts(bundle)["safety"] = dict(
        evaluated_asset_ids=[1, 2],
        exceptions_present=False,
        critical_remediation_overdue=False,
        contradictory_findings_present=False,
    )
    apply_safety_signals(bundle, NOW)
    assert bundle["safety_signals_complete"]
    facts(bundle)["safety"]["evaluated_asset_ids"] = [1]
    apply_safety_signals(bundle, NOW)
    assert not bundle["safety_signals_complete"]


def test_safety_blockers_preserve_canonical_remediation(bundle):
    from securescope.grc.assurance_requirements import apply_safety_signals

    bundle["blockers"] = ["Canonical remediation remains open."]
    facts(bundle)["safety"] = dict(
        evaluated_asset_ids=[1, 2],
        exceptions_present=True,
        critical_remediation_overdue=False,
        contradictory_findings_present=False,
    )
    apply_safety_signals(bundle, NOW)
    assert len(bundle["blockers"]) == 2
    assert not evaluate_assurance(bundle, now=NOW)["auto_verified"]


def test_manual_assessment_uses_stable_criterion_and_authorized_reviewer(bundle):
    criterion = requirement(bundle)
    criterion["rule"] = "Manual validation"
    bundle["requirement_evidence"] = []
    bundle["assessment"] = dict(id=11, validation_status="Validated", created_at=NOW.isoformat())
    bundle["validator_authorized"] = True
    bundle["criteria"] = [
        dict(
            criterion_identifier=criterion["id"],
            result="Pass",
            evidence_reference="Review report 42",
        )
    ]
    result = evaluate_requirement(criterion, bundle, NOW)
    assert result["result"] == "PASS"
    assert not result["automated"]
    assert result["assessment_id"] == 11
    bundle["validator_authorized"] = False
    assert evaluate_requirement(criterion, bundle, NOW)["result"] == "NO EVIDENCE"


@pytest.mark.parametrize("change", ["stale", "wrong criterion", "no reference", "unvalidated"])
def test_manual_assessment_cannot_certify_unproven_requirement(bundle, change):
    criterion = requirement(bundle)
    criterion["rule"] = "Manual validation"
    bundle["requirement_evidence"] = []
    bundle["validator_authorized"] = True
    bundle["assessment"] = dict(validation_status="Validated", created_at=NOW.isoformat())
    bundle["criteria"] = [
        dict(criterion_identifier=criterion["id"], result="Pass", evidence_reference="Report")
    ]
    if change == "stale":
        bundle["assessment"]["created_at"] = (NOW - timedelta(days=365)).isoformat()
    elif change == "wrong criterion":
        bundle["criteria"][0]["criterion_identifier"] = "unrelated"
    elif change == "no reference":
        bundle["criteria"][0]["evidence_reference"] = ""
    else:
        bundle["assessment"]["validation_status"] = "Pending"
    assert evaluate_requirement(criterion, bundle, NOW)["result"] == "NO EVIDENCE"


def test_human_implementation_does_not_imply_sufficient_evidence(bundle):
    bundle["requirement_evidence"] = []
    bundle["validator_authorized"] = True
    bundle["assessment"] = dict(
        validation_status="Validated",
        created_at=NOW.isoformat(),
        assessment_status="Implemented and effective",
    )
    result = evaluate_assurance(bundle, now=NOW)
    assert result["implementation"] == "Implemented"
    assert result["assurance"] == "Needs Review"
    assert result["evidence_status"] == "Missing"


def test_explicit_human_only_criterion_cannot_auto_pass_provider_data(bundle):
    requirement(bundle)["machine_verifiable"] = False
    result = evaluate_requirement(requirement(bundle), bundle, NOW)
    assert result["result"] == "UNKNOWN"
    assert not result["automated"]


def test_machine_verification_requires_explicit_opt_in(bundle):
    requirement(bundle).pop("machine_verifiable")
    assert evaluate_requirement(requirement(bundle), bundle, NOW)["result"] == "UNKNOWN"


def test_unreviewed_baseline_blocks_automatic_assurance(bundle):
    bundle["profile"]["assessment_scope"]["implementation_requirements"][
        "baseline_review_pending"
    ] = True
    result = evaluate_assurance(bundle, now=NOW)
    assert not result["auto_verified"]
    assert any("authored baseline" in reason for reason in result["automation_blockers"])
