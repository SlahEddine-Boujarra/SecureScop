"""Regression tests for evidence-based implementation decisions."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from securescope.core.gap_assessment_domain import ASSURANCE_DIMENSIONS
from securescope.grc.control_implementation import evaluate_implementation, input_fingerprint
from securescope.grc.gap_dashboard import assessment_result

NOW = datetime(2026, 9, 17, 12, tzinfo=timezone.utc)


@pytest.fixture
def bundle():
    """Bundle.

    Args:
        None.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    return {
        "profile": {
            "id": 4,
            "control_id": "A.8.16",
            "profile_version": 2,
            "control_owner": "IT Security",
            "assessment_scope": {
                "implementation_requirements": {
                    "reviewed": True,
                    "review_days": 90,
                    "scope_version_id": 10,
                    "criteria": ["Alerts are reviewed"],
                    "policy_links": [{"id": "policy", "version": 2}],
                    "procedure_links": [{"id": "procedure", "version": 1}],
                }
            },
        },
        "assessment": {
            "id": 3,
            "target_id": 8,
            "created_at": NOW.isoformat(),
            "validation_status": "Validated",
            "assessment_status": "Implemented and effective",
        },
        "target": {"id": 8},
        "scope": {"id": 10, "status": "Approved"},
        "validator_authorized": True,
        "documents": [
            {
                "policy_id": key,
                "title": key,
                "policy_version": version,
                "status": "Approved",
                "controls": ["A.8.16"],
            }
            for key, version in [("policy", 2), ("procedure", 1)]
        ],
        "criteria": [
            {
                "description": "Alerts are reviewed",
                "required": True,
                "result": "Pass",
                "validation_status": "Validated",
                "evidence_reference": "report-1",
            }
        ],
        "dimensions": [
            {
                "dimension": name,
                "status": "Implemented and effective",
                "validation_status": "Validated",
            }
            for name in ASSURANCE_DIMENSIONS
        ],
        "evidence": [
            {
                "id": 7,
                "evidence_version": 1,
                "raw_evidence_reference": "report-1",
                "collection_date": NOW.isoformat(),
                "freshness_status": "Current",
                "validation_status": "Validated",
            }
        ],
        "tests": [
            {
                "id": 4,
                "test_date": NOW.date().isoformat(),
                "result": "Successful",
                "evidence_reference": "report-1",
                "retest_required": False,
            }
        ],
    }


def test_complete_evidence_can_establish_implementation(bundle):
    """Complete evidence can establish implementation.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    result = evaluate_implementation(bundle, now=NOW)
    assert result["status"] == "Implemented"
    assert all(check["passed"] for check in result["checks"])
    assert "scripts are not required" in result["verification"]


@pytest.mark.parametrize("field", ["assessment", "evidence", "criteria", "dimensions", "tests"])
def test_missing_inputs_never_produce_implemented(bundle, field):
    """Missing inputs never produce implemented.

    Args:
        bundle: Isolated test input or fixture.
        field: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle[field] = {} if field == "assessment" else []
    assert evaluate_implementation(bundle, now=NOW)["status"] in {
        "Not Assessed",
        "Verification Pending",
    }


@pytest.mark.parametrize("change", ["expired", "future", "old", "rejected", "unknown", "unrelated"])
def test_invalid_evidence_does_not_prove_absence_or_implementation(bundle, change):
    """Invalid evidence does not prove absence or implementation.

    Args:
        bundle: Isolated test input or fixture.
        change: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    evidence = bundle["evidence"][0]
    if change == "expired":
        evidence["expiration_date"] = NOW.isoformat()
    elif change in {"future", "old"}:
        evidence["collection_date"] = (
            NOW + timedelta(days=1 if change == "future" else -91)
        ).isoformat()
    elif change == "rejected":
        evidence["validation_status"] = "Rejected"
    elif change == "unknown":
        evidence["freshness_status"] = "Unknown"
    else:
        evidence["raw_evidence_reference"] = "different report"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_documents_alone_do_not_prove_operation(bundle):
    """Documents alone do not prove operation.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["evidence"] = []
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


@pytest.mark.parametrize(
    "outcome, expected",
    [
        ("Fail", "Not Implemented"),
        ("Partial", "Partially Implemented"),
        ("Not assessed", "Verification Pending"),
    ],
)
def test_evidenced_criterion_results_drive_conclusion(bundle, outcome, expected):
    """Evidenced criterion results drive conclusion.

    Args:
        bundle: Isolated test input or fixture.
        outcome: Isolated test input or fixture.
        expected: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["criteria"][0]["result"] = outcome
    assert evaluate_implementation(bundle, now=NOW)["status"] == expected


def test_omitted_declared_criterion_is_not_a_pass(bundle):
    """Omitted declared criterion is not a pass.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["profile"]["assessment_scope"]["implementation_requirements"]["criteria"].append(
        "Alerts are investigated"
    )
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_latest_failed_test_overrides_older_success(bundle):
    """Latest failed test overrides older success.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["tests"].append({**bundle["tests"][0], "id": 5, "result": "Failed"})
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Partially Implemented"


@pytest.mark.parametrize("field", ["retest_required", "exceptions"])
def test_unresolved_test_findings_prevent_implementation(bundle, field):
    """Unresolved test findings prevent implementation.

    Args:
        bundle: Isolated test input or fixture.
        field: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["tests"][0][field] = True if field == "retest_required" else "Open exception"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_new_document_version_requires_review(bundle):
    """New document version requires review.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    old = input_fingerprint(bundle)
    bundle["documents"][0]["policy_version"] = 3
    assert input_fingerprint(bundle) != old
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Partially Implemented"


def test_document_omission_requires_rationale(bundle):
    """Document omission requires rationale.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    config = bundle["profile"]["assessment_scope"]["implementation_requirements"]
    config["procedure_links"] = []
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"
    config["procedure_rationale"] = "Procedure included in policy"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Implemented"


def test_replaced_target_requires_review(bundle):
    """Replaced target requires review.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["target"]["id"] = 9
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_replaced_scope_requires_review(bundle):
    """Replaced scope requires review.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["scope"]["id"] = 11
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_retired_validator_cannot_support_positive_result(bundle):
    """Retired validator cannot support positive result.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["validator_authorized"] = False
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_revoked_hub_evidence_invalidates_copied_reference(bundle):
    """Revoked hub evidence invalidates copied reference.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["linked_evidence"] = [{"id": 13, "validation_status": "Rejected"}]
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"


def test_exclusion_requires_approved_justified_soa(bundle):
    """Exclusion requires approved justified soa.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["profile"]["applicability"] = "Not applicable"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"
    bundle["soa"] = {
        "approved": True,
        "applicability": "Not applicable",
        "exclusion_justification": "Outside scope",
    }
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Not Applicable"


def test_time_changes_current_result_without_rewriting_inputs(bundle):
    """Time changes current result without rewriting inputs.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    original = deepcopy(bundle)
    assert (
        evaluate_implementation(bundle, now=NOW + timedelta(days=91))["status"]
        == "Verification Pending"
    )
    assert bundle == original


def test_gap_dashboard_uses_implementation_result(bundle):
    """Gap dashboard uses implementation result.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    row = {"control_id": "A.8.16", "assessment_status": "Implemented and effective"}
    row["implementation_evaluation"] = evaluate_implementation(bundle, now=NOW)
    assert assessment_result(row) == "Met"
    bundle["evidence"] = []
    row["implementation_evaluation"] = evaluate_implementation(bundle, now=NOW)
    assert assessment_result(row) == "Review required"


def test_validated_dimension_gap_prevents_positive_result(bundle):
    """Validated dimension gap prevents positive result.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["dimensions"][0]["status"] = "Partially implemented"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Partially Implemented"


def test_reference_lists_require_exact_known_tokens(bundle):
    """Reference lists require exact known tokens.

    Args:
        bundle: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle["evidence"][0]["raw_evidence_reference"] = "report-1; report-2"
    bundle["criteria"][0]["evidence_reference"] = "report-2"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Implemented"
    bundle["criteria"][0]["evidence_reference"] = "report-2; unknown"
    assert evaluate_implementation(bundle, now=NOW)["status"] == "Verification Pending"
