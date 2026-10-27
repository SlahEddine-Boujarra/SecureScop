"""M3 source predicates and explainable requirement boundaries; no external scanners."""

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from securescope.evidence.automated_checks import SCAN_COMPLETED, classify_nuclei
from securescope.evidence.nuclei_assurance import source_facts
from securescope.grc.assurance_requirements import evaluate_requirement, validate_requirements
from securescope.grc.requirement_templates import baseline_requirements, merge_baseline

NOW = datetime(2026, 10, 19, 18, tzinfo=timezone.utc)


def test_source_facts_are_stable_across_database_session_timezones():
    """Equivalent timestamp offsets produce identical source digests after rereading."""
    raw = b'{"template-id":"ssl-expired","host":"192.0.2.1"}'
    other_zone = NOW.astimezone(timezone(timedelta(hours=1)))
    assert source_facts(raw, 1, "192.0.2.1", NOW) == source_facts(raw, 1, "192.0.2.1", other_zone)


def fixture(control="A.8.9", template="http-missing-security-headers"):
    """Build repository-annotated inputs; return requirement/bundle; raises no expected errors."""
    requirement = baseline_requirements(control)[-1 if control != "A.8.8" else 0]
    requirement["asset_ids"] = [1, 2]
    raw = (
        json.dumps(
            {"template-id": template, "host": "https://192.0.2.1", "timestamp": NOW.isoformat()}
        ).encode()
        if template
        else b""
    )
    proof = source_facts(raw, 1, "192.0.2.1", NOW)
    row = dict(
        id=7,
        tool_id="nuclei",
        scope_id=3,
        engagement_id=2,
        source_verification_current=True,
        eligible_requirement_ids=[requirement["id"]],
        nuclei_verified_source=proof,
        collected_at=NOW,
        validation_status="Validated",
        source_key="nuclei:fixture:attempt:1",
        normalized_payload={"metadata": {"automated_checks": [SCAN_COMPLETED.to_dict()]}},
    )
    return requirement, dict(scope_id=3, engagement_id=2, requirement_evidence=[row])


@pytest.mark.parametrize(
    "template,tags",
    [
        ("unknown", ["default-login"]),
        ("unknown", ["cve"]),
        ("default-login-example", []),
        ("arbitrary-tls", ["tls", "ssl"]),
    ],
)
def test_tags_and_prefixes_do_not_authorize_control_mapping(template, tags):
    """Tags and prefixes do not authorize control mapping."""
    assert classify_nuclei(template, tags) == ()


@pytest.mark.parametrize(
    "control,template",
    [
        ("A.8.9", "missing-x-frame-options"),
        ("A.8.24", "ssl-expired"),
        ("A.8.5", "grafana-default-login"),
    ],
)
def test_positive_finding_explains_only_exact_gap(control, template):
    """Positive finding explains only exact gap."""
    requirement, bundle = fixture(control, template)
    before = copy.deepcopy(bundle)
    result = evaluate_requirement(requirement, bundle, NOW)
    assert result["result"] == "FAIL"
    assert result["asset_results"] == {"1": "FAIL", "2": "NOT COLLECTED"}
    assert result["missing_assets"] == [2]
    assert result["observations"][0]["template_id"] == template
    assert result["recommended_action"]
    assert bundle == before


@pytest.mark.parametrize("control", ["A.8.9", "A.8.24", "A.8.5"])
def test_zero_findings_cannot_prove_negative_test(control):
    """Zero findings cannot prove negative test."""
    requirement, bundle = fixture(control, "")
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "UNKNOWN"


def test_unassigned_gap_is_candidate_not_formal_failure():
    """Unassigned gap is candidate not formal failure."""
    requirement, bundle = fixture()
    requirement["asset_ids"] = []
    result = evaluate_requirement(requirement, bundle, NOW)
    assert result["result"] == "UNKNOWN"
    assert result["reason_code"] == "assets_unassigned"
    assert result["candidate_observations"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_id", 99),
        ("engagement_id", 99),
        ("eligible_requirement_ids", ["other"]),
        ("source_verification_current", False),
        ("validation_status", "Rejected"),
    ],
)
def test_denied_context_cannot_create_coverage(field, value):
    """Denied context cannot create coverage."""
    requirement, bundle = fixture("A.8.8", "")
    bundle["requirement_evidence"][0][field] = value
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "NO EVIDENCE"


@pytest.mark.parametrize("change", ["stale", "future", "expired", "missing-proof"])
def test_timestamp_and_source_gates(change):
    """Timestamp and source gates."""
    requirement, bundle = fixture("A.8.8", "")
    row = bundle["requirement_evidence"][0]
    if change == "missing-proof":
        row.pop("nuclei_verified_source")
    elif change == "expired":
        row["expires_at"] = NOW
    else:
        row["collected_at"] = NOW + timedelta(days=1 if change == "future" else -100)
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "NO EVIDENCE"


@pytest.mark.parametrize(
    "item,reason",
    [
        (
            {"template-id": "ssl-expired", "host": "https://other.invalid", "ip": "192.0.2.1"},
            "target_unverified",
        ),
        ({"template-id": "ssl-expired"}, "target_unverified"),
        (
            {
                "template-id": "ssl-expired",
                "host": "192.0.2.1",
                "timestamp": (NOW + timedelta(seconds=1)).isoformat(),
            },
            "timestamp_invalid",
        ),
        ({"template-id": "unknown", "host": "192.0.2.1"}, "unsupported_template"),
    ],
)
def test_raw_source_is_validated_independently_of_scan_target(item, reason):
    """Raw source is validated independently of scan target."""
    proof = source_facts(json.dumps(item).encode(), 1, "192.0.2.1", NOW)
    assert not proof["observations"]
    assert proof["excluded"][0]["reason"] == reason


def test_self_signed_requires_context_review_not_automatic_failure():
    """Self signed requires context review not automatic failure."""
    requirement, bundle = fixture("A.8.24", "ssl-self-signed")
    result = evaluate_requirement(requirement, bundle, NOW)
    assert result["result"] == "UNKNOWN"
    assert result["observations"][0]["context_review_required"]


def test_old_source_timestamp_cannot_be_refreshed_by_new_scan_time():
    """Old source timestamp cannot be refreshed by new scan time."""
    requirement, bundle = fixture()
    bundle["requirement_evidence"][0]["nuclei_verified_source"]["observations"][0][
        "observed_at"
    ] = (NOW - timedelta(days=100)).isoformat()
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "UNKNOWN"


def test_forged_negative_and_clean_retest_cannot_erase_gap():
    """Forged negative and clean retest cannot erase gap."""
    requirement, bundle = fixture()
    clean = copy.deepcopy(bundle["requirement_evidence"][0])
    clean["id"] = 8
    clean["nuclei_verified_source"]["observations"] = []
    clean["normalized_payload"]["metadata"]["assurance"] = {
        "technical_checks": {
            requirement["rule"]: {"evaluated_asset_ids": [1, 2], "satisfied_asset_ids": [1, 2]}
        }
    }
    bundle["requirement_evidence"].append(clean)
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "FAIL"
    bundle["requirement_evidence"].pop(0)
    assert evaluate_requirement(requirement, bundle, NOW)["result"] == "UNKNOWN"


def test_incomplete_window_cannot_claim_full_coverage():
    """Incomplete window cannot claim full coverage."""
    requirement, bundle = fixture("A.8.8", "")
    requirement["asset_ids"] = [1]
    bundle["requirement_evidence"][0]["evidence_window_incomplete"] = True
    result = evaluate_requirement(requirement, bundle, NOW)
    assert result["result"] == "UNKNOWN"
    assert result["reason_code"] == "incomplete_evidence_window"


def test_rule_version_and_template_choices_require_review():
    """Rule version and template choices require review."""
    requirement, bundle = fixture()
    requirement.pop("nuclei_rule_version")
    assert (
        evaluate_requirement(requirement, bundle, NOW)["reason_code"] == "mapping_review_required"
    )
    requirement.update(nuclei_rule_version=3, nuclei_template_ids=["arbitrary"])
    with pytest.raises(ValueError, match="template predicates"):
        validate_requirements([requirement])


def test_template_upgrade_preserves_custom_edits_and_removed_criteria():
    """Template upgrade preserves custom edits and removed criteria."""
    existing = baseline_requirements("A.8.9")[-1]
    existing.update(title="Organization baseline", asset_ids=[11])
    before = copy.deepcopy(existing)
    rows, pending = merge_baseline(
        "A.8.9", dict(baseline_template_version=2, requirements=[existing])
    )
    assert pending and rows == [before] and existing == before


def test_clock_template_version_unchanged():
    """Clock template version unchanged."""
    assert {r["template_version"] for r in baseline_requirements("A.8.17")} == {2}
    assert all("nuclei_rule_version" not in r for r in baseline_requirements("A.8.17"))
