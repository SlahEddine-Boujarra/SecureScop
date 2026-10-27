"""Regression coverage for authored baselines and canonical versioned seeding."""

from copy import deepcopy
from unittest.mock import Mock

import pytest

from securescope.grc.assurance_requirements import validate_requirements
from securescope.grc.requirement_templates import (
    LABELS,
    TEMPLATE_VERSION,
    baseline_requirements,
    item_type,
    merge_baseline,
    template_version_for,
)
from securescope.persistence import assurance_workspace_repository as repository


def test_every_catalog_entry_has_valid_independent_baseline():
    assert len(LABELS) == 123
    assert sum(item_type(ref) == "ISO Requirement" for ref in LABELS) == 30
    identifiers = set()
    for reference in LABELS:
        baseline = baseline_requirements(reference)
        assert len(baseline) >= 3
        assert validate_requirements(baseline)
        for criterion in baseline:
            assert criterion["id"] not in identifiers
            identifiers.add(criterion["id"])
            assert criterion["source_kind"] == "SecureScope Baseline"
            assert criterion["template_version"] == template_version_for(reference)
        baseline[0]["title"] = "Local edit"
        assert baseline_requirements(reference)[0]["title"] != "Local edit"
    assert baseline_requirements("Unknown") == []


def test_seed_preserves_edits_custom_criteria_and_intentional_removal():
    baseline = baseline_requirements("A.8.16")
    custom = dict(baseline[0], id="custom", template_id=None, title="Custom review")
    edited = dict(baseline[0], title="Reviewed local wording")
    original = {"requirements": [custom, edited]}
    before = deepcopy(original)
    merged, needed = merge_baseline("A.8.16", original)
    assert needed and original == before
    assert merged[:2] == [custom, edited]
    assert len(merged) == len(baseline) + 1
    seeded = {"requirements": merged[1:], "baseline_template_version": TEMPLATE_VERSION}
    assert merge_baseline("A.8.16", seeded) == (merged[1:], False)


def test_policy_and_machine_checks_are_explicit_not_universal():
    monitoring = baseline_requirements("A.8.16")
    assert all(r["policy_required"] == "Not Required" for r in monitoring)
    assert any(r["machine_verifiable"] for r in monitoring)
    assert any(r["human_review_required"] for r in monitoring)
    policies = baseline_requirements("A.5.1")
    assert any(r["policy_required"] == "Required" for r in policies)


@pytest.mark.parametrize(
    "role,expected", [("Auditor", False), ("Consultant", True), ("Administrator", True)]
)
def test_seed_reuses_canonical_version_service_with_scope_and_role(monkeypatch, role, expected):
    save = Mock(return_value=8)
    monkeypatch.setattr(repository, "save_requirements", save)
    view = {"role": role, "bundle": {"profile": {"profile_version": 7, "assessment_scope": {}}}}
    assert repository.seed_control_baseline("Client", "A.8.16", "User", 2, 9, view) is expected
    if expected:
        assert save.call_args.args[:6] == ("Client", "A.8.16", "User", 2, 9, 7)
        assert save.call_args.kwargs["seed_baseline"] is True
    else:
        save.assert_not_called()
