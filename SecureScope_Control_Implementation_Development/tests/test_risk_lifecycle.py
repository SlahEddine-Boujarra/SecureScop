"""Risk lifecycle validation and canonical draft persistence."""

from unittest.mock import Mock

import pytest

from securescope.grc.document_registers import normalize_register_rows
from securescope.grc.risk_lifecycle import scoring_view, workflow_fields
from securescope.persistence import risk_links
from securescope.persistence.foundation_repository import FoundationError


def complete_record():
    """Return a complete proposed assessment; it is not an approval."""
    return dict(
        risk_ref=1,
        risk_summary="Service outage",
        risk_description="Service becomes unavailable",
        asset_group="Software",
        asset="Service",
        threat="Outage",
        vulnerability="Single site",
        risk_type="A",
        risk_owner="Owner",
        pre_likelihood=4,
        pre_impact=5,
        pre_likelihood_rationale="Recent incidents",
        pre_impact_rationale="Lost business",
        treatment_option="Modify",
        treatment_action="Add failover",
        control_references=["A.8.14"],
        treatment_action_owner="IT",
        treatment_due_date="2026-12-31",
        treatment_progress_percent=0,
        post_likelihood=2,
        post_impact=3,
        post_likelihood_rationale="Failover planned",
        post_impact_rationale="Shorter outage",
        assessment_conclusion="Proceed with treatment",
        residual_decision="Additional treatment required",
    )


def test_incomplete_draft_retains_ref_and_unset_ratings():
    """An empty identified draft is stored as one canonical row, not dropped."""
    rows = normalize_register_rows("asset_risks", [{"risk_ref": 6}], preserve_incomplete=True)
    assert len(rows) == 1 and rows[0]["risk_ref"] == 6
    assert rows[0]["pre_risk_score"] is None
    assert rows[0]["post_risk_score"] is None
    assert workflow_fields({}) == {}
    assert normalize_register_rows("asset_risks", [{"risk_ref": 6}]) == []


def test_completion_requires_all_fields_and_acceptance_stays_an_intent():
    """Completion requires ratings/rationales but never returns approval flags."""
    with pytest.raises(ValueError, match="Risk summary"):
        workflow_fields({"risk_ref": 1}, complete=True)
    record = complete_record()
    record["residual_decision"] = "Accept residual risk"
    result = workflow_fields(record, complete=True)
    assert result["treatment_progress_percent"] == 0
    assert "review_state" not in result and "residual_verified" not in result
    del record["pre_impact_rationale"]
    with pytest.raises(ValueError, match="Impact rationale"):
        workflow_fields(record, complete=True)


@pytest.mark.parametrize("progress", [-1, 101, 1.5, True, "not a number"])
def test_invalid_progress_rejected_even_for_drafts(progress):
    """Partial drafts still enforce input types and ranges."""
    with pytest.raises(ValueError):
        workflow_fields({"treatment_progress_percent": progress})


def test_scoring_uses_existing_levels_without_inventing_appetite():
    """The browser receives canonical bands and no unconfigured appetite."""
    view = scoring_view()
    assert [view["levels"][str(n)] for n in (4, 5, 9, 10, 16, 17, 25)] == [
        "Low",
        "Medium",
        "Medium",
        "High",
        "High",
        "Critical",
        "Critical",
    ]
    assert view["appetite"] is None


def test_completion_metadata_is_atomic_and_preserves_unrelated_fields(monkeypatch):
    """The existing transaction writes completion and links on the same risk ref."""
    cursor = Mock()
    cursor.fetchall.side_effect = [[{"control_id": "A.8.14"}], [], []]
    cursor.fetchone.return_value = {"revision": 2, "payload": {"category": "Availability"}}
    monkeypatch.setattr(risk_links, "member_role", lambda *a: "Consultant")
    monkeypatch.setattr(risk_links, "protect_text", lambda payload, **k: dict(payload))

    def save(client, record, **kwargs):
        assert record["risk_ref"] == 1
        assert not record["residual_verified"]
        assert kwargs["allow_incomplete"] is False
        kwargs["authorize"](cursor, 8)
        kwargs["after_save"](cursor, 8, {1: 4})

    monkeypatch.setattr(risk_links, "save_risk_record", save)
    risk_links.save_assessment(
        "Client",
        complete_record(),
        actor="reviewer",
        revision=3,
        group="default",
        metadata_revision=2,
        asset_ids=[],
        complete=True,
    )
    payload = cursor.execute.call_args.args[1][2].adapted
    assert payload["completion_state"] == "Completed"
    assert payload["completed_revision"] == 4
    assert payload["review_state"] == "Draft"
    assert payload["category"] == "Availability"
    assert payload["risk_summary"] == "Service outage"


def test_existing_control_links_must_belong_to_workspace(monkeypatch):
    """Foreign profile IDs cannot be linked even in an incomplete draft."""
    cursor = Mock()
    cursor.fetchall.return_value = []
    monkeypatch.setattr(risk_links, "member_role", lambda *a: "Consultant")

    def save(client, record, **kwargs):
        kwargs["authorize"](cursor, 8)

    monkeypatch.setattr(risk_links, "save_risk_record", save)
    with pytest.raises(FoundationError, match="Select controls"):
        risk_links.save_assessment(
            "Client",
            {"risk_ref": 1, "existing_control_references": ["foreign"]},
            actor="reviewer",
            revision=0,
            group="default",
            metadata_revision=0,
            asset_ids=[],
        )
