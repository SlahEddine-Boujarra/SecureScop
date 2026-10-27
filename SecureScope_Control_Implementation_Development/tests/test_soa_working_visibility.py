"""Working SoA changes are visible without becoming approved decisions."""

from securescope.ui import soa_ownership


def test_working_applicability_is_scoped_and_reverting_clears_it(monkeypatch):
    """Return only changed rows from the exact client, engagement and scope."""
    baseline = {"control_id": "A.8.16", "applicability": "Applicable"}
    key = "soa_working_editor::Client A::2::9"
    state = {
        key + "::baseline": [baseline],
        key: [dict(baseline, applicability="Not applicable")],
    }
    monkeypatch.setattr(soa_ownership.st, "session_state", state)
    assert soa_ownership.pending_soa_applicability("Client A", 2, 9) == {"A.8.16": "Not applicable"}
    for context in [("Client B", 2, 9), ("Client A", 3, 9), ("Client A", 2, 10)]:
        assert soa_ownership.pending_soa_applicability(*context) == {}
    state[key] = [dict(baseline)]
    assert soa_ownership.pending_soa_applicability("Client A", 2, 9) == {}
    assert baseline["applicability"] == "Applicable"


def test_working_default_applicable_with_new_rationale_is_still_a_proposal(monkeypatch):
    """An edited default Applicable row must not look already approved."""
    baseline = {
        "control_id": "A.8.16",
        "applicability": "Applicable",
        "inclusion_justification": "",
    }
    key = "soa_working_editor::Client A::2::9"
    monkeypatch.setattr(
        soa_ownership.st,
        "session_state",
        {
            key + "::baseline": [baseline],
            key: [dict(baseline, inclusion_justification="Required for monitoring")],
        },
    )
    assert soa_ownership.pending_soa_applicability("Client A", 2, 9) == {"A.8.16": "Applicable"}
    assert soa_ownership.pending_soa_applicability("Client A", None, None) == {}
