"""Behavioral regressions for the reviewed Kimi UI changes and retained filters."""

from streamlit.testing.v1 import AppTest

from securescope.ui import evidence_hub_ui as ui
from securescope.ui.grc_workspace import context
from tests.test_evidence_scope_submission import record


def test_combined_search_retains_independent_reviewer_and_scope_filters(monkeypatch):
    """Search and advanced filters intersect without widening the server scope query."""
    rows = [
        dict(record(1), title="Wazuh proof", validator="Alice", scope_description="Scope one"),
        dict(record(2), title="Wazuh proof", validator="Bob", scope_description="Scope one"),
        dict(record(3), title="Wazuh proof", validator="Alice", scope_description="Scope two"),
    ]
    calls = []

    def records(client, **kwargs):
        """Return synthetic records and capture the query's unchanged association limits."""
        calls.append((client, kwargs))
        return rows

    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 3))
    monkeypatch.setattr(ui, "list_evidence_records", records)
    app = AppTest.from_string(
        """
from securescope.ui.evidence_hub_ui import _evidence_register
_evidence_register("Client", "reader@example.invalid", None)
"""
    ).run()
    assert not app.exception
    inputs = {item.label: item for item in app.text_input}
    inputs["Search evidence"].set_value("wazuh")
    inputs["Reviewer search"].set_value("alice")
    inputs["Scope search"].set_value("one")
    app.run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 1
    assert calls[-1] == ("Client", {"scope_id": 3, "engagement_id": 2})


def test_empty_register_does_not_offer_auditor_collection(monkeypatch):
    """The Auditor remains on its permitted read-only evidence navigation."""
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 3))
    monkeypatch.setattr(ui, "list_evidence_records", lambda *args, **kwargs: [])
    app = AppTest.from_string(
        """
from securescope.ui.evidence_hub_ui import _evidence_register
from securescope.evidence.models import WorkspaceRole
_evidence_register("Client", "auditor@example.invalid", WorkspaceRole.AUDITOR)
"""
    ).run()
    assert not app.exception
    assert "Open automated collection" not in [b.label for b in app.button]
