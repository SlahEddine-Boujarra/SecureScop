"""Submission context and register rendering regressions (database transport mocked)."""

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.evidence import evidence_service as service
from securescope.persistence import evidence_repository as repository
from securescope.persistence import foundation_repository as foundation
from securescope.ui import evidence_hub_ui as ui
from securescope.ui.grc_workspace import context


def submission():
    """Return a complete manual submission with a canonical scope context."""
    return dict(
        role="Consultant",
        control_ids=["4.1"],
        evidence_type="Record",
        title="Reviewed context",
        summary="Context review minutes",
        scope_description="Scope one",
        source_asset_or_system="Governance",
        owner="reviewer@example.test",
        submitted_by="reviewer@example.test",
        engagement_id=2,
        scope_id=3,
    )


def record(evidence_id=5):
    """Return a persisted-shaped evidence summary suitable for real Streamlit rendering."""
    return dict(
        id=evidence_id,
        title="Reviewed context",
        tool_id="manual",
        controls=[{"control_id": "4.1"}],
        scope_description="Scope one",
        validation_status="Pending",
        freshness_status="Current",
        collected_at=datetime.now(timezone.utc),
        expires_at=None,
        validator=None,
        collection_method="Manual",
        summary="Context review minutes",
    )


def test_service_forwards_canonical_context(monkeypatch):
    """Submission forwards context rather than deriving a scope from free text."""
    create = MagicMock(return_value=5)
    monkeypatch.setattr(service, "create_evidence_record", create)
    assert service.submit_manual_evidence("Client", **submission()) == 5
    assert create.call_args.kwargs["scope_id"] == 3
    assert create.call_args.kwargs["engagement_id"] == 2


@pytest.mark.parametrize(
    "scope,engagement,membership,found,valid",
    [
        (3, 2, "Consultant", True, True),
        (3, None, "Consultant", True, False),
        (None, 2, "Consultant", True, False),
        (3, 2, "Auditor", True, False),
        (3, 2, "", True, False),
        (3, 2, "Consultant", False, False),
        (None, None, "", False, True),
    ],
)
def test_atomic_submission_context(monkeypatch, scope, engagement, membership, found, valid):
    """Reject invalid context before insertion; preserve deliberately unassigned legacy callers."""
    cursor = MagicMock()
    cursor.fetchone.side_effect = (
        [{"id": 1}]
        + (
            [{"id": 3} if found else None]
            if scope and engagement and membership == "Consultant"
            else []
        )
        + [{"id": 5}, None]
    )
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    outcomes = []

    @contextmanager
    def transaction():
        """Track domain failure propagation through the single transaction boundary."""
        try:
            yield connection
        except repository.EvidenceRepositoryError:
            outcomes.append("rollback")
            raise
        else:
            outcomes.append("commit")

    monkeypatch.setattr(repository, "connect", transaction)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    monkeypatch.setattr(foundation, "member_role", lambda *args: membership)
    arguments = dict(
        tool_id="manual",
        collection_method="Manual",
        evidence_type="Record",
        title="Title",
        summary="Summary",
        scope_description="Description",
        source_asset_or_system="System",
        owner="Owner",
        submitted_by="reviewer@example.test",
        collected_at=datetime.now(timezone.utc),
        expires_at=None,
        confidence="Medium",
        normalized={},
        suggested_controls=["4.1"],
        scope_id=scope,
        engagement_id=engagement,
    )
    if valid:
        assert repository.create_evidence_record("Client", **arguments) == 5
        assert outcomes == ["commit"]
    else:
        with pytest.raises(repository.EvidenceRepositoryError):
            repository.create_evidence_record("Client", **arguments)
        assert outcomes == ["rollback"]
    writes = [call for call in cursor.execute.call_args_list if "INSERT INTO" in call.args[0]]
    if not valid:
        assert not writes
    elif scope:
        links = [call for call in writes if "securescope_engagement_record_links" in call.args[0]]
        assert len(links) == 1
        assert links[0].args[1][:5] == (1, 2, 3, "assurance-evidence:3:5", 5)
    else:
        assert not any("securescope_engagement_record_links" in call.args[0] for call in writes)


def test_register_renders_scoped_and_all_client_records(monkeypatch):
    """Both modes render rows; current scope is passed only to the scoped query."""
    calls = []

    def records(client, **kwargs):
        """Simulate two scopes without replacing any Streamlit rendering component."""
        calls.append(kwargs)
        return (
            [record()] if kwargs["scope_id"] else [record(), dict(record(6), title="Other scope")]
        )

    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 3))
    monkeypatch.setattr(ui, "list_evidence_records", records)
    app = AppTest.from_string("""
from securescope.ui.evidence_hub_ui import _evidence_register
_evidence_register("Client", "reviewer@example.test", None)
""").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 1
    app.selectbox[0].select("All Client Evidence").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 2
    assert calls[-1] == {"scope_id": None, "engagement_id": 2}
    app.selectbox[0].select("Current ISMS Scope").run()
    assert len(app.dataframe[0].value) == 1


def test_manual_form_context_and_success_survive_rerun(monkeypatch):
    """The real form passes selected context and consumes its notice after rerunning."""
    create = MagicMock(return_value=5)
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 3))
    monkeypatch.setattr(ui, "selected_context_ids", lambda client: (2, 3))
    monkeypatch.setattr(ui, "submit_manual_evidence", create)
    app = AppTest.from_string("""
import streamlit as st
from securescope.ui.evidence_hub_ui import _manual_tab
from securescope.evidence.models import WorkspaceRole
notice = st.session_state.pop("evidence_notice::Client", None)
if notice:
    st.success(notice)
_manual_tab("Client", "reviewer@example.test", WorkspaceRole.CONSULTANT)
""").run()
    app.button[0].click().run()
    assert not app.exception
    assert create.call_count == 1
    assert create.call_args.kwargs["scope_id"] == 3
    assert create.call_args.kwargs["engagement_id"] == 2
    assert app.success[0].value == "Manual evidence #5 submitted for review."
    app.run()
    assert create.call_count == 1
    assert not app.success
