"""M2 control surfaces use the existing trusted context; these are not authentication tests."""

from unittest.mock import Mock

from streamlit.testing.v1 import AppTest

from securescope.persistence import evidence_schedule_repository as schedules
from securescope.ui import wazuh_monitoring_ui as ui
from tests.test_api_evidence_contracts import api_client  # noqa: F401

TARGET = dict(
    asset_id=1,
    binding_id=2,
    engagement_id=3,
    scope_id=4,
    scope_version_id=5,
    profile_id=6,
    requirement_id="monitoring",
    control_id="A.8.16",
)


def test_http_schedule_keeps_verified_workspace_identity(api_client, monkeypatch):
    """HTTP callers cannot substitute the workspace/approver used by schedule authorization."""
    create = Mock(return_value=7)
    monkeypatch.setattr(schedules, "create_schedule", create)
    response = api_client.post(
        "/v1/evidence-schedules", json=dict(name="Test", connector_id="source", targets=[TARGET])
    )
    assert response.status_code == 201
    assert response.json() == dict(schedule_id=7, enabled=False)
    assert create.call_args.args == ("Client Alpha", "operator@example.invalid")
    assert create.call_args.kwargs["targets"] == [
        dict(TARGET, accept_health=False, health_policy={})
    ]


def test_http_rejects_clock_dispatch_and_empty_targets(api_client, monkeypatch):
    """The typed M2 surface cannot enqueue A.8.17 or an unbounded implicit target set."""
    create = Mock()
    monkeypatch.setattr(schedules, "create_schedule", create)
    for targets in ([], [dict(TARGET, control_id="A.8.17")]):
        response = api_client.post(
            "/v1/evidence-schedules", json=dict(name="Test", connector_id="source", targets=targets)
        )
        assert response.status_code == 422
    create.assert_not_called()


def test_schedule_ui_requires_explicit_approval_and_pins_selected_target(monkeypatch):
    """The existing Streamlit screen creates a disabled schedule only after explicit selection/approval."""
    monkeypatch.setattr(ui, "require_connector_admin", lambda *args: None)
    monkeypatch.setattr(schedules, "list_schedules", lambda *args: [])
    monkeypatch.setattr(
        schedules,
        "schedule_candidates",
        lambda *args: [dict(TARGET, label="Test asset / scope", health_allowed=False)],
    )
    create = Mock(return_value=7)
    monkeypatch.setattr(schedules, "create_schedule", create)
    app = AppTest.from_string(
        "from securescope.ui.wazuh_monitoring_ui import render_collection_schedules\n"
        "render_collection_schedules('Workspace','admin@example.invalid')"
    ).run()
    assert not app.exception and app.button[0].disabled
    app.multiselect[0].set_value([0]).run()
    assert app.button[0].disabled
    app.checkbox[-1].check().run()
    app.button[0].click().run()
    assert not app.exception
    create.assert_called_once()
    assert create.call_args.args == ("Workspace", "admin@example.invalid")
    sent = create.call_args.kwargs["targets"][0]
    assert all(sent[k] == v for k, v in TARGET.items())
    assert not sent["accept_health"]
