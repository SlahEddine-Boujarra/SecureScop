"""Exercise binding forms and source inspection with Streamlit's runtime harness."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.integrations.wazuh_service import WazuhError
from securescope.ui import wazuh_monitoring_ui as ui


@pytest.fixture
def editor(monkeypatch):
    """Supply synthetic inventory with no database, credentials or live Wazuh."""
    monkeypatch.setattr(ui, "require_connector_admin", lambda *a: None)
    monkeypatch.setattr(ui, "WazuhClient", lambda: SimpleNamespace(connector_id="test-source"))
    monkeypatch.setattr(
        ui,
        "load_latest_wazuh_status",
        lambda *a: [{"asset_id": 7, "asset_tag": "TEST", "asset_ip": "192.0.2.7"}],
    )
    monkeypatch.setattr(ui, "list_monitoring_bindings", lambda *a: [])
    save = MagicMock(return_value=1)
    monkeypatch.setattr(ui, "approve_monitoring_binding", save)
    app = AppTest.from_string(
        "from securescope.ui.wazuh_monitoring_ui import render_monitoring_bindings\n"
        "render_monitoring_bindings('Workspace', 'admin@example.invalid')\n"
    ).run()
    assert not app.exception
    return app, save


def test_binding_form_requires_explicit_identity_confirmation(editor):
    """An unconfirmed submission must not call the identity mutation."""
    app, save = editor
    app.button[0].click().run()
    assert not app.exception
    assert any("Confirm the exact" in warning.value for warning in app.warning)
    save.assert_not_called()


def test_binding_form_preserves_asset_policy_and_actor(editor):
    """Explicit submission sends the selected stable asset and policy to authorization."""
    app, save = editor
    app.text_input[0].set_value("manager")
    app.text_input[1].set_value("007")
    app.text_area[0].set_value("Confirmed in Wazuh inventory")
    app.checkbox[0].check()
    app.button[0].click().run()
    assert not app.exception
    save.assert_called_once_with(
        "Workspace",
        "admin@example.invalid",
        asset_id=7,
        connector_id="test-source",
        manager_name="manager",
        agent_id="007",
        heartbeat_max_age_seconds=300,
        telemetry_max_age_seconds=3600,
        rationale="Confirmed in Wazuh inventory",
    )


def test_non_administrator_cannot_open_binding_editor(monkeypatch):
    """Unauthorized users see explanatory text without configuration or write controls."""
    monkeypatch.setattr(ui, "require_connector_admin", MagicMock(side_effect=WazuhError("Denied")))
    client = MagicMock()
    monkeypatch.setattr(ui, "WazuhClient", client)
    app = AppTest.from_string(
        "from securescope.ui.wazuh_monitoring_ui import render_monitoring_bindings\n"
        "render_monitoring_bindings('Workspace', 'viewer@example.invalid')\n"
    ).run()
    assert not app.exception
    assert not app.button
    client.assert_not_called()


def test_source_inspector_shows_reason_without_compliance_claim():
    """The selected asset exposes source state and the human-assessment boundary."""
    app = AppTest.from_string(
        "from securescope.ui.wazuh_monitoring_ui import render_monitoring_detail\n"
        "render_monitoring_detail([dict(asset_id=7, asset_ip='192.0.2.7', "
        "monitoring_status='Agent active — telemetry unverified', "
        "monitoring_reason='No current security event')], 'Workspace')\n"
    ).run()
    assert not app.exception
    assert any("No current security event" in caption.value for caption in app.caption)
    assert any("human assessment" in caption.value for caption in app.caption)
