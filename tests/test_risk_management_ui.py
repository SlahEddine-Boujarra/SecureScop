"""Exercise visible register creation and role restrictions without a database."""

from unittest.mock import MagicMock

import pytest
from streamlit.testing.v1 import AppTest

from securescope.ui import assurance_workbench, risk_management


@pytest.fixture
def screen(monkeypatch):
    saved = MagicMock(return_value="new-register")
    monkeypatch.setattr(risk_management, "current_actor", lambda: "owner@example.test")
    monkeypatch.setattr(risk_management, "get_workspace_role", lambda *args: "Administrator")
    monkeypatch.setattr(risk_management, "put_record", saved)
    monkeypatch.setattr(assurance_workbench, "render_risk_workbench", lambda *args, **kwargs: None)
    app = AppTest.from_string(
        "from securescope.ui.risk_management import render_risk_management\n"
        "render_risk_management('Client')"
    ).run()
    return app, saved


def press(app, label):
    next(b for b in app.button if b.label == label).click().run()


def test_register_save_uses_current_client_and_opens_saved_register(screen):
    app, saved = screen
    app.session_state["risk_register_create::Client"] = True
    app.run()
    app.text_input[0].set_value("Production")
    press(app, "Save risk register")
    assert not app.exception
    assert saved.call_args.args[:3] == ("Client", "risk_group", "")
    assert saved.call_args.kwargs["actor"] == "owner@example.test"
    assert app.session_state["risk::Client:group"] == "new-register"
    assert app.success


def test_failed_save_keeps_form_and_never_reports_success(screen):
    app, saved = screen
    saved.side_effect = ValueError("Concurrent change")
    app.session_state["risk_register_create::Client"] = True
    app.run()
    app.text_input[0].set_value("Production")
    press(app, "Save risk register")
    assert app.text_input[0].value == "Production"
    assert app.error and not app.success


@pytest.mark.parametrize("stage", ["Methodology", "Risk acceptance", "Residual assessment"])
def test_unfinished_workflow_is_explicit(screen, stage):
    app, _ = screen
    app.session_state["risk_management::Client"] = stage
    app.run()
    assert not app.exception
    assert "Coming Soon" in " ".join(e.value for e in [*app.warning, *app.caption])


def test_auditor_cannot_open_creation_even_with_forged_ui_flag(screen, monkeypatch):
    app, saved = screen
    monkeypatch.setattr(risk_management, "get_workspace_role", lambda *args: "Auditor")
    app.session_state["risk_register_create::Client"] = True
    app.run()
    assert not any(b.label == "Add Risk Register" for b in app.button)
    assert not app.text_input
    saved.assert_not_called()
