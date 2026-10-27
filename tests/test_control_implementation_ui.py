"""Exercise visible saves, error feedback and existing local identity."""

from unittest.mock import MagicMock

from streamlit.testing.v1 import AppTest

from securescope.persistence.foundation_repository import FoundationError
from securescope.ui import control_implementation_ui as ui


def test_visible_save_and_feedback(monkeypatch):
    """Visible save and feedback.

    Args:
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    monkeypatch.setattr(ui, "current_actor", lambda: "reviewer@example.test")
    monkeypatch.setattr(
        ui,
        "implementation_view",
        lambda *args: {
            "bundle": {"profile": {"profile_version": 2}},
            "previous": None,
            "current": {
                "status": "Verification Pending",
                "checks": [],
                "input_fingerprint": "version",
            },
        },
    )
    saved = MagicMock(return_value={"status": "Verification Pending"})
    monkeypatch.setattr(ui, "save_implementation_evaluation", saved)
    app = AppTest.from_string(
        "from securescope.ui.control_implementation_ui import "
        "render_implementation\nrender_implementation('Client','A.8.16','Co"
        "nsultant')"
    ).run()
    app.button[0].click().run()
    assert not app.exception
    assert app.success
    assert saved.call_args.args == ("Client", "A.8.16", "reviewer@example.test", "version")


def test_stale_save_shows_error_without_success(monkeypatch):
    """Stale save shows error without success.

    Args:
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    monkeypatch.setattr(ui, "current_actor", lambda: "reviewer@example.test")
    monkeypatch.setattr(
        ui,
        "implementation_view",
        lambda *args: {
            "bundle": {"profile": {"profile_version": 2}},
            "previous": None,
            "current": {"status": "Implemented", "checks": [], "input_fingerprint": "old"},
        },
    )
    monkeypatch.setattr(
        ui,
        "save_implementation_evaluation",
        MagicMock(side_effect=FoundationError("Inputs changed")),
    )
    app = AppTest.from_string(
        "from securescope.ui.control_implementation_ui import "
        "render_implementation\nrender_implementation('Client','A.8.16','Co"
        "nsultant')"
    ).run()
    app.button[0].click().run()
    assert not app.exception
    assert app.error[0].value == "Inputs changed"
    assert not app.success


def test_local_session_identity_requires_membership(monkeypatch):
    """Local session identity requires membership.

    Args:
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    from securescope.ui import evidence_hub_ui
    from securescope.ui.grc_workspace import context

    monkeypatch.setattr(context, "current_actor", lambda: "local-admin@example.test")
    membership = MagicMock(return_value="Administrator")
    monkeypatch.setattr(evidence_hub_ui, "get_workspace_role", membership)
    actor, role = evidence_hub_ui._identity("Client")
    assert actor == "local-admin@example.test"
    assert role.value == "Administrator"
    membership.assert_called_once_with("Client", "local-admin@example.test")
    membership.return_value = ""
    assert evidence_hub_ui._identity("Client")[1] is None
