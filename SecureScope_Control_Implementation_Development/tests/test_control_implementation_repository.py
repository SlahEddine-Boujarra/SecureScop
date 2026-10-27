"""Test authorization, scoped inputs and immutable encrypted recording."""

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from securescope.integrations.credential_store import open_configuration
from securescope.persistence import control_implementation_repository as repository
from securescope.persistence.foundation_repository import FoundationError


@pytest.fixture
def service(monkeypatch):
    """Service.

    Args:
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    from cryptography.fernet import Fernet

    from securescope.integrations import credential_store

    key = Fernet.generate_key()
    monkeypatch.setattr(credential_store, "credential_cipher", lambda: Fernet(key))
    cursor = MagicMock()

    @contextmanager
    def workspace(client):
        """Workspace.

        Args:
            client: Isolated test input or fixture.
        Returns:
            Test fixture data or None.
        Raises:
            AssertionError: If the required behavior is violated.
        """
        assert client == "Client"
        yield cursor, 7

    bundle = {"profile": {"id": 12, "control_id": "A.8.16", "profile_version": 1}, "assessment": {}}
    loaded, appended = MagicMock(return_value=bundle), MagicMock()
    monkeypatch.setattr(repository, "workspace_cursor", workspace)
    monkeypatch.setattr(repository, "member_role", lambda *args: "Consultant")
    monkeypatch.setattr(repository, "_load_bundle", loaded)
    monkeypatch.setattr(repository, "_append_audit_event", appended)
    return bundle, loaded, appended


def test_save_reloads_and_encrypts_snapshot(service):
    """Save reloads and encrypts snapshot.

    Args:
        service: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle, loaded, appended = service
    result = repository.save_implementation_evaluation(
        "Client", "A.8.16", "real@example.test", repository.input_fingerprint(bundle)
    )
    assert result["status"] == "Not Assessed"
    assert loaded.call_args.args[1:] == (7, "A.8.16")
    args = appended.call_args.kwargs
    assert args["actor"] == "real@example.test"
    assert set(args["payload"]) == {"snapshot_ciphertext"}
    decoded = open_configuration(args["payload"]["snapshot_ciphertext"].encode())
    assert decoded["inputs"] == bundle
    assert decoded["recorded_by"] == "real@example.test"


def test_stale_preview_cannot_be_saved(service):
    """Stale preview cannot be saved.

    Args:
        service: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    _, _, appended = service
    with pytest.raises(FoundationError, match="changed"):
        repository.save_implementation_evaluation("Client", "A.8.16", "actor", "old hash")
    appended.assert_not_called()


@pytest.mark.parametrize("role", ["", "Auditor", "Client contributor"])
def test_unprivileged_actor_cannot_save(service, monkeypatch, role):
    """Unprivileged actor cannot save.

    Args:
        service: Isolated test input or fixture.
        monkeypatch: Isolated test input or fixture.
        role: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle, loaded, appended = service
    monkeypatch.setattr(repository, "member_role", lambda *args: role)
    with pytest.raises(FoundationError, match="membership"):
        repository.save_implementation_evaluation(
            "Client", "A.8.16", "actor", repository.input_fingerprint(bundle)
        )
    loaded.assert_not_called()
    appended.assert_not_called()


def test_denied_reader_cannot_load_inputs(service, monkeypatch):
    """Denied reader cannot load inputs.

    Args:
        service: Isolated test input or fixture.
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    _, loaded, _ = service
    monkeypatch.setattr(repository, "member_role", lambda *args: "")
    with pytest.raises(FoundationError, match="membership"):
        repository.implementation_view("Client", "A.8.16", "outsider")
    loaded.assert_not_called()


def test_changed_inputs_keep_historical_result(service):
    """Changed inputs keep historical result.

    Args:
        service: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle, _, _ = service
    old = {
        "inputs": bundle,
        "result": {"status": "Implemented", "input_fingerprint": "old"},
        "recorded_by": "reviewer",
    }
    encrypted = repository.seal_configuration(old).decode()
    with repository.workspace_cursor("Client") as (cursor, _):
        cursor.fetchone.return_value = {"event_payload": {"snapshot_ciphertext": encrypted}}
    view = repository.implementation_view("Client", "A.8.16", "actor")
    assert view["inputs_changed"]
    assert view["previous"]["result"]["status"] == "Implemented"
    assert view["current"]["status"] == "Not Assessed"


def test_bundle_queries_use_trusted_client():
    """Bundle queries use trusted client.

    Args:
        None.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        {"id": 2, "control_id": "A.8.16", "assessment_scope": {}},
        {},
        {},
        {},
        None,
        {},
    ]
    cursor.fetchall.return_value = []
    assert repository._load_bundle(cursor, 42, "A.8.16")["profile"]["id"] == 2
    for call in cursor.execute.call_args_list:
        assert "client_id=%s" in call.args[0]
        assert call.args[1][0] == 42


def test_requirements_pin_versions_in_existing_profile(service, monkeypatch):
    """Requirements pin versions in existing profile.

    Args:
        service: Isolated test input or fixture.
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    bundle, _, _ = service
    bundle["profile"].update(
        measurement_model="checklist",
        control_owner="IT",
        assessment_owner="Reviewer",
        assessment_scope={"description": "Production", "unit_ids": [8]},
        assessment_methods=["Test"],
        evidence_requirements=["Reports"],
        automation_level="Manual",
        supported_data_sources=[],
    )
    with repository.workspace_cursor("Client") as (cursor, _):
        cursor.fetchone.side_effect = [{"id": 3}, {"id": 9, "status": "Approved"}]
    monkeypatch.setattr(
        repository,
        "_documents",
        lambda *args: [{"policy_id": "policy-1", "policy_version": 4, "controls": ["A.8.16"]}],
    )
    saved = MagicMock(return_value=2)
    monkeypatch.setattr(repository, "create_profile_version", saved)
    assert (
        repository.save_implementation_requirements(
            "Client",
            "A.8.16",
            "actor",
            1,
            engagement=2,
            scope=3,
            policy_ids=["policy-1"],
            procedure_ids=[],
            policy_rationale="",
            procedure_rationale="Procedure included",
            review_days=60,
            criteria=["Alerts reviewed"],
        )
        == 2
    )
    scope = saved.call_args.kwargs["assessment_scope"]
    assert scope["unit_ids"] == [8]
    assert scope["implementation_requirements"]["policy_links"] == [
        {"id": "policy-1", "version": 4}
    ]
    assert scope["implementation_requirements"]["scope_version_id"] == 9
    assert saved.call_args.kwargs["expected_profile_version"] == 1


def test_foreign_document_cannot_be_linked(service, monkeypatch):
    """Foreign document cannot be linked.

    Args:
        service: Isolated test input or fixture.
        monkeypatch: Isolated test input or fixture.
    Returns:
        Test fixture data or None.
    Raises:
        AssertionError: If the required behavior is violated.
    """
    with repository.workspace_cursor("Client") as (cursor, _):
        cursor.fetchone.side_effect = [{"id": 3}, {"id": 9, "status": "Approved"}]
    monkeypatch.setattr(repository, "_documents", lambda *args: [])
    saved = MagicMock()
    monkeypatch.setattr(repository, "create_profile_version", saved)
    with pytest.raises(FoundationError, match="mapped"):
        repository.save_implementation_requirements(
            "Client",
            "A.8.16",
            "actor",
            1,
            engagement=2,
            scope=3,
            policy_ids=["foreign"],
            procedure_ids=[],
            policy_rationale="",
            procedure_rationale="Procedure included",
            review_days=60,
            criteria=["Alerts reviewed"],
        )
    saved.assert_not_called()
