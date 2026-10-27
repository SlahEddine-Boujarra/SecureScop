"""Connector authorization, encrypted persistence, and TLS regression checks."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from securescope.integrations import credential_store, wazuh_service


@pytest.fixture
def connector_host(monkeypatch, tmp_path: Path):
    """Configure an isolated authorized host; no network or database is used."""
    identity = "administrator@example.test"
    monkeypatch.setenv("SECURESCOPE_CURRENT_USER_EMAIL", identity)
    monkeypatch.setenv("SECURESCOPE_CONNECTOR_ADMINS", identity)
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(wazuh_service, "get_workspace_role", lambda *_: "Administrator")
    location = tmp_path / "connection.enc"
    monkeypatch.setattr(credential_store, "configuration_path", lambda: location)
    for key in (
        "WAZUH_API_PASSWORD",
        "WAZUH_INDEXER_PASSWORD",
        "WAZUH_VERIFY_TLS",
        "WAZUH_INDEXER_VERIFY_TLS",
    ):
        monkeypatch.delenv(key, raising=False)
    yield identity, location


def test_connector_requires_host_and_workspace_administration(connector_host, monkeypatch):
    """Workspace role and host allowlist are both required before any write."""
    actor, path = connector_host
    monkeypatch.setattr(wazuh_service, "get_workspace_role", lambda *_: "Consultant")
    with pytest.raises(wazuh_service.WazuhError):
        wazuh_service.save_wazuh_config(
            "https://manager.example.test",
            "wazuh",
            "new-secret",
            client_name="Client A",
            actor=actor,
        )
    assert not path.exists()
    monkeypatch.setattr(wazuh_service, "get_workspace_role", lambda *_: "Administrator")
    monkeypatch.setenv("SECURESCOPE_CONNECTOR_ADMINS", "")
    with pytest.raises(wazuh_service.WazuhError):
        wazuh_service.require_connector_admin("Client A", actor)


def test_save_encrypts_secrets_and_enables_both_tls_checks(connector_host, monkeypatch):
    """New passwords are encrypted and blank replacements preserve saved values."""
    actor, path = connector_host
    wazuh_service.save_wazuh_config(
        "https://manager.example.test",
        "wazuh",
        "new-api-secret",
        indexer_url="https://indexer.example.test",
        indexer_user="indexer",
        indexer_password="new-indexer-secret",
        client_name="Client A",
        actor=actor,
    )
    assert b"new-api-secret" not in path.read_bytes()
    saved = credential_store.load_configuration()
    assert saved["WAZUH_VERIFY_TLS"] == saved["WAZUH_INDEXER_VERIFY_TLS"] == "true"
    monkeypatch.setenv("WAZUH_API_PASSWORD", "obsolete-environment-value")
    wazuh_service.save_wazuh_config(
        "https://manager.example.test",
        "wazuh",
        "",
        client_name="Client A",
        actor=actor,
        verify_indexer_tls=False,
    )
    saved = credential_store.load_configuration()
    assert saved["WAZUH_API_PASSWORD"] == "new-api-secret"
    assert saved["WAZUH_INDEXER_PASSWORD"] == "new-indexer-secret"
    assert saved["WAZUH_VERIFY_TLS"] == "true"
    assert saved["WAZUH_INDEXER_VERIFY_TLS"] == "false"


def test_persistence_failure_does_not_publish_new_runtime_credentials(connector_host, monkeypatch):
    """A failed atomic save leaves the previous runtime secret intact."""
    actor, path = connector_host
    monkeypatch.setenv("WAZUH_API_PASSWORD", "previous-secret")

    def fail_replace(*_args):
        """Simulate a filesystem failure before the encrypted file is published."""
        raise OSError("disk unavailable")

    monkeypatch.setattr(credential_store.os, "replace", fail_replace)
    with pytest.raises(credential_store.CredentialStoreError):
        wazuh_service.save_wazuh_config(
            "https://manager.example.test",
            "wazuh",
            "replacement-secret",
            client_name="Client A",
            actor=actor,
        )
    assert wazuh_service.os.environ["WAZUH_API_PASSWORD"] == "previous-secret"
    assert not path.exists()
