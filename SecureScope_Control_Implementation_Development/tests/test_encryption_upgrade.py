"""Exercise evidence and connector storage with the upgraded Fernet dependency."""

import hashlib

import pytest
from cryptography.fernet import Fernet

from securescope.evidence.storage import EvidenceStorageError, read_artifact, store_artifact
from securescope.integrations.credential_store import (
    CredentialStoreError,
    open_configuration,
    seal_configuration,
)


def test_encrypted_evidence_round_trip_and_workspace_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", Fernet.generate_key().decode())
    content = "Confidential audit evidence — français".encode()
    artifact = store_artifact(41, "audit.txt", content)
    ciphertext = (tmp_path / artifact.storage_reference).read_bytes()
    assert artifact.encrypted
    assert content not in ciphertext
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert read_artifact(41, artifact.storage_reference) == content
    with pytest.raises(EvidenceStorageError, match="outside the active workspace"):
        read_artifact(42, artifact.storage_reference)
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(EvidenceStorageError, match="Unable to decrypt"):
        read_artifact(41, artifact.storage_reference)


def test_connector_round_trip_rejects_wrong_key_and_modified_ciphertext(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", key)
    configuration = {"endpoint": "https://example.invalid", "password": "synthetic-fixture"}
    ciphertext = seal_configuration(configuration)
    assert b"synthetic-fixture" not in ciphertext
    assert open_configuration(ciphertext) == configuration
    with pytest.raises(CredentialStoreError, match="could not be decrypted"):
        open_configuration(ciphertext[:-8] + b"tampered")
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(CredentialStoreError, match="could not be decrypted"):
        open_configuration(ciphertext)
