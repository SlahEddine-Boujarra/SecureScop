"""Workspace-isolated raw evidence artifact storage."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from securescope.paths import PROJECT_ROOT

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceStorageError(RuntimeError):
    """Raised when an evidence artifact cannot be stored safely."""


@dataclass(frozen=True)
class StoredArtifact:
    """Immutable storage metadata persisted in PostgreSQL."""

    artifact_uuid: str
    original_filename: str
    storage_reference: str
    byte_size: int
    sha256: str
    encrypted: bool


def evidence_root() -> Path:
    """Return the configured artifact root outside database tables."""

    configured = os.getenv("SECURESCOPE_EVIDENCE_STORAGE_ROOT", "evidence_store")
    root = Path(configured)
    if not root.is_absolute():
        root = PROJECT_ROOT / root
    return root.resolve()


def _safe_filename(filename: str) -> str:
    """Return a basename safe for cross-platform artifact storage."""

    base = Path(filename).name
    cleaned = SAFE_NAME.sub("_", base).strip("._")
    return (cleaned or "evidence.bin")[:180]


def _encrypt_if_configured(content: bytes) -> tuple[bytes, bool]:
    """Encrypt artifact bytes when a Fernet key is configured."""

    key = os.getenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", "").strip()
    if not key:
        return content, False
    try:
        from cryptography.fernet import Fernet

        return Fernet(key.encode("ascii")).encrypt(content), True
    except (ImportError, ValueError, TypeError) as exc:
        raise EvidenceStorageError(
            "Evidence encryption is configured but its key or dependency is invalid."
        ) from exc


def store_artifact(
    client_id: int, filename: str, content: bytes, *, allow_empty: bool = False
) -> StoredArtifact:
    """Store one artifact atomically beneath a numeric workspace directory.

    Args:
        client_id: Positive canonical client identifier.
        filename: Original name, sanitized before storage.
        content: Raw artifact bytes, optionally encrypted at rest.
        allow_empty: Permit a trusted completed scan with zero findings.
    Returns:
        Stored artifact metadata including the hash of the original bytes.
    Raises:
        EvidenceStorageError: For invalid input, encryption or storage failure.
    """

    if int(client_id) <= 0:
        raise EvidenceStorageError("A positive client_id is required for artifact storage.")
    max_bytes = int(os.getenv("SECURESCOPE_EVIDENCE_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
    if (not content and not allow_empty) or len(content) > max_bytes:
        raise EvidenceStorageError(f"Artifact must contain 1 to {max_bytes} bytes.")
    artifact_uuid = str(uuid.uuid4())
    raw_sha256 = hashlib.sha256(content).hexdigest()
    stored_content, encrypted = _encrypt_if_configured(content)
    root = evidence_root()
    workspace_root = (root / str(int(client_id))).resolve()
    if root not in workspace_root.parents:
        raise EvidenceStorageError("Invalid workspace artifact path.")
    destination_directory = workspace_root / artifact_uuid[:2]
    destination_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    suffix = ".enc" if encrypted else ""
    destination = destination_directory / (f"{artifact_uuid}_{_safe_filename(filename)}{suffix}")
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(dir=destination_directory, delete=False) as temporary:
            temporary.write(stored_content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    except OSError as exc:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
        raise EvidenceStorageError(f"Unable to store evidence artifact: {exc}") from exc
    return StoredArtifact(
        artifact_uuid=artifact_uuid,
        original_filename=_safe_filename(filename),
        storage_reference=destination.relative_to(root).as_posix(),
        byte_size=len(content),
        sha256=raw_sha256,
        encrypted=encrypted,
    )


def read_artifact(
    client_id: int, storage_reference: str, *, expected_sha256: str | None = None
) -> bytes:
    """Read and optionally decrypt one workspace-owned artifact."""

    root = evidence_root()
    workspace_root = (root / str(int(client_id))).resolve()
    candidate = (root / storage_reference).resolve()
    if workspace_root != candidate.parent and workspace_root not in candidate.parents:
        raise EvidenceStorageError("Artifact reference is outside the active workspace.")
    try:
        content = candidate.read_bytes()
    except OSError as exc:
        raise EvidenceStorageError(f"Unable to read evidence artifact: {exc}") from exc
    if candidate.suffix != ".enc":
        return _verified_bytes(content, expected_sha256)
    key = os.getenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", "").strip()
    if not key:
        raise EvidenceStorageError("Evidence decryption key is not configured.")
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:
        raise EvidenceStorageError("The cryptography dependency is unavailable.") from exc
    try:
        return _verified_bytes(Fernet(key.encode("ascii")).decrypt(content), expected_sha256)
    except (ValueError, InvalidToken) as exc:
        raise EvidenceStorageError("Unable to decrypt evidence artifact.") from exc


def _verified_bytes(content: bytes, expected_sha256: str | None) -> bytes:
    """Return plaintext content; raise EvidenceStorageError on an expected-hash mismatch."""
    if expected_sha256 and hashlib.sha256(content).hexdigest() != expected_sha256:
        raise EvidenceStorageError("Evidence artifact SHA-256 mismatch.")
    return content


def store_protected_artifact(client_id: int, filename: str, content: bytes) -> StoredArtifact:
    """Store M2 bytes with mandatory encryption; raise EvidenceStorageError if unavailable."""
    if not os.getenv("SECURESCOPE_EVIDENCE_ENCRYPTION_KEY", "").strip():
        raise EvidenceStorageError("M2 evidence requires a configured encryption key.")
    artifact = store_artifact(client_id, filename, content)
    if not artifact.encrypted:
        raise EvidenceStorageError("M2 evidence protection is unavailable.")
    return artifact
