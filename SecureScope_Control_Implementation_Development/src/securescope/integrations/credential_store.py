"""Encrypted, atomic host connector configuration; never sends secrets to widgets."""

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from securescope.paths import PROJECT_ROOT

LOGGER = logging.getLogger(__name__)


class CredentialStoreError(RuntimeError):
    """A secret cannot be encrypted, read, or persisted safely."""


def credential_cipher() -> Fernet:
    """Resolve the encryption key supplied by the host administrator.

    Returns:
        Configured authenticated-encryption cipher.
    Raises:
        CredentialStoreError: If the external key is missing or invalid.
    """
    try:
        key = os.environ["SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY"].encode("ascii")
        return Fernet(key)
    except (KeyError, ValueError, UnicodeError) as exc:
        raise CredentialStoreError(
            (
                "Configure SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY on the host to "
                "save encrypted policies and connector settings. Preserve the "
                "existing key when upgrading."
            )
        ) from exc


def seal_configuration(configuration: dict[str, Any]) -> bytes:
    """Encrypt a validated connector configuration or pending change.

    Args:
        configuration: Settings to encrypt.
    Returns:
        Authenticated ciphertext.
    Raises:
        CredentialStoreError: If encryption is unavailable.
    """
    return credential_cipher().encrypt(json.dumps(configuration).encode("utf-8"))


def open_configuration(ciphertext: bytes) -> dict[str, Any]:
    """Decrypt connector settings only within the server process.

    Args:
        ciphertext: Stored authenticated ciphertext.
    Returns:
        Server-only configuration.
    Raises:
        CredentialStoreError: If decryption or validation fails.
    """
    try:
        value = json.loads(credential_cipher().decrypt(ciphertext))
        if not isinstance(value, dict):
            raise ValueError("Configuration must be an object")
        return value
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise CredentialStoreError("Connector configuration could not be decrypted.") from exc


def configuration_path() -> Path:
    """Return the host's encrypted Wazuh configuration location.

    Returns:
        Path excluded from release packages by the data-directory rule.
    Raises:
        No exceptions are raised.
    """
    return PROJECT_ROOT / "data" / "wazuh_connection.enc"


def load_configuration() -> dict[str, Any]:
    """Load saved encrypted settings, falling back only when no store exists.

    Returns:
        Stored settings, or an empty dictionary for environment-only installs.
    Raises:
        CredentialStoreError: If an existing store cannot be read or decrypted.
    """
    path = configuration_path()
    if not path.exists():
        return {}
    try:
        return open_configuration(path.read_bytes())
    except OSError as exc:
        raise CredentialStoreError("Connector configuration could not be read.") from exc


def store_configuration(configuration: dict[str, Any]) -> None:
    """Atomically replace the encrypted host configuration.

    Args:
        configuration: Validated settings, including credentials.
    Returns:
        None.
    Raises:
        CredentialStoreError: If encryption or disk persistence fails.
    """
    ciphertext = seal_configuration(configuration)
    path = configuration_path()
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, suffix=".enc")
        with os.fdopen(descriptor, "wb") as output:
            output.write(ciphertext)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        LOGGER.error("Encrypted connector configuration write failed (%s)", type(exc).__name__)
        raise CredentialStoreError(
            "Connector settings could not be saved; runtime settings are unchanged."
        ) from exc
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()
