"""Scanner-engine selection and capability helpers for SecureScope.

The UI can switch between Greenbone/OpenVAS and ProjectDiscovery Nuclei
without changing client, asset, ISO, Wazuh or reporting workflows. Every
persisted job retains its exact provider identity.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from typing import Iterable

ENGINE_OPENVAS = "OpenVAS"
ENGINE_NUCLEI = "Nuclei"
KNOWN_ENGINES = (ENGINE_OPENVAS, ENGINE_NUCLEI)


def _tokens(value: str) -> list[str]:
    """Split a comma- or semicolon-separated engine list."""

    return [
        token.strip() for token in str(value or "").replace(";", ",").split(",") if token.strip()
    ]


def normalize_engine(value: object, default: str = ENGINE_OPENVAS) -> str:
    """Return the canonical engine name for arbitrary user/config input."""

    text = str(value or "").strip().casefold()
    aliases = {
        "openvas": ENGINE_OPENVAS,
        "greenbone": ENGINE_OPENVAS,
        "gvm": ENGINE_OPENVAS,
        "nuclei": ENGINE_NUCLEI,
        "projectdiscovery": ENGINE_NUCLEI,
        "project discovery": ENGINE_NUCLEI,
    }
    return aliases.get(text, default)


def enabled_engines(raw_value: str | None = None) -> list[str]:
    """Return enabled engines in stable UI order."""

    raw = (
        raw_value
        if raw_value is not None
        else os.getenv(
            "SECURESCOPE_ENABLED_SCAN_ENGINES",
            "OpenVAS,Nuclei",
        )
    )
    requested = {normalize_engine(token, default="") for token in _tokens(raw)}
    resolved = [engine for engine in KNOWN_ENGINES if engine in requested]
    return resolved or [ENGINE_OPENVAS]


def default_engine(
    enabled: Iterable[str] | None = None,
    raw_value: str | None = None,
) -> str:
    """Return the configured default when enabled, otherwise the first."""

    available = list(enabled or enabled_engines())
    configured = normalize_engine(
        raw_value
        if raw_value is not None
        else os.getenv("SECURESCOPE_DEFAULT_SCAN_ENGINE", ENGINE_OPENVAS)
    )
    return configured if configured in available else available[0]


def engine_enabled(engine: object) -> bool:
    """Return whether an engine is enabled by the current environment."""

    return normalize_engine(engine, default="") in enabled_engines()


def persist_engine_selection(
    state: MutableMapping[str, object],
    engine: object,
    available: Iterable[str] | None = None,
) -> str:
    """Persist one enabled engine using a single Streamlit state key."""

    engines = list(available or enabled_engines()) or [ENGINE_OPENVAS]
    selected = normalize_engine(engine, default=engines[0])
    if selected not in engines:
        selected = engines[0]
    state["scan_engine"] = selected
    state.pop("sidebar_scan_engine_selector", None)
    state.pop("scan_center_engine_selector", None)
    return selected


def cycle_engine(current: object, available: Iterable[str] | None = None) -> str:
    """Return the next enabled engine for compact controls."""

    engines = list(available or enabled_engines()) or [ENGINE_OPENVAS]
    normalized = normalize_engine(current, default=engines[0])
    try:
        index = engines.index(normalized)
    except ValueError:
        return engines[0]
    return engines[(index + 1) % len(engines)]


def engine_description(engine: object) -> str:
    """Return a concise provider description."""

    normalized = normalize_engine(engine)
    if normalized == ENGINE_NUCLEI:
        return (
            "ProjectDiscovery Nuclei CLI with signed templates and a " "standalone provider worker."
        )
    return "Greenbone/OpenVAS over the existing GMP SSH tunnel."
