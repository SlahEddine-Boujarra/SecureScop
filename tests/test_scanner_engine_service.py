"""Tests for the OpenVAS/Nuclei selector and aliases."""

from securescope.core.scanner_engine_service import (
    ENGINE_NUCLEI,
    ENGINE_OPENVAS,
    cycle_engine,
    default_engine,
    enabled_engines,
    normalize_engine,
    persist_engine_selection,
)


def test_engine_aliases_are_normalized() -> None:
    assert normalize_engine("greenbone") == ENGINE_OPENVAS
    assert normalize_engine("projectdiscovery") == ENGINE_NUCLEI


def test_enabled_engines_preserve_stable_order() -> None:
    assert enabled_engines("Nuclei,GVM") == [ENGINE_OPENVAS, ENGINE_NUCLEI]


def test_default_falls_back_to_enabled_engine() -> None:
    assert default_engine([ENGINE_NUCLEI], "OpenVAS") == ENGINE_NUCLEI


def test_cycle_engine() -> None:
    assert cycle_engine(ENGINE_OPENVAS) == ENGINE_NUCLEI
    assert cycle_engine(ENGINE_NUCLEI) == ENGINE_OPENVAS


def test_persist_engine_selection_uses_one_state_key() -> None:
    state = {
        "scan_engine": ENGINE_OPENVAS,
        "sidebar_scan_engine_selector": ENGINE_OPENVAS,
        "scan_center_engine_selector": ENGINE_OPENVAS,
    }
    selected = persist_engine_selection(
        state,
        ENGINE_NUCLEI,
        [ENGINE_OPENVAS, ENGINE_NUCLEI],
    )
    assert selected == ENGINE_NUCLEI
    assert state["scan_engine"] == ENGINE_NUCLEI
    assert "sidebar_scan_engine_selector" not in state
    assert "scan_center_engine_selector" not in state


def test_persist_engine_selection_rejects_disabled_engine() -> None:
    state = {}
    selected = persist_engine_selection(
        state,
        ENGINE_NUCLEI,
        [ENGINE_OPENVAS],
    )
    assert selected == ENGINE_OPENVAS
    assert state["scan_engine"] == ENGINE_OPENVAS
