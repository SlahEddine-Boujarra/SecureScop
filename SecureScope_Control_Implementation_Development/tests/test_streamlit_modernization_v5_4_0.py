"""Regression contracts for SecureScope v5.4.0 Streamlit modernization."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def _source(relative_path: str) -> str:
    """Read one project source file.

    Args:
        relative_path: Path relative to ``src/securescope``.

    Returns:
        UTF-8 source text.

    Raises:
        OSError: If the file cannot be read.
    """

    return (SOURCE_ROOT / relative_path).read_text(encoding="utf-8")


def test_streamlit_162_is_the_supported_frontend_runtime() -> None:
    """Pin the release that provides the modern navigation/v2 APIs in use."""

    requirements = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "streamlit>=1.62,<1.63" in requirements
    assert '"streamlit>=1.62,<1.63"' in pyproject


def test_modern_router_uses_pages_hidden_navigation_and_page_run() -> None:
    """Require Streamlit to own the route rather than a session-state if-chain."""

    navigation = _source("ui/navigation.py")
    app = _source("app.py")
    assert "st.Page(" in navigation
    assert 'position="hidden"' in navigation
    assert "selected_page = run_hidden_navigation(page_registry)" in app
    assert "selected_page.run()" in app
    assert 'if current_page == "ISO Command Center":' not in app


def test_primary_and_contextual_routes_are_preserved() -> None:
    """Keep the simplified sidebar without deleting specialist workspaces."""

    navigation = _source("ui/navigation.py")
    for title in (
        "Command Center",
        "Exposure Overview",
        "Programme Foundation",
        "Control Assurance",
        "Asset Management",
        "Scan Center",
        "Vulnerabilities",
        "SIEM",
        "Remediation",
        "Reports & Audit",
        "Client Workspace",
    ):
        assert f'"{title}"' in navigation
    for hidden_title in ("Asset Discovery", "Technical Assurance", "Evidence Hub"):
        assert f'"{hidden_title}"' in navigation
    assert navigation.count("hidden=True") >= 3


def test_components_v2_use_structured_data_and_safe_dom_insertion() -> None:
    """Prevent user/database values from being concatenated into trusted markup."""

    components = _source("ui/components_v2/stitch_components.py")
    assert "st.components.v2.component(" in components
    assert "textContent" in components
    table_script = _source("ui/components_v2/table.js")
    assert "setTriggerValue('selected_row'" in table_script
    assert "innerHTML" not in table_script
    assert "parentElement.innerHTML" not in components
    assert '"on_selected_row_change"' in components


def test_control_profiles_use_shared_editable_drawer() -> None:
    """Keep the editable register connected to the existing assurance workflows."""

    exposure = _source("ui/exposure_management_ui.py")
    assert "components_v2_available()" in exposure
    assert "render_control_profiles(client_name, filtered_rows, overview_rows)" in exposure
    assert "st.dataframe(" in exposure
    assert '"SecureScope recommendation"' in exposure
    assert '"Human assessment"' in exposure
    assert "render_iso_evidence_hub(client_name, embedded=True)" in exposure


def test_high_interaction_workspaces_use_fragments() -> None:
    """Reduce full application reruns for common dashboard interactions."""

    app = _source("app.py")
    exposure = _source("ui/exposure_management_ui.py")
    programme = _source("ui/grc_workspace_ui.py")
    command_center = _source("ui/pages/command_center.py")
    assert app.count("@st.fragment") >= 6
    assert exposure.count("@st.fragment") >= 3
    assert "@st.fragment" in programme
    assert "@st.fragment(parallel=True)" in command_center


def test_shared_postgresql_repository_uses_threaded_pool() -> None:
    """Reuse PostgreSQL connections safely across concurrent dashboard reads."""

    database = _source("persistence/db_service.py")
    assert "ThreadedConnectionPool" in database
    assert "SECURESCOPE_DB_POOL_MIN" in database
    assert "SECURESCOPE_DB_POOL_MAX" in database
    assert "pool.getconn()" in database
    assert "pool.putconn(" in database
    assert "atexit.register(close_connection_pool)" in database


def test_design_tokens_match_the_approved_stitch_foundation() -> None:
    """Keep the approved visual foundation centralized instead of page-local."""

    tokens = _source("ui/design_system/tokens.py")
    assert 'primary: str = "#00685f"' in tokens
    assert 'navy: str = "#0f172a"' in tokens
    assert 'background: str = "#f8f9ff"' in tokens
    assert "card_radius_px: int = 10" in tokens
    assert "gutter_px: int = 24" in tokens


def test_navigation_registry_runtime_contract(monkeypatch) -> None:
    """Exercise page creation and hidden navigation without a real UI runtime."""

    from types import SimpleNamespace

    from securescope.ui import navigation

    created: list[object] = []

    def fake_page(renderer, **kwargs):
        page = SimpleNamespace(renderer=renderer, **kwargs)
        created.append(page)
        return page

    navigation_calls: list[tuple[object, ...]] = []

    def fake_navigation(pages, *, position):
        navigation_calls.append(tuple(pages))
        assert position == "hidden"
        return pages[0]

    monkeypatch.setattr(navigation.st, "Page", fake_page, raising=False)
    monkeypatch.setattr(navigation.st, "navigation", fake_navigation, raising=False)
    renderers = {spec.key: (lambda: None) for spec in navigation.PAGE_SPECS}

    registry = navigation.build_page_registry(renderers)
    selected = navigation.run_hidden_navigation(registry)

    assert len(created) == len(navigation.PAGE_SPECS)
    assert selected is registry["ISO Command Center"]
    assert navigation.active_navigation_key(selected, registry) == "ISO Command Center"
    assert navigation_calls


def test_metric_component_v2_mounts_structured_payload(monkeypatch) -> None:
    """Exercise one Components v2 renderer with a fake Streamlit frontend."""

    from types import SimpleNamespace

    from securescope.ui.components_v2 import stitch_components

    mounted: list[dict[str, object]] = []

    def fake_component(**registration):
        assert registration["name"] == "securescope_metric_grid"

        def renderer(**kwargs):
            mounted.append(kwargs)
            return SimpleNamespace()

        return renderer

    monkeypatch.setattr(
        stitch_components.st,
        "components",
        SimpleNamespace(v2=SimpleNamespace(component=fake_component)),
        raising=False,
    )
    monkeypatch.setattr(stitch_components, "_METRIC_COMPONENT", None)

    rendered = stitch_components.render_metric_grid_v2(
        [{"label": "Open gaps", "value": "4", "tone": "danger"}],
        key="test_metric_grid",
    )

    assert rendered is True
    assert mounted[0]["key"] == "test_metric_grid"
    assert mounted[0]["data"]["metrics"][0]["label"] == "Open gaps"


def test_database_context_reuses_and_returns_pooled_connection(monkeypatch) -> None:
    """Verify normal repository traffic commits and returns the borrowed connection."""

    from securescope.persistence import db_service

    class FakeConnection:
        closed = False

        def __init__(self) -> None:
            self.commits = 0
            self.rollbacks = 0

        def commit(self) -> None:
            self.commits += 1

        def rollback(self) -> None:
            self.rollbacks += 1

    class FakePool:
        def __init__(self) -> None:
            self.connection = FakeConnection()
            self.returned: list[tuple[object, bool]] = []

        def getconn(self):
            return self.connection

        def putconn(self, connection, *, close=False) -> None:
            self.returned.append((connection, close))

    pool = FakePool()
    monkeypatch.setattr(db_service, "_get_connection_pool", lambda: pool)

    with db_service.connect() as connection:
        assert connection is pool.connection

    assert pool.connection.commits == 1
    assert pool.connection.rollbacks == 0
    assert pool.returned == [(pool.connection, False)]
