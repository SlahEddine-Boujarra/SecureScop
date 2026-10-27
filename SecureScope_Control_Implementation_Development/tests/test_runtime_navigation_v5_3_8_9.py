"""Regression contracts for the v5.3.8.9 runtime/navigation hotfix."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "src" / "securescope" / "app.py"
ROUTER_PATH = ROOT / "src" / "securescope" / "ui" / "grc_workspace" / "router.py"
SIDEBAR_PATH = ROOT / "src" / "securescope" / "ui" / "securescope_sidebar.py"


def _function_source(source: str, function_name: str, next_name: str) -> str:
    """Return a stable top-level function source slice.

    Args:
        source: Python module source.
        function_name: Function whose source should be returned.
        next_name: Following top-level function used as the end boundary.

    Returns:
        Source text for the requested function.

    Raises:
        ValueError: If either function boundary is absent.
    """

    start = source.index(f"def {function_name}(")
    end = source.index(f"def {next_name}(", start + 1)
    return source[start:end]


def test_exposure_runtime_abcs_are_imported() -> None:
    """Prevent Sequence/Mapping runtime NameError in canonical findings helpers."""

    source = APP_PATH.read_text(encoding="utf-8")
    assert "from collections.abc import Mapping, Sequence" in source


def test_programme_navigation_is_deferred_until_before_widget_render() -> None:
    """Do not mutate the segmented-control key after widget instantiation."""

    source = ROUTER_PATH.read_text(encoding="utf-8")
    selector = _function_source(
        source,
        "select_programme_section",
        "_render_selected_section",
    )
    assert "programme_section_pending_key(client_name)" in selector
    assert 'f"programme_section_control::{client_name}"' not in selector
    render = source[source.index("def render_programme_setup(") :]
    assert "pending = str(st.session_state.pop(pending_key" in render
    assert "st.session_state[control_key] = requested" in render
    assert render.index("st.session_state[control_key] = requested") < render.index(
        "section_navigation("
    )


def test_legacy_a8_workspace_is_hidden_behind_control_assurance() -> None:
    """Keep the A.8 engine as a drill-down without duplicating sidebar navigation."""

    sidebar = SIDEBAR_PATH.read_text(encoding="utf-8")
    visible_navigation = sidebar.split("HIDDEN_NAVIGATION_PAGES", 1)[0]
    assert '"Control Assurance"' in visible_navigation
    assert '"Technical Assurance"' not in visible_navigation
    assert '"ISO 27001 Mapping"' in sidebar
    assert '"ISO Control Evidence"' not in sidebar
