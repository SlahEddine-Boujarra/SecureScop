"""Load the canonical design tokens inside existing Streamlit shadow components."""

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=16)
def component_styles(*filenames: str) -> str:
    """Combine shared tokens, existing component geometry and current theme rules.

    Args:
        filenames: Bundled component stylesheet basenames in load order.
    Returns:
        CSS suitable for an existing Components v2 shadow root.
    Raises:
        OSError: If a required packaged stylesheet cannot be read.
        ValueError: If a filename is not a simple CSS basename.
    """
    ui_root = Path(__file__).parent
    component_root = ui_root / "components_v2"
    for filename in filenames:
        if Path(filename).name != filename or not filename.endswith(".css"):
            raise ValueError("Component styles require a bundled CSS basename.")
    tokens = (ui_root / "styles/tokens.css").read_text(encoding="utf-8")
    rules = [tokens.replace(":root", ":host", 1)]
    rules.extend((component_root / name).read_text(encoding="utf-8") for name in filenames)
    rules.append((ui_root / "styles/component_theme.css").read_text(encoding="utf-8"))
    return "\n".join(rules)
