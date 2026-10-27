"""Verify release consumers share the canonical VERSION.txt value."""

import re
import runpy
import tomllib
from pathlib import Path

import securescope

ROOT = Path(__file__).resolve().parents[1]


def test_version_consumers_match_authority():
    """Check source, packaging and reader-facing current-version declarations.

    Returns:
        None.
    Raises:
        AssertionError: If a consumer drifts from VERSION.txt.
    """
    expected = (ROOT / "VERSION.txt").read_text().strip()
    assert securescope.__version__ == expected
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in metadata["project"]
    assert metadata["tool"]["setuptools"]["dynamic"]["version"] == {"file": "VERSION.txt"}
    assert runpy.run_path(str(ROOT / "scripts/build_release.py"))["VERSION"] == expected
    for name in ("README.md", "SECURITY.md", "START_HERE.md"):
        match = re.search(r"v(\d+\.\d+\.\d+(?:\.dev\d+)?)", (ROOT / name).read_text())
        assert match and match.group(1) == expected, name
