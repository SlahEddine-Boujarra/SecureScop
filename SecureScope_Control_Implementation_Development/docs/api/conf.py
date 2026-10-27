"""Sphinx configuration for SecureScope API documentation."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

project = "SecureScope"
release = "5.4.3"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]
autodoc_mock_imports = [
    "gvm",
    "lxml",
    "nmap",
    "pandas",
    "psycopg2",
    "pyarrow",
    "reportlab",
    "streamlit",
]
templates_path = ["_templates"]
exclude_patterns = ["_build"]
html_theme = "sphinx_rtd_theme"
