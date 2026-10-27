"""Canonical filesystem paths used by SecureScope.

Keeping repository paths in one module prevents application services from
depending on the current working directory or the location of an individual
Python source file.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parent
PROJECT_ROOT = SOURCE_ROOT.parent

ENV_FILE = Path(os.getenv("SECURESCOPE_ENV_FILE", str(PROJECT_ROOT / ".env"))).expanduser()
CONFIG_ROOT = PROJECT_ROOT / "config"
DATABASE_ROOT = PROJECT_ROOT / "database"
INTEGRATIONS_ROOT = PROJECT_ROOT / "integrations"
WAZUH_ROOT = INTEGRATIONS_ROOT / "wazuh"
LOG_ROOT = PROJECT_ROOT / "logs"
REPORT_ROOT = PROJECT_ROOT / "reports"
EXPORT_ROOT = PROJECT_ROOT / "exports"
TOOLS_ROOT = PROJECT_ROOT / "tools"
REMEDIATION_RECIPES_FILE = CONFIG_ROOT / "remediation_recipes.json"


def ensure_runtime_directories() -> None:
    """Create writable runtime directories when they do not exist.

    Returns:
        None.

    Raises:
        OSError: If a directory cannot be created.
    """

    for directory in (LOG_ROOT, REPORT_ROOT, EXPORT_ROOT):
        directory.mkdir(parents=True, exist_ok=True)
