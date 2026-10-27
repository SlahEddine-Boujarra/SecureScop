"""SecureScope platform; version originates from the root VERSION.txt."""

from importlib.metadata import version
from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION.txt"
# Source checkouts read the authority directly; wheels use its build metadata.
__version__ = (
    _VERSION_FILE.read_text(encoding="utf-8").strip()
    if _VERSION_FILE.is_file()
    else version("securescope")
)
