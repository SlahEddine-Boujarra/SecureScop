"""Guard against Python 3.12-only syntax entering a codebase pinned to 3.11.

`pyproject.toml` declares ``requires-python = ">=3.11,<3.13"`` and the supported
runtime is Python 3.11. PEP 701 multi-line f-strings parse cleanly on 3.12 but
raise ``SyntaxError: unterminated string literal`` on 3.11, so a developer on a
newer interpreter can ship code that will not start for any user.

These tests fail on 3.12+ as well as on 3.11, so the defect is caught wherever
the suite runs.
"""

from __future__ import annotations

import ast
import io
import pathlib
import tempfile
import tokenize
import unittest
from unittest.mock import patch

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNED_DIRECTORIES = ("src", "tests", "scripts")
TRIPLE_QUOTES = ('"""', "'''")


def _python_files() -> list[pathlib.Path]:
    """Collect every Python source file that ships with the product."""
    files: list[pathlib.Path] = sorted(PROJECT_ROOT.glob("*.py"))
    for directory in SCANNED_DIRECTORIES:
        root = PROJECT_ROOT / directory
        if root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return files


def _multiline_fstrings(source: str) -> list[int]:
    """Return the start lines of single-quoted f-strings that span several lines.

    Args:
        source: Python source text.

    Returns:
        Start line numbers of PEP 701 multi-line f-strings; empty when none.

    Raises:
        No exceptions are raised; unparsable files are reported separately.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        return []

    starts = []
    offenders: list[int] = []
    for token in tokens:
        if token.type == tokenize.FSTRING_START:
            starts.append(token)
        elif token.type == tokenize.FSTRING_END:
            if starts:
                start_token = starts.pop()
                quote = start_token.string.lower().lstrip("frbu")
                if quote not in TRIPLE_QUOTES and token.end[0] > start_token.start[0]:
                    offenders.append(start_token.start[0])
    return offenders


class Python311CompatibilityTests(unittest.TestCase):
    """Every shipped module must parse on the minimum supported interpreter."""

    def test_no_multiline_fstrings(self) -> None:
        """Reject PEP 701 f-strings, which need Python 3.12 or newer."""
        if not hasattr(tokenize, "FSTRING_START"):
            self.skipTest("Interpreter predates PEP 701 tokens; the parser check covers this.")

        offenders: list[str] = []
        for path in _python_files():
            source = path.read_text(encoding="utf-8")
            for line in _multiline_fstrings(source):
                relative = path.relative_to(PROJECT_ROOT)
                offenders.append(f"{relative}:{line}")

        self.assertEqual(
            offenders,
            [],
            "Multi-line f-strings require Python 3.12+ but this project supports 3.11. "
            "Split the literal into adjacent f-strings, or assign the expression to a "
            "local variable first. Offending locations: " + ", ".join(offenders),
        )

    def test_every_module_parses(self) -> None:
        """Fail loudly on any syntax error rather than at application start-up."""
        failures: list[str] = []
        for path in _python_files():
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path), feature_version=(3, 11))
            except SyntaxError as error:
                relative = path.relative_to(PROJECT_ROOT)
                failures.append(f"{relative}:{error.lineno}: {error.msg}")

        self.assertEqual(failures, [], "Modules failed to parse: " + "; ".join(failures))

    @unittest.skipUnless(hasattr(tokenize, "FSTRING_START"), "Requires Python 3.12 tokens")
    def test_guard_detects_nested_incompatible_expression(self) -> None:
        """A triple-quoted outer string cannot hide a PEP 701 inner string."""
        source = 'value = f"""{f"{(\n1 + 2\n)}"}"""'
        self.assertEqual(_multiline_fstrings(source), [1])

    @unittest.skipUnless(hasattr(tokenize, "FSTRING_START"), "Requires Python 3.12 tokens")
    def test_guard_accepts_valid_triple_quoted_expression(self) -> None:
        """Multiline expressions in triple-quoted strings are valid in 3.11."""
        source = 'value = f"""{(\n1 + 2\n)}"""'
        self.assertEqual(_multiline_fstrings(source), [])

    def test_root_launchers_are_scanned(self) -> None:
        """A root-level Python launcher must be covered when one is shipped."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            launcher = root / "launcher.py"
            launcher.write_text("print('startup')\n", encoding="utf-8")
            with patch.dict(_python_files.__globals__, PROJECT_ROOT=root):
                self.assertIn(launcher, _python_files())


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    unittest.main()
