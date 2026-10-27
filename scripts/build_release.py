"""Build a reproducible SecureScope source archive and verify every file digest."""

from __future__ import annotations

import argparse
import hashlib
import logging
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION = (PROJECT_ROOT / "VERSION.txt").read_text(encoding="utf-8").strip()
ARCHIVE_ROOT = f"SecureScope_v{VERSION.replace('.', '_')}_ISO_Gap_Dashboard_Windows"
EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "tmp",
    "logs",
    "reports",
    "exports",
    "scans",
    "data",
    "tools",
    "evidence_store",
    "build",
    "_build",
    "dist",
}
EXCLUDED_FILENAMES = {".env", "secrets.toml", "FILE_MANIFEST.sha256", ".coverage"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".zip", ".pem", ".key", ".pfx", ".p12"}
LOGGER = logging.getLogger(__name__)


def release_files() -> list[Path]:
    """Collect distributable sources without credentials, runtime data or caches.

    Returns:
        Source paths sorted by their relative POSIX names.

    Raises:
        OSError: If the source tree cannot be read.
    """

    files = []
    for path in PROJECT_ROOT.rglob("*"):
        relative = path.relative_to(PROJECT_ROOT)
        if any(
            part in EXCLUDED_DIRECTORIES or part.endswith(".egg-info") for part in relative.parts
        ):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.name in EXCLUDED_FILENAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if path.name.startswith(".env.") and path.name != ".env.example":
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(PROJECT_ROOT).as_posix())


def sha256(path: Path) -> str:
    """Calculate a file digest with bounded memory use.

    Args:
        path: Local file to read.

    Returns:
        Lowercase SHA-256 hexadecimal digest.

    Raises:
        OSError: If the file cannot be read.
    """

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(output: Path) -> tuple[int, str]:
    """Package sources and verify archive CRC plus every manifest entry.

    Args:
        output: Destination ZIP path; parent directories are created if needed.

    Returns:
        Packaged source count and final ZIP SHA-256 digest.

    Raises:
        OSError: If sources or destination cannot be accessed.
        RuntimeError: If the resulting archive fails integrity verification.
        zipfile.BadZipFile: If the resulting ZIP cannot be read.
    """

    files = release_files()
    manifest = {path.relative_to(PROJECT_ROOT).as_posix(): sha256(path) for path in files}
    manifest_text = "".join(f"{digest}  {name}\n" for name, digest in manifest.items())
    (PROJECT_ROOT / "FILE_MANIFEST.sha256").write_text(manifest_text, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            name = path.relative_to(PROJECT_ROOT).as_posix()
            entry = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{name}", date_time=(2026, 9, 6, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, path.read_bytes())
        entry = zipfile.ZipInfo(
            f"{ARCHIVE_ROOT}/FILE_MANIFEST.sha256", date_time=(2026, 9, 6, 0, 0, 0)
        )
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, manifest_text)
    with zipfile.ZipFile(output) as archive:
        corrupt = archive.testzip()
        if corrupt:
            raise RuntimeError(f"Corrupt ZIP member: {corrupt}")
        for name, expected in manifest.items():
            actual = hashlib.sha256(archive.read(f"{ARCHIVE_ROOT}/{name}")).hexdigest()
            if actual != expected:
                raise RuntimeError(f"Release digest mismatch: {name}")
    return len(files), sha256(output)


def main() -> None:
    """Build a release from one command-line destination path.

    Returns:
        None. Prints archive count and digest on success.

    Raises:
        SystemExit: If arguments are invalid or packaging fails.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        count, digest = build(args.output.resolve())
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        LOGGER.error("Release packaging failed: %s", exc)
        raise SystemExit(1) from exc
    print(f"Packaged files: {count}")
    print(f"ZIP SHA-256: {digest}")


if __name__ == "__main__":
    main()
