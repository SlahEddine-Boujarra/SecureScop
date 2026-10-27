"""Versioned PostgreSQL migration runner for SecureScope."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import psycopg2

from securescope.paths import DATABASE_ROOT
from securescope.persistence.db_service import get_database_url, init_database

LOGGER = logging.getLogger(__name__)
MIGRATION_LOCK_KEY = 74109006
MIGRATION_PATTERN = re.compile(r"^(?P<version>\d+)_(?P<name>[a-z0-9_]+)\.sql$")
COMPATIBLE_MIGRATION_CHECKSUMS: dict[int, frozenset[str]] = {
    3: frozenset(
        {
            # Previously published v6.2 ISO Evidence Hub migration.
            "07e4f9afa02acd923811e36ef3564d05e530baae5ff422477e308c8ef39c3b00",
            # Previously published v6.3 ISO Evidence Platform migration.
            "bfb1fb336008856f5cb9a7a414e0595dc4d5906b975c3b85096b128017022329",
            # Initial v5.3.7 migration, which differed from v6.3 only by a comment.
            "1137a461d007f793632191e84d251da945b40f0a375372254481f12a96c3831e",
            # Stable v5.3.7 compatibility bridge shipped with migration 004.
            "26e564bc022ee3daf151b25cd007ccafa513da2ea07883dc7e93758cb5138a09",
        }
    ),
    6: frozenset(
        {
            # Initial v5.3.8.4 organization-knowledge migration.
            "33b692a189316647f40f8332477a2f98581aacf251cf06d1296e06c8b176fbe2",
            # v5.3.8.5 compatibility form for previously published schemas.
            "5548fed5ed465e4f534f9534000ebbb5c6bdadb5429fa432f0d711b4faa09619",
        }
    ),
}
PREFERRED_MIGRATION_ALIASES: dict[int, str] = {
    3: "legacy_iso_evidence_bridge",
    6: "organization_knowledge_compat",
}


class MigrationError(RuntimeError):
    """Raised when migration discovery or execution fails."""


@dataclass(frozen=True)
class Migration:
    """One immutable SQL migration file.

    Args:
        version: Monotonically increasing integer version.
        name: Stable migration name.
        path: Absolute SQL file path.
        checksum: SHA-256 checksum of the SQL bytes.

    Returns:
        Immutable migration metadata.

    Raises:
        MigrationError: If metadata is invalid.
    """

    version: int
    name: str
    path: Path
    checksum: str

    def __post_init__(self) -> None:
        """Validate migration metadata.

        Returns:
            None.

        Raises:
            MigrationError: If the version, name or path is invalid.
        """

        if self.version <= 0 or not self.name or not self.path.is_file():
            raise MigrationError(f"Invalid migration metadata: {self.path}")


def discover_migrations(directory: Path | None = None) -> list[Migration]:
    """Discover and validate ordered SQL migrations.

    Args:
        directory: Migration folder. Defaults to ``database/migrations``.

    Returns:
        Migrations sorted by integer version.

    Raises:
        MigrationError: If the folder is missing, a filename is invalid or an
            unknown migration version appears more than once.
    """

    migration_directory = directory or (DATABASE_ROOT / "migrations")
    if not migration_directory.is_dir():
        raise MigrationError(f"Migration directory is missing: {migration_directory}")
    candidates_by_version: dict[int, list[Migration]] = {}
    for path in sorted(migration_directory.glob("*.sql")):
        match = MIGRATION_PATTERN.match(path.name)
        if not match:
            raise MigrationError(f"Invalid migration filename: {path.name}")
        version = int(match.group("version"))
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        candidates_by_version.setdefault(version, []).append(
            Migration(
                version=version,
                name=match.group("name"),
                path=path.resolve(),
                checksum=checksum,
            )
        )

    migrations: list[Migration] = []
    for version, candidates in sorted(candidates_by_version.items()):
        if len(candidates) == 1:
            migrations.append(candidates[0])
            continue

        preferred_name = PREFERRED_MIGRATION_ALIASES.get(version)
        compatible_checksums = COMPATIBLE_MIGRATION_CHECKSUMS.get(
            version,
            frozenset(),
        )
        preferred = [candidate for candidate in candidates if candidate.name == preferred_name]
        if (
            len(preferred) == 1
            and compatible_checksums
            and all(candidate.checksum in compatible_checksums for candidate in candidates)
        ):
            LOGGER.warning(
                "Detected known published aliases for migration %s; using %s.",
                version,
                preferred[0].path.name,
            )
            migrations.append(preferred[0])
            continue
        names = ", ".join(candidate.path.name for candidate in candidates)
        raise MigrationError(f"Duplicate migration version {version}: {names}")
    return migrations


def _ensure_migration_table(cursor: Any) -> None:
    """Create the migration ledger when missing.

    Args:
        cursor: Psycopg cursor supporting ``execute``.

    Returns:
        None.

    Raises:
        psycopg2.Error: If PostgreSQL rejects the statement.
    """

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS securescope_schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum CHAR(64) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )


def _applied_migrations(cursor: Any) -> dict[int, str]:
    """Load applied versions and checksums.

    Args:
        cursor: Psycopg cursor supporting ``execute`` and ``fetchall``.

    Returns:
        Mapping from version to checksum.

    Raises:
        psycopg2.Error: If PostgreSQL cannot read the migration ledger.
    """

    cursor.execute("SELECT version, checksum FROM securescope_schema_migrations ORDER BY version;")
    return {int(row[0]): str(row[1]) for row in cursor.fetchall()}


def _checksums_are_compatible(
    migration: Migration,
    previous_checksum: str,
) -> bool:
    """Return whether two published checksums are a safe migration alias.

    Args:
        migration: Migration currently present in the release.
        previous_checksum: Checksum recorded in PostgreSQL.

    Returns:
        ``True`` only when both checksums belong to the explicit compatibility
        set for the same migration version.

    Raises:
        No exceptions are raised.
    """

    compatible_checksums = COMPATIBLE_MIGRATION_CHECKSUMS.get(
        migration.version,
        frozenset(),
    )
    return migration.checksum in compatible_checksums and previous_checksum in compatible_checksums


def run_pending_migrations(
    migrations: Iterable[Migration] | None = None,
) -> list[str]:
    """Apply pending migrations under a PostgreSQL advisory transaction lock.

    Args:
        migrations: Optional explicit migrations, primarily for validation.

    Returns:
        Names of migrations applied by this invocation.

    Raises:
        MigrationError: If a checksum changed or migration execution fails.
        DatabaseConfigurationError: Propagated when the database URL is missing.
    """

    init_database()
    migration_rows = list(migrations) if migrations is not None else discover_migrations()
    connection = None
    applied_names: list[str] = []
    try:
        connection = psycopg2.connect(get_database_url())
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s);", (MIGRATION_LOCK_KEY,))
            _ensure_migration_table(cursor)
            applied = _applied_migrations(cursor)
            for migration in migration_rows:
                previous_checksum = applied.get(migration.version)
                if previous_checksum:
                    if previous_checksum != migration.checksum:
                        if not _checksums_are_compatible(
                            migration,
                            previous_checksum,
                        ):
                            raise MigrationError(
                                "Applied migration checksum changed: "
                                f"{migration.path.name} "
                                f"(database={previous_checksum}, "
                                f"release={migration.checksum})"
                            )
                        LOGGER.warning(
                            "Recognized published checksum variant for migration "
                            "%s; the additive reconciliation migration will verify "
                            "the current schema.",
                            migration.version,
                        )
                    continue
                LOGGER.info(
                    "Applying SecureScope migration %s (%s).",
                    migration.version,
                    migration.name,
                )
                migration_sql = migration.path.read_text(encoding="utf-8")
                cursor.execute(migration_sql)
                cursor.execute(
                    """
                    INSERT INTO securescope_schema_migrations (
                        version,
                        name,
                        checksum
                    )
                    VALUES (%s, %s, %s);
                    """,
                    (migration.version, migration.name, migration.checksum),
                )
                applied_names.append(migration.path.name)
        connection.commit()
        return applied_names
    except (psycopg2.Error, OSError, UnicodeError) as exc:
        if connection is not None:
            connection.rollback()
        LOGGER.error("SecureScope migration failed: %s", exc)
        raise MigrationError(str(exc)) from exc
    except MigrationError:
        if connection is not None:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            connection.close()
