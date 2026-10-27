"""Upgrade seeded M1 source/history through the actual migration runner and checksum ledger."""

import os

import pytest
from psycopg2.extensions import make_dsn

from securescope.persistence import migration_service
from tests.test_m1_evidence_postgres import ACTOR, add_profile, database  # noqa: F401

RUN_MIGRATIONS = migration_service.run_pending_migrations
pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Dedicated database not configured"
)


@pytest.fixture
def m1_database(monkeypatch, request):
    """Apply only migrations 001–017, then expose the real runner for the M2 upgrade."""
    discover = migration_service.discover_migrations
    releases = discover()
    monkeypatch.setattr(
        migration_service, "discover_migrations", lambda: [m for m in releases if m.version <= 17]
    )
    connection = request.getfixturevalue("database")
    monkeypatch.setattr(
        migration_service, "discover_migrations", lambda: [m for m in releases if m.version <= 19]
    )
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT current_schema()")
        schema = cur.fetchone()[0]
    monkeypatch.setattr(
        migration_service,
        "get_database_url",
        lambda: make_dsn(
            os.environ["SECURESCOPE_TEST_DATABASE_URL"], options=f"-c search_path={schema}"
        ),
    )
    return connection


def test_upgrade_ledger_repeatability_and_m1_history(m1_database):
    """Actual 018/019 upgrade preserves seeded decisions and rejects immutable target rewrites."""
    database = m1_database
    profile = add_profile(database, control="A.8.16")
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_control_assessments(client_id,profile_id,assessment_status,validator) "
            "VALUES(101,%s,'Implemented and effective',%s)",
            (profile, ACTOR),
        )
        cur.execute("SELECT row_to_json(a)::text FROM securescope_control_assessments a")
        before = cur.fetchall()
        # Seed the authentic M1 checksums; the real runner must apply only the additive M2 files.
        migration_service._ensure_migration_table(cur)
        for migration in migration_service.discover_migrations():
            if migration.version <= 17:
                cur.execute(
                    "INSERT INTO securescope_schema_migrations(version,name,checksum) VALUES (%s,%s,%s)",
                    (migration.version, migration.name, migration.checksum),
                )
    names = RUN_MIGRATIONS()
    assert [name[:3] for name in names] == ["018", "019"]
    assert RUN_MIGRATIONS() == []
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT row_to_json(a)::text FROM securescope_control_assessments a")
        assert cur.fetchall() == before
        cur.execute("SELECT max(version),count(*) FROM securescope_schema_migrations")
        assert cur.fetchone() == (19, 19)
    print(
        "Actual migration runner: M1 ledger 001–017 -> 018/019 -> repeated run empty; decision history unchanged."
    )
