"""Upgrade real M2 tables and checksum ledger without reinterpreting historic evidence."""

import os
from uuid import uuid4

import pytest
from psycopg2.extensions import make_dsn

from securescope.persistence import migration_service
from tests.test_m1_evidence_postgres import ACTOR, add_profile, database  # noqa: F401

RUN_MIGRATIONS = migration_service.run_pending_migrations
pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Dedicated database not configured"
)


@pytest.fixture
def m2_database(monkeypatch, request):
    """Build M2 using 001–019, then expose the real migration runner for 020."""
    releases = migration_service.discover_migrations()
    monkeypatch.setattr(
        migration_service, "discover_migrations", lambda: [m for m in releases if m.version <= 19]
    )
    connection = request.getfixturevalue("database")
    monkeypatch.setattr(migration_service, "discover_migrations", lambda: releases)
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


def test_m2_upgrade_repeatability_history_and_no_automatic_backfill(m2_database):
    """020 alone applies once; custom profiles, evidence and decisions remain byte-identical."""
    database = m2_database
    identity = add_profile(database)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_control_assessments(client_id,profile_id,assessment_status,validator) "
            "VALUES(101,%s,'Implemented and effective',%s)",
            (identity, ACTOR),
        )
        cur.execute(
            "INSERT INTO securescope_evidence_records(client_id,evidence_uuid,tool_id,collection_method,evidence_type,title,summary,scope_description,collected_at,owner,submitted_by,normalized_payload) "
            "VALUES(101,%s,'nuclei','Existing worker','Scan','M2 historical record','Retain','Historic',NOW(),%s,%s,'{\"metadata\":{\"rule_version\":2}}')",
            (str(uuid4()), ACTOR, ACTOR),
        )
        tables = (
            "securescope_control_assessments",
            "securescope_evidence_records",
            "securescope_control_assessment_profiles",
        )
        before = {}
        for table in tables:
            cur.execute(f"SELECT row_to_json(t)::text FROM {table} t ORDER BY id")
            before[table] = cur.fetchall()
        migration_service._ensure_migration_table(cur)
        for migration in migration_service.discover_migrations():
            if migration.version <= 19:
                cur.execute(
                    "INSERT INTO securescope_schema_migrations(version,name,checksum) VALUES(%s,%s,%s)",
                    (migration.version, migration.name, migration.checksum),
                )
    assert [name[:3] for name in RUN_MIGRATIONS()] == ["020"]
    assert RUN_MIGRATIONS() == []
    with database() as conn, conn.cursor() as cur:
        for table in tables:
            cur.execute(f"SELECT row_to_json(t)::text FROM {table} t ORDER BY id")
            assert cur.fetchall() == before[table]
        for table in (
            "securescope_nuclei_requirement_sources",
            "securescope_requirement_check_attributions",
        ):
            cur.execute(f"SELECT count(*) FROM {table}")
            assert cur.fetchone()[0] == 0
        migration = next(m for m in migration_service.discover_migrations() if m.version == 20)
        cur.execute(migration.path.read_text())
        cur.execute("SELECT max(version),count(*) FROM securescope_schema_migrations")
        assert cur.fetchone() == (20, 20)
    print(
        "M3 upgrade: 001–019 ledger -> 020 once -> empty repeat; SQL repeat safe; historic rows identical; no backfill."
    )
