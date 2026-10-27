"""Real PostgreSQL constraint regression in an isolated, disposable schema."""

import os
from pathlib import Path
from uuid import uuid4

import psycopg2
import pytest

URL = os.getenv("SECURESCOPE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not URL, reason="Explicit SECURESCOPE_TEST_DATABASE_URL is not configured"
)


def test_draft_exclusion_migration_and_deferred_approval_constraint():
    """Preserve legacy rows, permit justified drafts and guard both approval write paths."""
    schema = "test_soa_" + uuid4().hex
    admin = psycopg2.connect(URL)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(f"CREATE SCHEMA {schema}")
    connection = psycopg2.connect(URL, options=f"-c search_path={schema}")
    try:
        with connection, connection.cursor() as cursor:
            cursor.execute("""CREATE TABLE securescope_soa_versions (
                id BIGINT PRIMARY KEY, client_id BIGINT NOT NULL, status TEXT NOT NULL);
                CREATE TABLE securescope_soa_items (id BIGINT PRIMARY KEY,
                client_id BIGINT NOT NULL, soa_version_id BIGINT NOT NULL,
                applicability TEXT NOT NULL, inclusion_justification TEXT,
                exclusion_justification TEXT, approved BOOLEAN NOT NULL DEFAULT FALSE,
                CHECK ((applicability='Applicable' AND coalesce(inclusion_justification,'')<>'')
                OR (applicability='Not applicable'
                    AND coalesce(exclusion_justification,'')<>'' AND approved)));
                INSERT INTO securescope_soa_versions VALUES (1,1,'Approved'),(2,1,'Draft');
                INSERT INTO securescope_soa_items
                    VALUES (1,1,1,'Not applicable','','Historical',TRUE);""")
            migration = (
                Path(__file__).parents[1]
                / "database/migrations/016_soa_draft_justified_exclusions.sql"
            )
            cursor.execute(migration.read_text(encoding="utf-8"))
            cursor.execute(
                "INSERT INTO securescope_soa_items "
                "VALUES (2,1,2,'Not applicable','','Justified draft',FALSE)"
            )
        with pytest.raises(psycopg2.Error, match="formal approval"):
            with connection, connection.cursor() as cursor:
                cursor.execute("UPDATE securescope_soa_versions SET status='Approved' WHERE id=2")
        with pytest.raises(psycopg2.errors.CheckViolation):
            with connection, connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO securescope_soa_items VALUES (3,1,2,'Not applicable','','',FALSE)"
                )
        with connection, connection.cursor() as cursor:
            cursor.execute("UPDATE securescope_soa_items SET approved=TRUE WHERE id=2")
            cursor.execute("UPDATE securescope_soa_versions SET status='Approved' WHERE id=2")
        with pytest.raises(psycopg2.Error, match="formal approval"):
            with connection, connection.cursor() as cursor:
                cursor.execute("UPDATE securescope_soa_items SET approved=FALSE WHERE id=2")
        with connection, connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM securescope_soa_items")
            assert cursor.fetchone()[0] == 2
    finally:
        connection.close()
        with admin.cursor() as cursor:
            cursor.execute(f"DROP SCHEMA {schema} CASCADE")
        admin.close()
