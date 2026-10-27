"""Run additive Wazuh migration constraints in an explicitly configured test database."""

import os
from pathlib import Path
from uuid import uuid4

import psycopg2
import pytest

URL = os.getenv("SECURESCOPE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not URL, reason="Explicit SECURESCOPE_TEST_DATABASE_URL is not configured"
)


def test_monitoring_migration_preserves_history_and_rejects_cross_tenant_identity():
    """Exercise reapplication, ownership, deduplication and immutable observations."""
    schema = "test_wazuh_" + uuid4().hex
    admin = psycopg2.connect(URL)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(f"CREATE SCHEMA {schema}")
    connection = psycopg2.connect(URL)
    with connection, connection.cursor() as cursor:
        cursor.execute(f"SET search_path TO {schema}")
    try:
        with connection, connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE securescope_clients(id BIGINT PRIMARY KEY);
                CREATE TABLE securescope_assets(id BIGINT PRIMARY KEY,client_id BIGINT NOT NULL);
                CREATE TABLE securescope_asset_wazuh_status(id BIGINT PRIMARY KEY,raw JSONB);
                INSERT INTO securescope_clients VALUES (1),(2);
                INSERT INTO securescope_assets VALUES (10,1),(11,1),(20,2);
                INSERT INTO securescope_asset_wazuh_status VALUES (5,'{"legacy":true}');
            """
            )
            migration = (
                Path(__file__).parents[1] / "database/migrations/017_verified_wazuh_monitoring.sql"
            )
            cursor.execute(migration.read_text(encoding="utf-8"))
            cursor.execute(migration.read_text(encoding="utf-8"))
            cursor.execute(
                """INSERT INTO securescope_wazuh_bindings
                (id,client_id,asset_id,connector_id,manager_name,agent_id,
                 heartbeat_max_age_seconds,telemetry_max_age_seconds,approved_by,rationale)
                VALUES (1,1,10,'source','manager','007',300,3600,'admin','Confirmed ownership')"""
            )
            cursor.execute(
                """INSERT INTO securescope_wazuh_collection_runs
                (id,client_id,connector_id,requested_by) VALUES (1,1,'source','consultant')"""
            )
            cursor.execute(
                """INSERT INTO securescope_wazuh_observations
                (id,client_id,binding_id,asset_id,source_key,payload_sha256,payload)
                VALUES (1,1,1,10,'event',repeat('a',64),'{}')"""
            )
            cursor.execute(
                """INSERT INTO securescope_wazuh_observations
                (id,client_id,binding_id,asset_id,source_key,payload_sha256,payload)
                VALUES (2,1,1,10,'event',repeat('a',64),'{}') ON CONFLICT DO NOTHING"""
            )
            cursor.execute("SELECT count(*) FROM securescope_wazuh_observations")
            assert cursor.fetchone()[0] == 1
            cursor.execute("SELECT raw FROM securescope_asset_wazuh_status WHERE id=5")
            assert cursor.fetchone()[0] == {"legacy": True}
        invalid_queries = [
            (
                "UPDATE securescope_wazuh_bindings SET asset_id=20 WHERE id=1",
                "P0001",
                "another workspace",
            ),
            ("INSERT INTO securescope_wazuh_run_assets VALUES (2,1,1,20)", "23503", "foreign key"),
            ("INSERT INTO securescope_wazuh_run_assets VALUES (1,1,1,11)", "23503", "foreign key"),
            (
                "UPDATE securescope_wazuh_observations SET payload='{\"changed\":true}' WHERE id=1",
                "P0001",
                "immutable",
            ),
            (
                """INSERT INTO securescope_wazuh_observations
                (id,client_id,binding_id,asset_id,source_key,payload_sha256,payload)
                VALUES (3,1,1,11,'wrong-asset',repeat('a',64),'{}')""",
                "23503",
                "foreign key",
            ),
            (
                """INSERT INTO securescope_wazuh_bindings
                (id,client_id,asset_id,connector_id,manager_name,agent_id,
                 heartbeat_max_age_seconds,telemetry_max_age_seconds,approved_by,rationale)
                VALUES (2,2,20,'source','manager','007',300,3600,'admin','Duplicate agent')""",
                "23505",
                "wazuh_binding_active_agent",
            ),
        ]
        invalid_queries.extend(
            [
                (
                    """INSERT INTO securescope_wazuh_bindings
                (id,client_id,asset_id,connector_id,manager_name,agent_id,
                 heartbeat_max_age_seconds,telemetry_max_age_seconds,approved_by,rationale)
                VALUES (3,1,10,'source','manager','008',300,3600,'admin','Duplicate asset')""",
                    "23505",
                    "wazuh_binding_active_asset",
                ),
                (
                    """INSERT INTO securescope_wazuh_observations
                (id,client_id,binding_id,asset_id,source_key,payload_sha256,payload)
                VALUES (4,1,1,10,'event',repeat('b',64),'{}')""",
                    "23505",
                    "source_key",
                ),
            ]
        )
        for query, code, message in invalid_queries:
            with pytest.raises(psycopg2.Error, match=message) as rejected:
                with connection, connection.cursor() as cursor:
                    cursor.execute(query)
            assert rejected.value.pgcode == code
        with connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO securescope_wazuh_run_assets VALUES (1,1,1,10)")
            cursor.execute(
                """UPDATE securescope_wazuh_bindings
                SET revoked_at=NOW(),revoked_by='admin' WHERE id=1"""
            )
            cursor.execute(migration.read_text(encoding="utf-8"))
            cursor.execute(
                "SELECT source_key,payload_sha256,payload "
                "FROM securescope_wazuh_observations WHERE id=1"
            )
            assert cursor.fetchone() == ("event", "a" * 64, {})
            cursor.execute("SELECT count(*) FROM securescope_wazuh_run_assets")
            assert cursor.fetchone()[0] == 1
    finally:
        connection.close()
        with admin.cursor() as cursor:
            cursor.execute(f"DROP SCHEMA {schema} CASCADE")
        admin.close()
