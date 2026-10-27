"""M1 database regressions; require an explicit, disposable PostgreSQL test target."""

import hashlib
import json
import os
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg2
import pytest
from cryptography.fernet import Fernet
from psycopg2 import sql
from psycopg2.extras import Json, RealDictCursor

from securescope.evidence import evidence_service, wazuh_bridge
from securescope.evidence.automated_checks import usable_evidence
from securescope.evidence.storage import EvidenceStorageError, read_artifact
from securescope.grc.assurance_requirements import evaluate_requirement
from securescope.integrations import wazuh_service
from securescope.persistence import assurance_workspace_repository as assurance
from securescope.persistence import (
    db_service,
)
from securescope.persistence import db_wazuh_service as monitoring
from securescope.persistence import evidence_repository as evidence
from securescope.persistence import foundation_repository as foundation
from securescope.persistence import (
    migration_service,
    nuclei_persistence,
)
from tests.test_wazuh_monitoring import snapshot

URL = os.getenv("SECURESCOPE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not URL, reason="Explicit SECURESCOPE_TEST_DATABASE_URL is not configured"
)
ACTOR = "reviewer@example.invalid"


@pytest.fixture
def database(monkeypatch, tmp_path):
    """Apply actual application DDL in an isolated schema and bind real transactions.

    Args:
        monkeypatch: Pytest isolation manager for connection/configuration boundaries.
        tmp_path: Disposable encrypted artifact location.
    Yields:
        A callable opening real database transactions in the test schema.
    Raises:
        psycopg2.Error: If DDL, setup or cleanup fails on the explicit test target.
    """
    schema = "m1_verify_" + uuid4().hex
    with closing(psycopg2.connect(URL)) as admin:
        admin.autocommit = True
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    @contextmanager
    def connection():
        """Yield a real transaction; explicitly select the schema for every connection.

        Yields:
            psycopg2 connection, committed on success and rolled back on failure.
        Raises:
            DatabaseError: On a PostgreSQL error, matching repository behavior.
        """
        with closing(psycopg2.connect(URL)) as conn:
            try:
                with conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
                        )
                    yield conn
            except psycopg2.Error as exc:
                raise db_service.DatabaseError(str(exc)) from exc

    try:
        for module in (
            db_service,
            monitoring,
            evidence,
            foundation,
            nuclei_persistence,
            wazuh_bridge,
        ):
            monkeypatch.setattr(module, "connect", connection)
        monkeypatch.setattr(db_service, "_INITIALIZED", False)
        monkeypatch.setattr(nuclei_persistence, "_NUCLEI_INITIALIZED", False)
        db_service.init_database()
        with connection() as conn, conn.cursor() as cursor:
            for migration in migration_service.discover_migrations():
                cursor.execute(migration.path.read_text(encoding="utf-8"))
        # The real migration SQL has run above; avoid changing the production pool in tests.
        for module in (migration_service, evidence, foundation):
            monkeypatch.setattr(module, "run_pending_migrations", lambda: [])
        nuclei_persistence.init_nuclei_tables()
        monkeypatch.setattr(wazuh_service, "restore_wazuh_settings", lambda: None)
        for key, value in {
            "WAZUH_API_URL": "https://manager.invalid",
            "WAZUH_API_PASSWORD": "test-only",
            "WAZUH_INDEXER_URL": "https://indexer.invalid",
            "WAZUH_VERIFY_TLS": "true",
            "WAZUH_INDEXER_VERIFY_TLS": "true",
            "SECURESCOPE_CURRENT_USER_EMAIL": ACTOR,
            "SECURESCOPE_CONNECTOR_ADMINS": ACTOR,
            "SECURESCOPE_EVIDENCE_STORAGE_ROOT": str(tmp_path),
            "SECURESCOPE_EVIDENCE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        }.items():
            monkeypatch.setenv(key, value)
        with connection() as conn, conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO securescope_clients(id,name) VALUES (101,'Alpha'),(202,'Beta')"
            )
            cursor.execute(
                "INSERT INTO securescope_assets(id,client_id,ip,asset_tag,payload) VALUES "
                "(1001,101,'192.0.2.1','ALPHA-1','{}'),"
                "(1002,101,'192.0.2.2','ALPHA-2','{}'),"
                "(2001,202,'192.0.2.1','BETA-1','{}')"
            )
            cursor.execute(
                "INSERT INTO securescope_users(id,user_uuid,email,display_name) "
                "VALUES (301,%s,%s,'Test reviewer')",
                (str(uuid4()), ACTOR),
            )
            cursor.execute(
                "INSERT INTO securescope_workspace_memberships"
                "(client_id,user_id,role,granted_by) VALUES (101,301,'Administrator','fixture')"
            )
            cursor.execute(
                "INSERT INTO securescope_consulting_organizations"
                "(id,organization_uuid,name,created_by) VALUES (401,%s,'Test organization',%s)",
                (str(uuid4()), ACTOR),
            )
            for client_id, engagement_id in ((101, 501), (202, 502)):
                cursor.execute(
                    "INSERT INTO securescope_client_consulting_organizations"
                    "(client_id,organization_id,created_by) VALUES (%s,401,%s)",
                    (client_id, ACTOR),
                )
                cursor.execute(
                    "INSERT INTO securescope_engagements"
                    "(id,client_id,consulting_organization_id,engagement_uuid,reference,name,"
                    "engagement_type,objective,created_by,updated_by) "
                    "VALUES (%s,%s,401,%s,%s,'Verification','Initial gap assessment',"
                    "'Test evidence',%s,%s)",
                    (engagement_id, client_id, str(uuid4()), f"TEST-{engagement_id}", ACTOR, ACTOR),
                )
            for scope_id, client_id, engagement_id, state in (
                (601, 101, 501, "Approved"),
                (602, 101, 501, "Approved"),
                (603, 101, 501, "Draft"),
                (604, 202, 502, "Approved"),
            ):
                cursor.execute(
                    "INSERT INTO securescope_scope_definitions"
                    "(id,client_id,engagement_id,scope_uuid,scope_code,name,created_by) "
                    "VALUES (%s,%s,%s,%s,%s,'Test scope',%s)",
                    (scope_id, client_id, engagement_id, str(uuid4()), str(scope_id), ACTOR),
                )
                cursor.execute(
                    "INSERT INTO securescope_scope_versions"
                    "(id,client_id,engagement_id,scope_id,version_number,status,scope_statement,"
                    "prepared_by,approved_by,approved_at) VALUES (%s,%s,%s,%s,1,%s,"
                    "'Test scope',%s,%s,NOW())",
                    (scope_id + 1000, client_id, engagement_id, scope_id, state, ACTOR, ACTOR),
                )
                if state == "Approved":
                    cursor.execute(
                        "UPDATE securescope_scope_definitions SET current_approved_version_id=%s "
                        "WHERE id=%s",
                        (scope_id + 1000, scope_id),
                    )
        yield connection
    finally:
        with closing(psycopg2.connect(URL)) as admin:
            admin.autocommit = True
            with admin.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def add_profile(
    database,
    *,
    scope=601,
    assets=(1001,),
    version=1,
    scope_version=None,
    client=101,
    engagement=501,
    control="A.8.8",
):
    """Insert a real versioned control configuration for explicit fixture assets.

    Returns:
        Numeric profile identity.
    Raises:
        DatabaseError: If constraints reject the test profile.
    """
    rule = "Monitoring coverage" if control == "A.8.16" else "Recent vulnerability scan"
    config = dict(
        scope_id=scope,
        engagement_id=engagement,
        scope_version_id=scope_version or scope + 1000,
        reviewed=True,
        requirements=[
            dict(
                id="requirement",
                title=rule,
                rule=rule,
                asset_ids=list(assets),
                machine_verifiable=True,
                max_age_days=90,
                threshold=100,
            )
        ],
    )
    with database() as conn, conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO securescope_control_assessment_profiles"
            "(client_id,control_id,control_name,profile_version,control_objective,"
            "expected_security_outcome,assessment_scope,measurement_model) "
            "VALUES (%s,%s,'Test control',%s,'Test objective','Test outcome',%s,"
            "'quantitative_coverage') "
            "RETURNING id",
            (client, control, version, Json({"implementation_requirements": config})),
        )
        return cursor.fetchone()[0]


def add_job(database, *, client=101, ip="192.0.2.1", context=None):
    """Persist a synthetic completed scan source; this never executes Nuclei.

    Returns:
        Stable job UUID.
    Raises:
        DatabaseError: On rejected source fixture writes.
    """
    identity = str(uuid4())
    with database() as conn, conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO securescope_nuclei_batches"
            "(batch_uuid,client_id,label,scan_mode,profile_name) "
            "VALUES (%s,%s,'Test scan','Single asset','standard') RETURNING id",
            (identity, client),
        )
        batch = cursor.fetchone()[0]
        cursor.execute(
            "INSERT INTO securescope_nuclei_jobs"
            "(batch_id,client_id,logical_job_id,job_uuid,asset_ip,scan_name,status,"
            "provider_status,asset_payload) "
            "VALUES (%s,%s,%s,%s,%s,'Test scan','Completed','Completed',%s)",
            (
                batch,
                client,
                identity,
                identity,
                ip,
                Json({"evidence_collection_context": context or {}}),
            ),
        )
    return identity


def ingest(job, *, client="Alpha", content=b""):
    """Ingest synthetic successful scan bytes through the real Nuclei evidence service.

    Returns:
        Canonical evidence ID.
    Raises:
        EvidenceRepositoryError: If job ownership or provenance is invalid.
    """
    return evidence_service.ingest_nuclei_scan_output(
        client,
        job_uuid=job,
        attempt_number=1,
        report_id=job,
        asset_ip="192.0.2.1",
        profile="standard",
        collected_at=datetime.now(timezone.utc),
        content=content,
        successful=True,
    )


def scoped_evidence(database, *, client=101, engagement=501, scope=601, control="A.8.8"):
    """Read the actual Control Profile evidence query in the selected tenant/scope.

    Returns:
        Scoped canonical evidence rows.
    Raises:
        DatabaseError: On SQL read failure.
    """
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        return assurance._evidence(cursor, client, control, engagement, scope)


def test_nuclei_ingestion_profile_visibility_and_artifact_isolation(database):
    """Zero findings, repeat delivery and overlapping client IPs stay correctly scoped."""
    add_profile(database)
    add_profile(database, scope=602, assets=(1002,), version=2)
    add_profile(database, scope=603, version=3)
    add_profile(database, scope=604, client=202, engagement=502, assets=(2001,))
    job = add_job(database)
    identity = ingest(job)
    assert ingest(job) == identity
    assert [row["id"] for row in scoped_evidence(database)] == [identity]
    assert scoped_evidence(database, scope=602) == []
    assert scoped_evidence(database, scope=603) == []
    assert scoped_evidence(database, scope=604, client=202, engagement=502) == []
    with pytest.raises(evidence.EvidenceRepositoryError, match="completed canonical"):
        ingest(job, client="Beta")
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM securescope_evidence_artifacts")
        artifacts = cursor.fetchall()
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact["sha256"] == hashlib.sha256(b"").hexdigest()
        assert artifact["encrypted"]
        assert read_artifact(101, artifact["storage_reference"]) == b""
        with pytest.raises(EvidenceStorageError, match="outside"):
            read_artifact(202, artifact["storage_reference"])
        cursor.execute("SELECT count(*) FROM securescope_evidence_records")
        assert cursor.fetchone()["count"] == 1
    requirement = dict(
        id="requirement",
        title="Recent vulnerability scan",
        rule="Recent vulnerability scan",
        asset_ids=[1001],
        machine_verifiable=True,
        max_age_days=90,
        threshold=100,
    )
    result = evaluate_requirement(
        requirement,
        dict(scope_id=601, engagement_id=501, requirement_evidence=scoped_evidence(database)),
        datetime.now(timezone.utc),
    )
    assert result["result"] == "PASS"


def test_nuclei_scope_version_and_empty_origin_do_not_assign_scope(database):
    """An obsolete profile version and an empty collection target cannot grant membership."""
    add_profile(database, scope_version=99999)
    add_profile(database, scope=602, assets=(), version=2)
    job = add_job(
        database,
        context=dict(
            client="Alpha",
            scope_id=602,
            engagement_id=501,
            control_id="A.8.8",
            requirement_id="requirement",
        ),
    )
    identity = ingest(job)
    assert identity
    assert scoped_evidence(database) == []
    assert scoped_evidence(database, scope=602) == []


@pytest.mark.parametrize("origin", [False, True])
def test_latest_invalid_profile_cannot_resurrect_historical_membership(database, origin):
    """Only the latest scoped profile may authorize an automated association."""
    add_profile(database)
    add_profile(database, version=2, scope_version=99999)
    context = (
        dict(scope_id=601, engagement_id=501, control_id="A.8.8", requirement_id="requirement")
        if origin
        else None
    )
    ingest(add_job(database, context=context))
    assert scoped_evidence(database) == []


def monitoring_evidence(database):
    """Ingest the current real persisted monitoring source through canonical validation."""
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        rows = monitoring.load_monitoring_rows(cursor, 101)
        row = wazuh_bridge.load_source(cursor, 101, "monitoring", rows[0]["id"])
        payload, observed = wazuh_bridge.normalized_source(row, "monitoring")
    return evidence.create_evidence_record(
        "Alpha",
        tool_id="wazuh",
        collection_method="Authenticated API",
        evidence_type="Automated technical evidence",
        title="Monitoring proof",
        summary="Synthetic exact-identity event",
        scope_description="Explicit membership",
        source_asset_or_system=row["ip"],
        owner=ACTOR,
        submitted_by="system:wazuh-connector",
        collected_at=observed,
        expires_at=None,
        confidence="Medium",
        normalized=payload,
        suggested_controls=["A.8.16"],
        system_source=dict(
            provider="wazuh", kind="monitoring", record_id=row["id"], requested_by=ACTOR
        ),
    )


def test_repeated_monitoring_preserves_sources_evidence_assessments_and_audit(database):
    """Real collection/ingestion appends history without changing human decisions."""
    profile = add_profile(database, control="A.8.16")
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        for decision in ("Gap identified", "Implemented and effective"):
            cursor.execute(
                "INSERT INTO securescope_control_assessments"
                "(client_id,profile_id,assessment_status,validation_status,validator,"
                "validation_date,created_by) VALUES (101,%s,%s,'Validated',%s,CURRENT_DATE,%s)",
                (profile, decision, ACTOR, ACTOR),
            )
        cursor.execute("SELECT * FROM securescope_control_assessments ORDER BY id")
        assessments_before = cursor.fetchall()
    connector = wazuh_service.configured_connector_id()
    binding = monitoring.approve_monitoring_binding(
        "Alpha",
        ACTOR,
        asset_id=1001,
        connector_id=connector,
        manager_name="manager",
        agent_id="007",
        heartbeat_max_age_seconds=300,
        telemetry_max_age_seconds=3600,
        rationale="Synthetic asset identity approved for isolated regression",
    )
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    row = snapshot(
        asset_id=1001,
        binding_id=binding,
        connector_id=connector,
        collected_at=now,
        wazuh_last_keep_alive=now,
    )
    row["telemetry"]["observed_at"] = now
    for _ in range(2):
        row["collected_at"] = datetime.now(timezone.utc)
        run = monitoring.start_monitoring_collection("Alpha", ACTOR, connector)
        monitoring.finish_monitoring_collection("Alpha", ACTOR, run, [row], "succeeded")
        monitoring.finish_monitoring_collection("Alpha", ACTOR, run, [row], "succeeded")
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM securescope_wazuh_observations ORDER BY id")
        first_observations = cursor.fetchall()
        assert len(first_observations) == 1
        cursor.execute("SELECT count(*) FROM securescope_wazuh_run_assets")
        assert cursor.fetchone()["count"] == 2
        cursor.execute("SELECT * FROM securescope_evidence_audit_events ORDER BY id")
        audit_before = cursor.fetchall()
    first = monitoring_evidence(database)
    assert monitoring_evidence(database) == first
    assert [r["id"] for r in scoped_evidence(database, control="A.8.16")] == [first]
    requirement = dict(
        id="monitoring",
        rule="Monitoring coverage",
        title="Monitoring coverage",
        asset_ids=[1001],
        machine_verifiable=True,
        max_age_days=90,
        threshold=100,
    )
    assert (
        evaluate_requirement(
            requirement,
            dict(
                scope_id=601,
                engagement_id=501,
                requirement_evidence=scoped_evidence(database, control="A.8.16"),
            ),
            datetime.now(timezone.utc),
        )["result"]
        == "PASS"
    )
    row["telemetry"]["source_event_id"] = "alerts:event-2"
    run = monitoring.start_monitoring_collection("Alpha", ACTOR, connector)
    monitoring.finish_monitoring_collection("Alpha", ACTOR, run, [row], "succeeded")
    second = monitoring_evidence(database)
    assert second != first
    # New latest evidence does not erase the former source or canonical evidence.
    history = evidence.list_evidence_records("Alpha")
    assert {r["id"] for r in history} == {first, second}
    assert evidence.list_evidence_records("Beta") == []
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM securescope_wazuh_observations ORDER BY id")
        observations = cursor.fetchall()
        assert len(observations) == 2
        assert observations[:1] == first_observations
        for observation in observations:
            encoded = json.dumps(
                observation["payload"], sort_keys=True, separators=(",", ":"), default=str
            )
            assert hashlib.sha256(encoded.encode()).hexdigest() == observation["payload_sha256"]
        cursor.execute("SELECT * FROM securescope_control_assessments ORDER BY id")
        assert cursor.fetchall() == assessments_before
        cursor.execute("SELECT * FROM securescope_evidence_audit_events ORDER BY id")
        audits = cursor.fetchall()
        assert audits[: len(audit_before)] == audit_before
        assert len(audits) > len(audit_before)
    with pytest.raises(monitoring.WazuhDatabaseError, match="authorization"):
        monitoring.start_monitoring_collection("Beta", ACTOR, connector)
    with pytest.raises(monitoring.WazuhDatabaseError, match="authorization"):
        monitoring.start_monitoring_collection("Alpha", "outsider@example.invalid", connector)
    assert scoped_evidence(database, scope=604, client=202, engagement=502, control="A.8.16") == []
    # A subsequent successful API response without telemetry cannot renew monitoring proof.
    row["telemetry"] = {}
    run = monitoring.start_monitoring_collection("Alpha", ACTOR, connector)
    monitoring.finish_monitoring_collection("Alpha", ACTOR, run, [row], "succeeded")
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        assert (
            monitoring.load_monitoring_rows(cursor, 101)[0]["monitoring_state"]
            == "active_unverified"
        )
    assert not any(
        usable_evidence(r, {"wazuh"}) for r in scoped_evidence(database, control="A.8.16")
    )
    assert len(evidence.list_evidence_records("Alpha")) == 2
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM securescope_control_assessments ORDER BY id")
        assert cursor.fetchall() == assessments_before


def test_historical_active_only_evidence_is_retained_but_cannot_satisfy_monitoring(database):
    """An approved legacy mapping remains historical, without becoming telemetry proof."""
    add_profile(database, control="A.8.16")
    legacy_payload = dict(
        metadata=dict(
            automated_checks=[
                dict(
                    check_id="wazuh.monitoring.coverage",
                    mapped_controls=["A.8.16"],
                    effect="supports",
                    check_version=1,
                )
            ],
            assurance=dict(monitoring=dict(evaluated_asset_ids=[1001], satisfied_asset_ids=[1001])),
        )
    )
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute(
            "INSERT INTO securescope_evidence_records "
            "(client_id,evidence_uuid,tool_id,collection_method,evidence_type,title,summary,"
            "scope_description,normalized_payload,collected_at,expires_at,validation_status,"
            "owner,submitted_by,validator,validated_at,verification_origin,source_key) "
            "VALUES (101,%s,'wazuh','Authenticated API','Automated technical evidence',"
            "'Legacy active agent','Historical active-only observation','Explicit scope',%s,"
            "NOW()-interval '1 day',NOW()+interval '89 days','Validated',%s,"
            "'system:wazuh-connector',%s,NOW(),'System collector','legacy-active-only') "
            "RETURNING id",
            (str(uuid4()), Json(legacy_payload), ACTOR, ACTOR),
        )
        identity = cursor.fetchone()["id"]
        cursor.execute(
            "INSERT INTO securescope_evidence_control_mappings "
            "(client_id,evidence_id,control_id,mapping_origin,evidence_dimension,rationale,"
            "consultant_approved,approved_by,approved_at) VALUES "
            "(101,%s,'A.8.16','Consultant mapping','Implementation',"
            "'Historical review',TRUE,%s,NOW())",
            (identity, ACTOR),
        )
        evidence._insert_evidence_scope_link(
            cursor, 101, 501, 601, identity, ACTOR, "Historical link", origin="Automated collection"
        )
        cursor.execute("SELECT * FROM securescope_evidence_records WHERE id=%s", (identity,))
        before = cursor.fetchone()
    scoped = scoped_evidence(database, control="A.8.16")
    assert len(scoped) == 1
    assert not usable_evidence(scoped[0], {"wazuh"})
    requirement = dict(
        id="monitoring",
        title="Monitoring coverage",
        rule="Monitoring coverage",
        asset_ids=[1001],
        machine_verifiable=True,
        max_age_days=90,
        threshold=100,
    )
    assert (
        evaluate_requirement(
            requirement,
            dict(scope_id=601, engagement_id=501, requirement_evidence=scoped),
            datetime.now(timezone.utc),
        )["result"]
        == "NO EVIDENCE"
    )
    assert evidence.list_evidence_records("Alpha")[0]["id"] == identity
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM securescope_evidence_records WHERE id=%s", (identity,))
        assert cursor.fetchone() == before
