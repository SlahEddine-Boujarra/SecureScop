"""Real-database M2 queue contracts; native concurrency cases are gated separately."""

import os

import pytest
from psycopg2.extras import RealDictCursor

from securescope.integrations import wazuh_service
from securescope.persistence import evidence_schedule_repository as schedules
from tests.test_m1_evidence_postgres import ACTOR, add_profile, database  # noqa: F401

pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Dedicated database not configured"
)


@pytest.fixture
def scheduled(database, monkeypatch):
    """Create an approved current target in the isolated actual-schema fixture."""
    from securescope.persistence import db_wazuh_service as monitoring

    monkeypatch.setattr(schedules, "connect", database)
    monkeypatch.setattr(schedules, "run_pending_migrations", lambda: [])
    monkeypatch.setenv("SECURESCOPE_DEPLOYMENT_MODE", "development")
    monkeypatch.setenv("SECURESCOPE_RECURRING_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_WORKER_ALLOWLIST", "test-worker,other-worker")
    connector = wazuh_service.configured_connector_id()
    profile = add_profile(database, control="A.8.16")
    binding = monitoring.approve_monitoring_binding(
        "Alpha",
        ACTOR,
        asset_id=1001,
        connector_id=connector,
        manager_name="manager",
        agent_id="007",
        heartbeat_max_age_seconds=300,
        telemetry_max_age_seconds=3600,
        rationale="Fixture binding",
    )
    target = dict(
        asset_id=1001,
        binding_id=binding,
        engagement_id=501,
        scope_id=601,
        scope_version_id=1601,
        profile_id=profile,
        requirement_id="requirement",
        control_id="A.8.16",
    )
    identity = schedules.create_schedule(
        "Alpha", ACTOR, name="Fixture", connector_id=connector, targets=[target]
    )
    schedules.set_enabled("Alpha", ACTOR, identity, True)
    return database, identity, target


def test_occurrence_retry_recovery_fencing_and_cancellation(scheduled):
    """A recovered lease rejects old writes; cancellation retains attempts and queued retries."""
    database, identity, _ = scheduled
    assert schedules.tick("test-worker") == 1
    assert schedules.tick("other-worker") == 0
    job = schedules.claim("test-worker")
    assert job and job["attempt_count"] == 1
    assert schedules.claim("other-worker") is None
    schedules.renew(job)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_execution_leases SET expires_at=NOW()-interval '1 second'"
        )
    assert schedules.recover_expired("other-worker") == 1
    recovered = schedules.claim("other-worker")
    assert recovered["fencing_token"] > job["fencing_token"]
    with pytest.raises(schedules.LeaseLost):
        schedules.renew(job)
    assert schedules.finish(recovered, error_code="timeout", retryable=True) == "Queued"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET available_at=NOW() WHERE id=%s", (job["id"],)
        )
    last = schedules.claim("test-worker")
    assert last["attempt_count"] == 3
    schedules.cancel_job("Alpha", ACTOR, last["id"])
    with pytest.raises(schedules.LeaseLost):
        schedules.renew(last)
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT outcome FROM securescope_evidence_job_attempts ORDER BY id")
        assert [r["outcome"] for r in cur.fetchall()] == ["abandoned", "failed", "cancelled"]
    assert schedules.list_schedules("Alpha", ACTOR)[0]["jobs"][0]["status"] == "Cancelled"


def test_gate_and_delegation_fail_closed(scheduled, monkeypatch):
    """Production cannot run recurring collection, even when a development flag is enabled."""
    database, identity, _ = scheduled
    monkeypatch.setenv("SECURESCOPE_DEPLOYMENT_MODE", "production")
    assert schedules.tick("test-worker") == 0
    assert schedules.claim("test-worker") is None
    monkeypatch.setenv("SECURESCOPE_DEPLOYMENT_MODE", "development")
    with database() as conn, conn.cursor() as cur:
        cur.execute("UPDATE securescope_workspace_memberships SET active=FALSE WHERE client_id=101")
    assert schedules.tick("test-worker") == 0
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT enabled FROM securescope_evidence_schedules WHERE id=%s", (identity,))
        assert not cur.fetchone()[0]


def test_latest_profile_and_cross_workspace_targets_rejected(scheduled):
    """Neither another tenant's binding nor a historical profile authorizes a schedule."""
    database, identity, target = scheduled
    with pytest.raises(schedules.ScheduleError):
        schedules.queue_now("Beta", ACTOR, identity)
    add_profile(database, control="A.8.16", version=2)
    with pytest.raises(schedules.ScheduleError, match="Profile"):
        schedules.set_enabled("Alpha", ACTOR, identity, True)


def test_missed_polls_coalesce_and_attempt_exhaustion_is_bounded(scheduled):
    """Downtime creates one current occurrence, and a job never exceeds its retry policy."""
    database, identity, _ = scheduled
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_schedules SET next_run_at=NOW()-interval '10 minutes' WHERE id=%s",
            (identity,),
        )
    assert schedules.tick("test-worker") == 1
    assert schedules.tick("other-worker") == 0
    for attempt in range(1, 4):
        job = schedules.claim("test-worker")
        assert job["attempt_count"] == attempt
        expected = "Queued" if attempt < 3 else "Failed"
        assert (
            schedules.finish(job, error_code="timeout", retryable=True, retry_after=99999)
            == expected
        )
        with database() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT EXTRACT(EPOCH FROM (available_at-NOW())) FROM securescope_evidence_jobs WHERE id=%s",
                (job["id"],),
            )
            assert 0 < float(cur.fetchone()[0]) <= 300
            cur.execute(
                "UPDATE securescope_evidence_jobs SET available_at=NOW() WHERE id=%s", (job["id"],)
            )
    assert schedules.claim("test-worker") is None
    row = schedules.list_schedules("Alpha", ACTOR)[0]
    assert row["missed_occurrences"] >= 9
    assert len(schedules.job_history("Alpha", ACTOR, job["id"])["attempts"]) == 3
    with pytest.raises(schedules.ScheduleError):
        schedules.job_history("Beta", ACTOR, job["id"])


def test_database_rejects_cross_scope_and_target_history_mutation(scheduled):
    """Ownership and write-once policy are database constraints, beyond form validation."""
    from securescope.persistence.db_service import DatabaseError

    database, identity, target = scheduled
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM securescope_evidence_schedule_targets WHERE schedule_id=%s", (identity,)
        )
        target_id = cur.fetchone()[0]
    for sql, args in [
        (
            "UPDATE securescope_evidence_schedule_targets SET asset_id=2001 WHERE id=%s",
            (target_id,),
        ),
        ("DELETE FROM securescope_evidence_schedule_targets WHERE id=%s", (target_id,)),
        ("UPDATE securescope_evidence_schedules SET interval_seconds=120 WHERE id=%s", (identity,)),
        (
            "INSERT INTO securescope_evidence_schedule_targets(client_id,schedule_id,asset_id,binding_id,engagement_id,scope_id,scope_version_id,profile_id,requirement_id,control_id) VALUES (101,%s,1001,%s,502,604,1604,%s,'foreign','A.8.16')",
            (identity, target["binding_id"], target["profile_id"]),
        ),
    ]:
        with pytest.raises(DatabaseError):
            with database() as conn, conn.cursor() as cur:
                cur.execute(sql, args)


def test_pause_cancellation_and_rate_budget_are_enforced(scheduled):
    """Pausing rejects collection writes and the host connector budget cannot grow unbounded."""
    from securescope.evidence.collection_scheduler import admit_request
    from securescope.integrations.wazuh_collection_health import CollectionFailure

    database, identity, _ = scheduled
    schedules.queue_now("Alpha", ACTOR, identity)
    job = schedules.claim("test-worker")
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_evidence_connector_budget VALUES(%s,NOW()+interval '20 seconds')",
            (job["connector_id"],),
        )
    with pytest.raises(CollectionFailure, match="rate_limit"):
        admit_request(job)
    schedules.set_enabled("Alpha", ACTOR, identity, False)
    with pytest.raises(schedules.ScheduleError):
        schedules.renew(job)
    schedules.cancel_job("Alpha", ACTOR, job["id"])
    with pytest.raises(schedules.LeaseLost):
        schedules.renew(job)


def test_legacy_direct_collection_cannot_bypass_scheduling(scheduled):
    """A process with stale feature flags cannot run the old HTTP path around an M2 delegation."""
    from securescope.persistence import db_wazuh_service as monitoring

    _, identity, _ = scheduled
    connector = schedules.list_schedules("Alpha", ACTOR)[0]["connector_id"]
    for enabled in (True, False):
        schedules.set_enabled("Alpha", ACTOR, identity, enabled)
        with pytest.raises(monitoring.WazuhDatabaseError, match="Run now"):
            monitoring.start_monitoring_collection("Alpha", ACTOR, connector)
