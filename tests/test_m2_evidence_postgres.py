"""Actual-schema M2 integration and recovery demonstration with synthetic Wazuh responses."""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from psycopg2.extras import RealDictCursor

from securescope.evidence import wazuh_scheduled as worker
from securescope.evidence.storage import EvidenceStorageError, read_artifact
from securescope.grc.assurance_requirements import evaluate_requirement
from securescope.integrations.wazuh_collection_health import validate_hit
from securescope.persistence import evidence_repository as evidence
from securescope.persistence import evidence_schedule_repository as schedules
from securescope.persistence import wazuh_evidence_repository as sources
from tests.test_m1_evidence_postgres import ACTOR, database  # noqa: F401
from tests.test_m2_scheduling_postgres import scheduled  # noqa: F401

pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Dedicated database not configured"
)
POLICY = dict(
    schema_version=1,
    mode="canary",
    index_pattern="wazuh-archives-*",
    channel="/var/log/health",
    max_age_seconds=120,
)


class QuietWazuh:
    """Deterministic agent source with no security alerts; no live validation is claimed."""

    verify_tls = True
    api_url = "https://manager.invalid"
    timeout = 10

    def list_agents(self, *, agent_ids):
        """Return exact fixture identities and a fresh heartbeat."""
        return [
            dict(
                id=i,
                name="test-agent",
                status="active",
                manager="manager",
                lastKeepAlive=datetime.now(timezone.utc).isoformat(),
                ip="192.0.2.1",
            )
            for i in agent_ids
        ]

    def search_last_alert_for_agent(self, *, agent_id, manager_name):
        """Return a successful empty security-event query."""
        return {}


def health(sequence=1, event="synthetic-event-0001", observed=None):
    """Validate a synthetic canary using the real source contract."""
    stamp = (observed or datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    hit = dict(
        _index="wazuh-archives-test",
        _id=event,
        _source=dict(
            agent=dict(id="007"),
            manager=dict(name="manager"),
            location=POLICY["channel"],
            timestamp=stamp,
            data=dict(
                securescope_health=dict(
                    version=1,
                    channel=POLICY["channel"],
                    event_id=event,
                    sequence=sequence,
                    observed_at=stamp,
                )
            ),
        ),
    )
    return validate_hit(hit, POLICY, agent_id="007", manager_name="manager")


@pytest.fixture
def pipeline(scheduled, monkeypatch):
    """Bind M2 repositories to the real schema; replace only network and rate wait boundaries."""
    database, identity, target = scheduled
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(assessment_scope,'{implementation_requirements,requirements,0}',"
            "(assessment_scope#>'{implementation_requirements,requirements,0}') || "
            '\'{"expected_result":"Verified source channel","type":"Technical","mandatory":true}\'::jsonb) '
            "WHERE id=%s",
            (target["profile_id"],),
        )
    monkeypatch.setattr(sources, "connect", database)
    monkeypatch.setattr(worker, "WazuhClient", QuietWazuh)
    monkeypatch.setattr(worker, "admit_request", schedules.renew)
    monkeypatch.setenv(
        "SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", os.environ["SECURESCOPE_EVIDENCE_ENCRYPTION_KEY"]
    )
    return database, identity, target


def health_schedule(pipeline):
    """Approve a precise health-enabled profile/target in the synthetic fixture."""
    database, identity, target = pipeline
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(assessment_scope,'{implementation_requirements,requirements,0,allow_collection_health}','true') "
            "WHERE id=%s",
            (target["profile_id"],),
        )
    configured = dict(target, accept_health=True, health_policy=POLICY)
    connector = schedules.list_schedules("Alpha", ACTOR)[0]["connector_id"]
    revision = schedules.create_schedule(
        "Alpha",
        ACTOR,
        name="Quiet-agent proof",
        connector_id=connector,
        targets=[configured],
        replaces=identity,
    )
    schedules.set_enabled("Alpha", ACTOR, revision, True)
    return revision


def run_job(identity):
    """Queue and execute through the same typed handler used by the Evidence Worker."""
    schedules.queue_now("Alpha", ACTOR, identity)
    job = schedules.claim("test-worker")
    assert job
    assert worker.process_scheduled_job(job) == "Succeeded"
    return job


def test_quiet_agent_protected_evidence_reaches_exact_control_assurance(pipeline, monkeypatch):
    """E2E: schedule -> attempt -> source -> encrypted artifact -> canonical evidence -> requirement PASS."""
    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    proof = health()
    monkeypatch.setattr(worker, "acquire_health", lambda *args: proof)
    # Existing human decision tables are snapshotted and must remain byte-for-byte unchanged.
    tables = [
        "securescope_control_assessments",
        "securescope_soa_items",
        "securescope_grc_approvals",
        "securescope_risk_acceptances",
    ]
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_control_assessments (client_id,profile_id,assessment_status,validation_status,validator) VALUES (101,%s,'Implemented and effective','Validated',%s)",
            (pipeline[2]["profile_id"], ACTOR),
        )
    with database() as conn, conn.cursor() as cur:
        existing = []
        for name in tables:
            cur.execute("SELECT to_regclass(%s)", (name,))
            if cur.fetchone()[0]:
                existing.append(name)
        before = {}
        for name in existing:
            cur.execute(f"SELECT row_to_json(t)::text FROM {name} t ORDER BY id")
            before[name] = cur.fetchall()
    job = run_job(identity)
    from securescope.persistence.assurance_workspace_repository import record_evaluation

    evaluated = record_evaluation("Alpha", "A.8.16", ACTOR, 501, 601)
    assert (
        next(r for r in evaluated["requirements"] if r["id"] == "requirement")["result"] == "PASS"
    )
    records = evidence.list_evidence_records("Alpha")
    assert len(records) == 1
    record = records[0]
    assert record["source_verification_current"]
    assert record["eligible_requirement_ids"] == ["requirement"]
    assert record["tool_id"] == "wazuh"
    raw = read_artifact(101, record["storage_reference"], expected_sha256=record["sha256"])
    assert hashlib.sha256(raw).hexdigest() == record["sha256"]
    assert json.loads(raw)["facts"]["telemetry"]["kind"] == "collection_health"
    assert record["storage_reference"].endswith(".enc")
    with pytest.raises(EvidenceStorageError):
        read_artifact(202, record["storage_reference"], expected_sha256=record["sha256"])
    with pytest.raises(EvidenceStorageError):
        read_artifact(101, record["storage_reference"], expected_sha256="0" * 64)
    from securescope.persistence.assurance_workspace_repository import load_workspace

    view = load_workspace("Alpha", "A.8.16", ACTOR, 501, 601)
    record = next(e for e in view["bundle"]["requirement_evidence"] if e["id"] == record["id"])
    requirement = dict(
        id="requirement",
        title="Monitoring",
        rule="Monitoring coverage",
        asset_ids=[1001],
        threshold=100,
        max_age_days=90,
        machine_verifiable=True,
    )
    bundle = dict(scope_id=601, engagement_id=501, requirement_evidence=[record])
    result = evaluate_requirement(requirement, bundle, datetime.now(timezone.utc))
    assert result["result"] == "PASS", result
    assert (
        evaluate_requirement(
            dict(requirement, id="unapproved-requirement"), bundle, datetime.now(timezone.utc)
        )["result"]
        != "PASS"
    )
    assert (
        evaluate_requirement(
            dict(requirement, rule="Log source coverage"), bundle, datetime.now(timezone.utc)
        )["result"]
        != "PASS"
    )
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT scope_id FROM securescope_engagement_record_links WHERE evidence_id=%s",
            (record["id"],),
        )
        assert cur.fetchall() == [(601,)]
        cur.execute(
            "SELECT count(*) FROM securescope_evidence_job_results WHERE job_id=%s", (job["id"],)
        )
        assert cur.fetchone()[0] == 1
        for name in existing:
            cur.execute(f"SELECT row_to_json(t)::text FROM {name} t ORDER BY id")
            assert cur.fetchall() == before[name]
    print(
        "M2 E2E: quiet agent -> protected artifact -> exact A.8.16 requirement PASS; A.8.15 excluded."
    )


def test_active_agent_without_proof_preserves_unverified_history(pipeline):
    """Successful empty acquisition never publishes verified monitoring evidence."""
    database, identity, _ = pipeline
    run_job(identity)
    run_job(identity)
    assert evidence.list_evidence_records("Alpha") == []
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM securescope_wazuh_collection_runs")
        assert cur.fetchone()[0] == 2
        cur.execute(
            "SELECT count(*) FROM securescope_evidence_target_attempts WHERE ingestion='not_eligible'"
        )
        assert cur.fetchone()[0] == 2


def test_crash_after_source_resumes_exact_artifact_and_rejects_old_worker(pipeline, monkeypatch):
    """Recover a committed source without new HTTP, then deduplicate publication."""
    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    proof = health()
    monkeypatch.setattr(worker, "acquire_health", lambda *args: proof)
    schedules.queue_now("Alpha", ACTOR, identity)
    old = schedules.claim("test-worker")
    target = old["targets"][0]
    row, failure = worker.collect_target(old, target, QuietWazuh())
    assert failure is None
    sources.save_source(old, target, row)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_execution_leases SET expires_at=NOW()-interval '1 second'"
        )
    schedules.recover_expired("other-worker")
    job = schedules.claim("other-worker")
    with pytest.raises(schedules.LeaseLost):
        sources.save_source(old, target, row)

    def forbidden(*args, **kwargs):
        raise AssertionError("Persisted acquisition must resume without new source requests")

    monkeypatch.setattr(worker, "collect_target", forbidden)
    persisted = sources.existing_source(job, target)
    first = worker.publish(job, target, persisted)
    assert worker.publish(job, target, persisted) == first
    assert worker.process_scheduled_job(job) == "Succeeded"
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM securescope_evidence_records")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM securescope_evidence_artifacts")
        assert cur.fetchone()[0] == 1


def test_scope_change_blocks_stored_source_publication(pipeline, monkeypatch):
    """A mid-run approved-version change preserves acquired history without granting coverage."""
    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    schedules.queue_now("Alpha", ACTOR, identity)
    job = schedules.claim("test-worker")
    target = job["targets"][0]
    row, _ = worker.collect_target(job, target, QuietWazuh())
    sources.save_source(job, target, row)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_scope_definitions SET current_approved_version_id=NULL WHERE id=601"
        )
    assert worker.process_scheduled_job(job) == "Failed"
    assert evidence.list_evidence_records("Alpha") == []
    assert not schedules.list_schedules("Alpha", ACTOR)[0]["enabled"]


def test_partial_failure_keeps_independent_health_and_retries_only_failed_acquisition(
    pipeline, monkeypatch
):
    """An unavailable alert stream cannot erase approved health evidence for another target."""
    from securescope.integrations.wazuh_service import WazuhError
    from tests.test_m1_evidence_postgres import add_profile

    database, _, original = pipeline
    health_identity = health_schedule(pipeline)
    profile = add_profile(database, control="A.8.15")
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope=jsonb_set(assessment_scope,"
            "'{implementation_requirements,requirements,0,rule}','\"Log source coverage\"') WHERE id=%s",
            (profile,),
        )
    connector = schedules.list_schedules("Alpha", ACTOR)[0]["connector_id"]
    identity = schedules.create_schedule(
        "Alpha",
        ACTOR,
        name="Two streams",
        connector_id=connector,
        targets=[
            dict(original, accept_health=True, health_policy=POLICY),
            dict(original, profile_id=profile, control_id="A.8.15"),
        ],
        replaces=health_identity,
    )
    schedules.set_enabled("Alpha", ACTOR, identity, True)
    calls = []

    def unavailable(self, **kwargs):
        calls.append(kwargs)
        raise WazuhError("Indexer query failed: HTTP 429")

    monkeypatch.setattr(QuietWazuh, "search_last_alert_for_agent", unavailable)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    schedules.queue_now("Alpha", ACTOR, identity)
    first = schedules.claim("test-worker")
    assert worker.process_scheduled_job(first) == "Queued"
    assert len(calls) == 2
    record = evidence.list_evidence_records("Alpha")[0]
    assert record["source_verification_current"]
    assert record["normalized_payload"]["metadata"]["provenance"]["check"] == "monitoring"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET available_at=NOW() WHERE id=%s", (first["id"],)
        )
    retry = schedules.claim("other-worker")
    assert worker.process_scheduled_job(retry) == "Queued"
    assert len(calls) == 3  # Successful health acquisition was resumed, not repeated.
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT diagnostic_outcome FROM securescope_evidence_jobs WHERE id=%s", (first["id"],)
        )
        assert cur.fetchone()[0] == "partial"
        cur.execute("SELECT count(*) FROM securescope_evidence_records")
        assert cur.fetchone()[0] == 1


def test_replay_cannot_refresh_event_and_failure_invalidates_current_target(pipeline, monkeypatch):
    """Reusing a canary identity with new times/sequence is rejected and history stays retrievable."""
    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    first = health()
    monkeypatch.setattr(worker, "acquire_health", lambda *args: first)
    run_job(identity)
    before = evidence.list_evidence_records("Alpha")[0]
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health(sequence=2))
    schedules.queue_now("Alpha", ACTOR, identity)
    job = schedules.claim("test-worker")
    assert worker.process_scheduled_job(job) == "Failed"
    after = evidence.list_evidence_records("Alpha")[0]
    assert after["id"] == before["id"] and after["collected_at"] == before["collected_at"]
    assert not after["source_verification_current"]
    assert not schedules.list_schedules("Alpha", ACTOR)[0]["enabled"]
    read_artifact(101, after["storage_reference"], expected_sha256=after["sha256"])


def test_new_profile_removes_current_eligibility_without_rewriting_evidence(pipeline, monkeypatch):
    """Newest per-scope profile wins, and the legacy bridge cannot broaden M2 associations."""
    from securescope.evidence.wazuh_bridge import ingest_wazuh_evidence
    from tests.test_m1_evidence_postgres import add_profile

    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    run_job(identity)
    before = evidence.list_evidence_records("Alpha")[0]
    assert ingest_wazuh_evidence("Alpha", ACTOR) == []
    add_profile(database, scope=602, control="A.8.16", version=2)
    assert evidence.list_evidence_records("Alpha")[0]["source_verification_current"]
    add_profile(database, scope=601, control="A.8.16", version=3)
    after = evidence.list_evidence_records("Alpha")[0]
    assert after["id"] == before["id"] and not after["source_verification_current"]


def test_missing_artifact_prevents_publication_and_retains_resume_identity(pipeline, monkeypatch):
    """A protected source cannot become canonical if its retained bytes are unavailable."""
    from pathlib import Path

    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    schedules.queue_now("Alpha", ACTOR, identity)
    job = schedules.claim("test-worker")
    target = job["targets"][0]
    row, _ = worker.collect_target(job, target, QuietWazuh())
    sources.save_source(job, target, row)
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT storage_reference FROM securescope_evidence_artifacts")
        reference = cur.fetchone()[0]
    path = Path(os.environ["SECURESCOPE_EVIDENCE_STORAGE_ROOT"]) / reference
    saved = path.read_bytes()
    path.unlink()
    assert worker.process_scheduled_job(job) == "Queued"
    assert evidence.list_evidence_records("Alpha") == []
    path.write_bytes(saved)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET available_at=NOW() WHERE id=%s", (job["id"],)
        )
    recovered = schedules.claim("other-worker")
    assert worker.process_scheduled_job(recovered) == "Succeeded"
    assert len(evidence.list_evidence_records("Alpha")) == 1


def test_snapshot_refresh_failure_is_durable_and_recoverable(pipeline, monkeypatch):
    """Evidence publication succeeds independently; failed encrypted evaluation snapshots retry safely."""
    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    key = os.environ["SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY"]
    monkeypatch.delenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY")
    job = run_job(identity)
    assert len(evidence.list_evidence_records("Alpha")) == 1
    assert (
        schedules.job_history("Alpha", ACTOR, job["id"])["job"]["assurance_refresh_state"]
        == "failed"
    )
    monkeypatch.setenv("SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", key)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET assurance_refresh_available_at=NOW() WHERE id=%s",
            (job["id"],),
        )
    assert worker.refresh_pending("other-worker") == 1
    assert (
        schedules.job_history("Alpha", ACTOR, job["id"])["job"]["assurance_refresh_state"]
        == "succeeded"
    )


def test_reconciliation_reports_orphans_without_removing_referenced_evidence(pipeline, monkeypatch):
    """Reference-aware inspection preserves both known artifacts and interrupted-write orphans."""
    from securescope.cli import verify_evidence_artifacts as audit
    from securescope.evidence.storage import store_protected_artifact

    database, _, _ = pipeline
    identity = health_schedule(pipeline)
    monkeypatch.setattr(worker, "acquire_health", lambda *args: health())
    monkeypatch.setattr(audit, "connect", database)
    run_job(identity)
    orphan = store_protected_artifact(101, "interrupted-write.json", b"{}")
    result = audit.inspect_workspace("Alpha", ACTOR)
    assert result["verified"] == 1 and not result["failed_artifact_ids"]
    assert result["unreferenced_files"] == [orphan.storage_reference]
    assert result["deleted_files"] == 0
    assert read_artifact(101, orphan.storage_reference, expected_sha256=orphan.sha256) == b"{}"
