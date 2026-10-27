"""M3 real SQL, artifact and repository regressions on a disposable database.

PGlite can exercise serial SQL compatibility; native concurrency remains a separate gate.
"""

import json
import os
from datetime import datetime, timezone

import pytest
from psycopg2.extras import Json, RealDictCursor

from securescope.grc.assurance_requirements import evaluate_requirement
from securescope.grc.requirement_templates import baseline_requirements
from securescope.persistence import db_service, evidence_repository, migration_service
from securescope.persistence.nuclei_persistence import create_nuclei_batch
from tests.test_m1_evidence_postgres import (
    ACTOR,
    add_job,
    add_profile,
    database,
    ingest,
    scoped_evidence,
)

pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Dedicated database not configured"
)


def profile(database, control="A.8.8", **kwargs):
    """Create a reviewed exact criterion and return its profile ID and definition."""
    identity = add_profile(database, control=control, **kwargs)
    requirement = baseline_requirements(control)[0 if control == "A.8.8" else -1]
    requirement.update(id="requirement", asset_ids=list(kwargs.get("assets", (1001,))))
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(assessment_scope,'{implementation_requirements,requirements}',%s) WHERE id=%s",
            (Json([requirement]), identity),
        )
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(jsonb_set(assessment_scope,'{implementation_requirements,baseline_template_version}','3'),"
            "'{implementation_requirements,continuous_auto_assurance}','true') WHERE id=%s",
            (identity,),
        )
    return identity, requirement


def queued_job(database, context=None):
    """Queue through the actual repository, then simulate scanner completion without execution."""
    batch = create_nuclei_batch(
        client_name="Alpha",
        assets=[dict(ip="192.0.2.1", m3_requirement_targets=["forged"])],
        scan_mode="Single asset",
        profile_name="standard",
        actor=ACTOR,
        collection_context=context,
    )
    with database() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE securescope_nuclei_jobs SET status='Completed',provider_status='Completed' "
            "WHERE batch_id=%s RETURNING job_uuid,asset_payload",
            (batch["id"],),
        )
        return dict(cur.fetchone())


def evaluate(database, requirement, *, control="A.8.8", profile_id=None, scope=601):
    """Read actual scoped evidence and return its pure requirement evaluation."""
    rows = scoped_evidence(database, control=control, scope=scope)
    return evaluate_requirement(
        requirement,
        dict(
            scope_id=scope,
            engagement_id=501,
            profile=dict(id=profile_id, profile_version=1),
            scope=dict(id=scope + 1000),
            requirement_evidence=rows,
        ),
        datetime.now(timezone.utc),
    )


@pytest.mark.parametrize(
    "control,template,expected",
    [
        ("A.8.8", "", "PASS"),
        ("A.8.9", "http-missing-security-headers", "FAIL"),
        ("A.8.24", "ssl-expired", "FAIL"),
        ("A.8.5", "grafana-default-login", "FAIL"),
    ],
)
def test_scanner_artifact_to_exact_requirement_and_unchanged_decision(
    database, control, template, expected
):
    """Exercise queue, ingestion, protected bytes, exact attribution, evaluation and replay."""
    identity, requirement = profile(database, control)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_control_assessments(client_id,profile_id,assessment_status,validator) "
            "VALUES(101,%s,'Implemented and effective',%s)",
            (identity, ACTOR),
        )
        cur.execute("SELECT row_to_json(a)::text FROM securescope_control_assessments a")
        human_before = cur.fetchall()
    job = queued_job(database)
    assert job["asset_payload"]["m3_requirement_targets"][0]["profile_id"] == identity
    raw = (
        json.dumps({"template-id": template, "host": "https://192.0.2.1"}).encode()
        if template
        else b""
    )
    evidence_id = ingest(job["job_uuid"], content=raw)
    assert ingest(job["job_uuid"], content=raw) == evidence_id
    result = evaluate(database, requirement, control=control, profile_id=identity)
    assert result["result"] == expected
    assert result["evidence_ids"] == [evidence_id]
    assert result["observations"][0]["sha256"]
    assert result["profile_id"] == identity
    assert evidence_repository.repair_nuclei_evidence("Alpha", evidence_id)
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT row_to_json(a)::text FROM securescope_control_assessments a")
        assert cur.fetchall() == human_before
        cur.execute("SELECT count(*) FROM securescope_nuclei_requirement_sources")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM securescope_requirement_check_attributions")
        assert cur.fetchone()[0] == 1
    print("M3 TRACE " + json.dumps(dict(control=control, **result), default=str, sort_keys=True))


def test_origin_scope_and_profile_version_are_frozen_at_queue_time(database):
    """No origin fan-out or retrospective association after a profile change or replay."""
    identity, requirement = profile(database)
    profile(database, scope=602, version=2)
    context = dict(
        client="Alpha",
        scope_id=601,
        engagement_id=501,
        control_id="A.8.8",
        requirement_id="requirement",
    )
    job = queued_job(database, context)
    evidence_id = ingest(job["job_uuid"])
    assert evaluate(database, requirement, profile_id=identity)["result"] == "PASS"
    assert scoped_evidence(database, scope=602) == []
    assert scoped_evidence(database, client=202, engagement=502, scope=604) == []
    newer, _ = profile(database, version=3)
    assert evaluate(database, requirement, profile_id=newer)["result"] == "NO EVIDENCE"
    assert ingest(job["job_uuid"]) == evidence_id
    evidence_repository.repair_nuclei_evidence("Alpha", evidence_id)
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT DISTINCT profile_id FROM securescope_requirement_check_attributions")
        assert cur.fetchall() == [(identity,)]
    second_job = queued_job(database, context)
    profile(database, version=4)
    second_id = ingest(second_job["job_uuid"])
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM securescope_requirement_check_attributions WHERE evidence_id=%s",
            (second_id,),
        )
        assert cur.fetchone()[0] == 0
    assert second_id not in [r["id"] for r in scoped_evidence(database)]


def test_scope_pointer_not_latest_draft_and_changed_requirement_are_checked(database):
    """Drafts preserve current eligibility; an approved replacement or edited criterion revokes it."""
    identity, requirement = profile(database)
    ingest(queued_job(database)["job_uuid"])
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_scope_versions(id,client_id,engagement_id,scope_id,version_number,status,scope_statement,prepared_by) "
            "VALUES(2601,101,501,601,2,'Draft','New draft',%s)",
            (ACTOR,),
        )
    assert evaluate(database, requirement, profile_id=identity)["result"] == "PASS"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(assessment_scope,'{implementation_requirements,requirements,0,title}','\"Changed criterion\"') WHERE id=%s",
            (identity,),
        )
    assert evaluate(database, requirement, profile_id=identity)["result"] == "NO EVIDENCE"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope="
            "jsonb_set(assessment_scope,'{implementation_requirements,requirements}',%s) WHERE id=%s",
            (Json([requirement]), identity),
        )
        cur.execute("UPDATE securescope_scope_versions SET status='Under review' WHERE id=2601")
        cur.execute(
            "UPDATE securescope_scope_versions SET status='Reviewed',reviewed_by=%s,reviewed_at=NOW(),review_rationale='Reviewed fixture' WHERE id=2601",
            (ACTOR,),
        )
        cur.execute(
            "UPDATE securescope_scope_versions SET status='Approved',approved_by=%s,approved_at=NOW() WHERE id=2601",
            (ACTOR,),
        )
        cur.execute(
            "UPDATE securescope_scope_definitions SET current_approved_version_id=2601 WHERE id=601"
        )
    assert evaluate(database, requirement, profile_id=identity)["result"] == "NO EVIDENCE"


@pytest.mark.parametrize(
    "table",
    ["securescope_nuclei_requirement_sources", "securescope_requirement_check_attributions"],
)
def test_additive_records_are_append_only_and_owner_checked(database, table):
    """History rejects mutation/deletion and cannot be moved to another workspace."""
    profile(database)
    ingest(queued_job(database)["job_uuid"])
    for statement in (f"UPDATE {table} SET client_id=202", f"DELETE FROM {table}"):
        with pytest.raises(db_service.DatabaseError, match="append-only"):
            with database() as conn, conn.cursor() as cur:
                cur.execute(statement)
    with pytest.raises(db_service.DatabaseError, match="mismatch"):
        with database() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO securescope_requirement_check_attributions "
                "(client_id,evidence_id,profile_id,engagement_id,scope_id,scope_version_id,requirement_id,asset_id,rule_version,requirement_sha256) "
                "SELECT 202,evidence_id,profile_id,502,604,1604,requirement_id,2001,rule_version,requirement_sha256 "
                "FROM securescope_requirement_check_attributions"
            )


def test_tampered_artifact_and_job_state_never_provide_coverage(database):
    """Artifact hashes and the canonical job status are rechecked at every read."""
    from securescope.evidence.storage import evidence_root

    identity, requirement = profile(database)
    job = queued_job(database)
    ingest(job["job_uuid"])
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_nuclei_jobs SET provider_status='Failed' WHERE job_uuid=%s",
            (job["job_uuid"],),
        )
    assert evaluate(database, requirement, profile_id=identity)["result"] == "NO EVIDENCE"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_nuclei_jobs SET provider_status='Completed' WHERE job_uuid=%s",
            (job["job_uuid"],),
        )

    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT storage_reference FROM securescope_evidence_artifacts WHERE client_id=101"
        )
        artifact = evidence_root() / cur.fetchone()[0]
    original = artifact.read_bytes()
    artifact.write_bytes(b"corrupted ciphertext")
    assert evaluate(database, requirement, profile_id=identity)["result"] == "NO EVIDENCE"
    artifact.write_bytes(original)
    assert evaluate(database, requirement, profile_id=identity)["result"] == "PASS"
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_nuclei_jobs SET asset_payload=jsonb_set(asset_payload,'{m3_requirement_targets}','[]') WHERE job_uuid=%s",
            (job["job_uuid"],),
        )
    assert evaluate(database, requirement, profile_id=identity)["result"] == "NO EVIDENCE"


def test_real_workspace_audit_is_idempotent_and_preserves_prior_decisions(database, monkeypatch):
    """The real Control Assurance read and encrypted snapshot path retain prior state."""
    from securescope.persistence.assurance_workspace_repository import (
        load_workspace,
        record_evaluation,
    )

    monkeypatch.setenv(
        "SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY", os.environ["SECURESCOPE_EVIDENCE_ENCRYPTION_KEY"]
    )
    identity, _ = profile(database, "A.8.9")
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_control_assessments(client_id,profile_id,assessment_status,validation_status,validator) "
            "VALUES(101,%s,'Implemented and effective','Validated',%s)",
            (identity, ACTOR),
        )
        cur.execute("SELECT row_to_json(t)::text FROM securescope_control_assessments t")
        before = cur.fetchall()
    record_evaluation("Alpha", "A.8.9", ACTOR, 501, 601)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id,event_payload FROM securescope_evidence_audit_events WHERE event_type='control_requirement_evaluation'"
        )
        historic = cur.fetchall()
    ingest(
        queued_job(database)["job_uuid"],
        content=b'{"template-id":"missing-x-frame-options","host":"192.0.2.1"}',
    )
    view = load_workspace("Alpha", "A.8.9", ACTOR, 501, 601)
    result = record_evaluation("Alpha", "A.8.9", ACTOR, 501, 601)
    assert view["result"]["requirements"][0]["result"] == "FAIL"
    assert result["technical_review_required"]
    assert result["assurance"] == "Needs Review"
    assert result["human_assessment"]["status"] == "Implemented and effective"
    record_evaluation("Alpha", "A.8.9", ACTOR, 501, 601)
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id,event_payload FROM securescope_evidence_audit_events WHERE event_type='control_requirement_evaluation' ORDER BY id"
        )
        history = cur.fetchall()
        assert len(history) == 2 and history[:1] == historic
        cur.execute("SELECT row_to_json(t)::text FROM securescope_control_assessments t")
        assert cur.fetchall() == before
    print(
        "M3 Control Assurance: new scoped gap -> Needs Review; approved human decision and prior encrypted snapshot unchanged; repeated evaluation deduplicated."
    )


def test_real_bounded_evidence_query_never_claims_complete_coverage(database):
    """The 501st SQL row marks the returned 500 summaries as an incomplete window."""
    identity, requirement = profile(database)
    ingest(queued_job(database)["job_uuid"])
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO securescope_evidence_records(client_id,evidence_uuid,tool_id,collection_method,evidence_type,title,summary,scope_description,collected_at,owner,submitted_by) "
            "SELECT 101,md5('m3-fixture-'||n)::uuid,'nuclei','Existing worker','Scan','Historic','Fixture','Scope',NOW(),'fixture','fixture' FROM generate_series(1,500) n RETURNING id"
        )
        identities = [r[0] for r in cur.fetchall()]
        cur.execute(
            "INSERT INTO securescope_evidence_control_mappings(client_id,evidence_id,control_id,mapping_origin,evidence_dimension,rationale) "
            "SELECT 101,id,'A.8.8','Automated check','Implementation','Fixture' FROM securescope_evidence_records WHERE id=ANY(%s)",
            (identities,),
        )
        cur.execute(
            "INSERT INTO securescope_engagement_record_links(client_id,engagement_id,scope_id,link_key,evidence_id,link_origin,rationale,linked_by) "
            "SELECT 101,501,601,'m3-fixture-'||id,id,'Scope inheritance','Fixture','fixture' FROM securescope_evidence_records WHERE id=ANY(%s)",
            (identities,),
        )
    rows = scoped_evidence(database)
    assert len(rows) == 500 and all(r["evidence_window_incomplete"] for r in rows)
    assert (
        evaluate(database, requirement, profile_id=identity)["reason_code"]
        == "incomplete_evidence_window"
    )


def test_fresh_scan_does_not_hide_a_gap_and_wrong_target_blocks_coverage(database):
    """A clean retest lacks a negative execution contract; foreign target data is ineligible."""
    identity, requirement = profile(database, "A.8.9")
    _, coverage = profile(database)
    ingest(
        queued_job(database)["job_uuid"],
        content=b'{"template-id":"missing-x-frame-options","host":"192.0.2.1"}',
    )
    ingest(queued_job(database)["job_uuid"])
    assert evaluate(database, requirement, control="A.8.9", profile_id=identity)["result"] == "FAIL"
    # A separately assigned scope has only the suspect source, avoiding legitimate older coverage.
    profile(database, scope=602, version=2)
    context = dict(
        client="Alpha",
        scope_id=602,
        engagement_id=501,
        control_id="A.8.8",
        requirement_id="requirement",
    )
    ingest(
        queued_job(database, context)["job_uuid"],
        content=b'{"template-id":"ssl-expired","host":"other.invalid","ip":"192.0.2.1"}',
    )
    assert evaluate(database, coverage, scope=602)["result"] == "NO EVIDENCE"
