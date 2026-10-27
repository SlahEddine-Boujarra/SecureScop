"""Approved, tenant-bound scheduling and fenced execution in the Evidence Worker queue."""

from __future__ import annotations

import os
import random
from uuid import uuid4

from psycopg2.extras import Json, RealDictCursor

from securescope.persistence.db_service import connect
from securescope.persistence.evidence_repository import EvidenceRepositoryError, _append_audit_event
from securescope.persistence.foundation_repository import member_role
from securescope.persistence.migration_service import run_pending_migrations

OPERATION = "wazuh.monitoring.collect"
LEASE_SECONDS = 90
DEADLINE_SECONDS = 900


class ScheduleError(EvidenceRepositoryError):
    """Reject unauthorized, changed or malformed scheduling context."""


class LeaseLost(ScheduleError):
    """Reject writes from expired, cancelled or superseded execution owners."""


def worker_allowed(worker: str) -> bool:
    """Check the explicit development gate; production remains disabled.

    Args:
        worker: Host-configured worker identity.
    Returns:
        Whether this development worker may execute recurring jobs.
    Raises:
        No expected exceptions.
    """
    allowed = {
        name.strip() for name in os.getenv("SECURESCOPE_EVIDENCE_WORKER_ALLOWLIST", "").split(",")
    }
    return bool(
        os.getenv("SECURESCOPE_DEPLOYMENT_MODE") == "development"
        and os.getenv("SECURESCOPE_RECURRING_EVIDENCE_ENABLED", "").lower() == "true"
        and worker
        and worker in allowed
    )


def _audit(cursor, client_id, actor, event, identity, payload=None):
    """Append a scheduler audit event; arguments identify the tenant and operation.

    Returns:
        None.
    Raises:
        DatabaseError: On persistence failure.
    """
    _append_audit_event(
        cursor,
        client_id,
        event_type=event,
        entity_type="Evidence schedule",
        entity_id=str(identity),
        actor=actor,
        summary=event,
        payload=payload or {},
    )


def validate_target(cursor, client_id, target, connector_id):
    """Validate exact current membership and approved version without older-profile fallback.

    Args:
        cursor: Transaction cursor; client_id: tenant; target: pinned IDs; connector_id: source.
    Returns:
        Binding and immutable profile requirement metadata.
    Raises:
        ScheduleError: If any identity, permission context or scope version differs.
    """
    cursor.execute(
        "SELECT b.*,a.ip,a.asset_tag FROM securescope_wazuh_bindings b "
        "JOIN securescope_assets a ON a.client_id=b.client_id AND a.id=b.asset_id "
        "WHERE b.client_id=%s AND b.id=%s AND b.asset_id=%s AND b.connector_id=%s "
        "AND b.revoked_at IS NULL FOR SHARE OF b,a",
        (client_id, target["binding_id"], target["asset_id"], connector_id),
    )
    binding = cursor.fetchone()
    if not binding:
        raise ScheduleError("Binding or asset is no longer authorized.")
    cursor.execute(
        "SELECT s.id FROM securescope_scope_definitions s JOIN securescope_scope_versions v "
        "ON v.client_id=s.client_id AND v.scope_id=s.id AND v.id=s.current_approved_version_id "
        "JOIN securescope_engagements e ON e.client_id=s.client_id AND e.id=s.engagement_id "
        "WHERE s.client_id=%s AND s.id=%s AND s.engagement_id=%s AND v.id=%s "
        "AND NOT s.archived AND v.status='Approved' AND e.status NOT IN ('Completed','Cancelled') FOR SHARE OF s,v,e",
        (client_id, target["scope_id"], target["engagement_id"], target["scope_version_id"]),
    )
    if not cursor.fetchone():
        raise ScheduleError("The approved scope version changed or is unavailable.")
    cursor.execute(
        "SELECT id,profile_version,assessment_scope FROM securescope_control_assessment_profiles "
        "WHERE client_id=%s AND control_id=%s AND "
        "assessment_scope->'implementation_requirements'->>'scope_id'=%s "
        "ORDER BY profile_version DESC LIMIT 1 FOR SHARE",
        (client_id, target["control_id"], str(target["scope_id"])),
    )
    profile = cursor.fetchone()
    config = (profile or {}).get("assessment_scope", {}).get("implementation_requirements", {})
    requirement = next(
        (r for r in config.get("requirements", []) if r.get("id") == target["requirement_id"]), None
    )
    expected_rule = {"A.8.15": "Log source coverage", "A.8.16": "Monitoring coverage"}.get(
        target["control_id"]
    )
    if (
        not profile
        or profile["id"] != target["profile_id"]
        or config.get("engagement_id") != target["engagement_id"]
        or config.get("scope_version_id") != target["scope_version_id"]
        or not config.get("reviewed")
        or not requirement
        or requirement.get("rule") != expected_rule
        or target["asset_id"] not in requirement.get("asset_ids", [])
    ):
        raise ScheduleError("The exact reviewed Control Profile requirement changed.")
    if target.get("accept_health") and (
        target["control_id"] != "A.8.16" or not requirement.get("allow_collection_health")
    ):
        raise ScheduleError("This requirement has not approved collection-health proof.")
    return dict(binding, requirement=requirement, profile_version=profile["profile_version"])


def create_schedule(
    client_name,
    actor,
    *,
    name,
    connector_id,
    targets,
    interval_seconds=60,
    max_attempts=3,
    replaces=None,
):
    """Create a disabled immutable schedule revision approved by a current administrator.

    Args:
        client_name: Workspace; actor: trusted administrator; name: label; connector_id: source.
        targets: Explicit pinned dictionaries; interval_seconds: UTC cadence; max_attempts: bound.
        replaces: Optional previous schedule ID to supersede atomically.
    Returns:
        New numeric schedule ID.
    Raises:
        ScheduleError: For invalid context/policy; WazuhError: For denied host administration.
    """
    from securescope.integrations.wazuh_collection_health import validate_health_policy
    from securescope.integrations.wazuh_service import (
        configured_connector_id,
        require_connector_admin,
    )

    require_connector_admin(client_name, actor)
    if connector_id != configured_connector_id():
        raise ScheduleError("Connector configuration changed.")
    if not name.strip() or not 30 <= interval_seconds <= 604800 or not 1 <= max_attempts <= 5:
        raise ScheduleError("Invalid schedule name, interval or attempt limit.")
    if not targets or len(targets) > 100:
        raise ScheduleError("Select between one and 100 explicit targets.")
    run_pending_migrations()
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id FROM securescope_clients WHERE name=%s", (client_name,))
        client = cur.fetchone()
        if not client or member_role(cur, client["id"], actor) != "Administrator":
            raise ScheduleError("Current workspace Administrator membership is required.")
        client_id = client["id"]
        identity, revision = str(uuid4()), 1
        if replaces:
            cur.execute(
                "SELECT * FROM securescope_evidence_schedules WHERE client_id=%s AND id=%s FOR UPDATE",
                (client_id, replaces),
            )
            old = cur.fetchone()
            if not old:
                raise ScheduleError("Schedule does not belong to this workspace.")
            identity, revision = str(old["schedule_uuid"]), old["revision"] + 1
            cur.execute(
                "UPDATE securescope_evidence_schedules SET enabled=FALSE,pause_reason='Superseded' "
                "WHERE client_id=%s AND id=%s",
                (client_id, replaces),
            )
        for target in targets:
            binding = validate_target(cur, client_id, target, connector_id)
            if interval_seconds >= min(
                binding["heartbeat_max_age_seconds"], binding["telemetry_max_age_seconds"]
            ):
                raise ScheduleError(
                    "Collection interval must be shorter than the heartbeat and telemetry policies."
                )
            if target.get("accept_health"):
                validate_health_policy(target.get("health_policy", {}))
                if interval_seconds >= target["health_policy"]["max_age_seconds"]:
                    raise ScheduleError(
                        "Collection interval must be shorter than the health proof policy."
                    )
            elif target.get("health_policy"):
                raise ScheduleError("Health policy requires an explicitly eligible requirement.")
        cur.execute(
            "INSERT INTO securescope_evidence_schedules "
            "(client_id,schedule_uuid,revision,connector_id,name,interval_seconds,max_attempts,approved_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (
                client_id,
                identity,
                revision,
                connector_id,
                name.strip(),
                interval_seconds,
                max_attempts,
                actor,
            ),
        )
        schedule_id = cur.fetchone()["id"]
        for target in targets:
            cur.execute(
                "INSERT INTO securescope_evidence_schedule_targets "
                "(client_id,schedule_id,asset_id,binding_id,engagement_id,scope_id,scope_version_id,"
                "profile_id,requirement_id,control_id,accept_health,health_policy) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    client_id,
                    schedule_id,
                    *[
                        target[k]
                        for k in (
                            "asset_id",
                            "binding_id",
                            "engagement_id",
                            "scope_id",
                            "scope_version_id",
                            "profile_id",
                            "requirement_id",
                            "control_id",
                        )
                    ],
                    bool(target.get("accept_health")),
                    Json(target.get("health_policy") or {}),
                ),
            )
        _audit(
            cur,
            client_id,
            actor,
            "Schedule approved (disabled)",
            schedule_id,
            {"revision": revision},
        )
        return schedule_id


def set_enabled(client_name, actor, schedule_id, enabled):
    """Enable or pause a pinned schedule after current administrator authorization.

    Args:
        client_name, actor: Trusted workspace context; schedule_id: owned ID; enabled: desired state.
    Returns:
        None.
    Raises:
        ScheduleError: On denied or obsolete context.
    """
    from securescope.integrations.wazuh_service import (
        configured_connector_id,
        require_connector_admin,
    )

    require_connector_admin(client_name, actor)
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        schedule = _schedule(cur, client_name, actor, schedule_id, admin=True)
        if enabled:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"wazuh-collection-boundary:{schedule['client_id']}:{schedule['connector_id']}",),
            )
            cur.execute(
                "SELECT id FROM securescope_wazuh_collection_runs WHERE client_id=%s "
                "AND connector_id=%s AND outcome='running' LIMIT 1",
                (schedule["client_id"], schedule["connector_id"]),
            )
            if cur.fetchone():
                raise ScheduleError(
                    "Finish or investigate the existing on-demand collection before enabling M2."
                )
            if schedule["connector_id"] != configured_connector_id():
                raise ScheduleError("Connector configuration changed.")
            for target in _targets(cur, schedule["client_id"], schedule_id):
                validate_target(cur, schedule["client_id"], target, schedule["connector_id"])
        cur.execute(
            "UPDATE securescope_evidence_schedules SET enabled=%s,pause_reason=%s,next_run_at=NOW() "
            "WHERE client_id=%s AND id=%s",
            (
                enabled,
                "" if enabled else "Paused by administrator",
                schedule["client_id"],
                schedule_id,
            ),
        )
        _audit(
            cur,
            schedule["client_id"],
            actor,
            "Schedule enabled" if enabled else "Schedule paused",
            schedule_id,
        )


def _schedule(cursor, client_name, actor, schedule_id, *, admin=False):
    """Resolve an owned schedule and authorize its reader/mutator.

    Returns:
        Schedule dictionary for the supplied client, actor and schedule ID.
    Raises:
        ScheduleError: On missing schedule or insufficient membership.
    """
    cursor.execute(
        "SELECT s.*,c.name AS client_name FROM securescope_evidence_schedules s "
        "JOIN securescope_clients c ON c.id=s.client_id WHERE c.name=%s AND s.id=%s FOR UPDATE OF s",
        (client_name, schedule_id),
    )
    row = cursor.fetchone()
    roles = {"Administrator"} if admin else {"Administrator", "Consultant"}
    if not row or member_role(cursor, row["client_id"], actor) not in roles:
        raise ScheduleError("Authorized workspace schedule access is required.")
    return dict(row)


def _targets(cursor, client_id, schedule_id):
    """Read immutable targets for an exact tenant/schedule; return list, raising DB errors."""
    cursor.execute(
        "SELECT * FROM securescope_evidence_schedule_targets WHERE client_id=%s "
        "AND schedule_id=%s ORDER BY id",
        (client_id, schedule_id),
    )
    return [dict(row) for row in cursor.fetchall()]


def _enqueue(cursor, schedule, scheduled_for, actor):
    """Insert one idempotent occurrence for a validated schedule; return job ID or None."""
    cursor.execute(
        "INSERT INTO securescope_evidence_jobs "
        "(client_id,job_uuid,tool_id,job_type,operation,schedule_id,scheduled_for,"
        "request_payload,requested_by,max_attempts) "
        "VALUES (%s,%s,'wazuh','Collect',%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT DO NOTHING RETURNING id",
        (
            schedule["client_id"],
            str(uuid4()),
            OPERATION,
            schedule["id"],
            scheduled_for,
            Json({"schedule_revision": schedule["revision"]}),
            actor,
            schedule["max_attempts"],
        ),
    )
    row = cursor.fetchone()
    return row["id"] if row else None


def queue_now(client_name, actor, schedule_id):
    """Queue a manual occurrence using existing reviewed targets, without HTTP.

    Args:
        client_name, actor: Trusted caller; schedule_id: Approved enabled schedule.
    Returns:
        Numeric job ID.
    Raises:
        ScheduleError: On disabled, unauthorized or obsolete context.
    """
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        schedule = _schedule(cur, client_name, actor, schedule_id)
        if not schedule["enabled"]:
            raise ScheduleError("Enable the reviewed schedule before collecting.")
        for target in _targets(cur, schedule["client_id"], schedule_id):
            validate_target(cur, schedule["client_id"], target, schedule["connector_id"])
        cur.execute("SELECT clock_timestamp() AS now")
        identity = _enqueue(cur, schedule, cur.fetchone()["now"], schedule["approved_by"])
        _audit(
            cur,
            schedule["client_id"],
            actor,
            "Manual collection queued",
            schedule_id,
            {"job_id": identity},
        )
        return identity


def tick(worker):
    """Recover expired jobs and enqueue at most 50 due schedules for an authorized worker.

    Args:
        worker: Host allowlisted execution identity.
    Returns:
        Number of occurrences inserted.
    Raises:
        DatabaseError: On transaction failure.
    """
    if not worker_allowed(worker):
        return 0
    recover_expired(worker)
    count = 0
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT *,NOW() AS now FROM securescope_evidence_schedules "
            "WHERE enabled AND next_run_at<=NOW() ORDER BY next_run_at,id "
            "LIMIT 50 FOR UPDATE SKIP LOCKED"
        )
        for schedule in cur.fetchall():
            if member_role(cur, schedule["client_id"], schedule["approved_by"]) != "Administrator":
                cur.execute(
                    "UPDATE securescope_evidence_schedules SET enabled=FALSE,"
                    "pause_reason='Authorizing membership revoked' WHERE id=%s",
                    (schedule["id"],),
                )
                _audit(
                    cur,
                    schedule["client_id"],
                    worker,
                    "Schedule authorization revoked",
                    schedule["id"],
                )
                continue
            cur.execute(
                "SELECT id FROM securescope_evidence_jobs WHERE schedule_id=%s "
                "AND status IN ('Queued','Running') LIMIT 1",
                (schedule["id"],),
            )
            busy = cur.fetchone()
            missed = max(
                0,
                int((schedule["now"] - schedule["next_run_at"]).total_seconds())
                // schedule["interval_seconds"],
            )
            if not busy:
                count += bool(
                    _enqueue(cur, schedule, schedule["next_run_at"], schedule["approved_by"])
                )
            cur.execute(
                "UPDATE securescope_evidence_schedules SET next_run_at=NOW()+%s*interval '1 second',"
                "missed_occurrences=missed_occurrences+%s WHERE id=%s",
                (schedule["interval_seconds"], missed + bool(busy), schedule["id"]),
            )
            _audit(
                cur,
                schedule["client_id"],
                worker,
                "Schedule tick",
                schedule["id"],
                {"missed_occurrences": missed + bool(busy), "coalesced": bool(busy)},
            )
    return count


def claim(worker):
    """Claim one Wazuh job and a renewable workspace/connector lease atomically.

    Args:
        worker: Allowlisted host worker name.
    Returns:
        Claimed job with attempt ID and fencing token, or None.
    Raises:
        DatabaseError: On failed transaction.
    """
    if not worker_allowed(worker):
        return None
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT j.*,s.connector_id,s.enabled,s.approved_by,c.name AS client_name "
            "FROM securescope_evidence_jobs j JOIN securescope_evidence_schedules s "
            "ON s.client_id=j.client_id AND s.id=j.schedule_id "
            "JOIN securescope_clients c ON c.id=j.client_id "
            "WHERE j.operation=%s AND j.status='Queued' AND j.available_at<=NOW() "
            "AND j.attempt_count<j.max_attempts ORDER BY j.available_at,j.id "
            "LIMIT 20 FOR UPDATE OF j SKIP LOCKED",
            (OPERATION,),
        )
        for row in cur.fetchall():
            if (
                not row["enabled"]
                or member_role(cur, row["client_id"], row["approved_by"]) != "Administrator"
            ):
                cur.execute(
                    "UPDATE securescope_evidence_jobs SET status='Cancelled',completed_at=NOW(),"
                    "last_error='Delegation paused or revoked' WHERE id=%s",
                    (row["id"],),
                )
                continue
            cur.execute(
                "INSERT INTO securescope_evidence_execution_leases(client_id,connector_id) "
                "VALUES (%s,%s) ON CONFLICT DO NOTHING",
                (row["client_id"], row["connector_id"]),
            )
            cur.execute(
                "UPDATE securescope_evidence_execution_leases SET token=token+1,job_id=%s,"
                "worker_name=%s,expires_at=NOW()+%s*interval '1 second' "
                "WHERE client_id=%s AND connector_id=%s AND expires_at<=NOW() RETURNING token",
                (row["id"], worker, LEASE_SECONDS, row["client_id"], row["connector_id"]),
            )
            lease = cur.fetchone()
            if not lease:
                continue
            cur.execute(
                "UPDATE securescope_evidence_jobs SET status='Running',worker_name=%s,"
                "fencing_token=%s,claimed_at=NOW(),heartbeat_at=NOW(),attempt_count=attempt_count+1,"
                "execution_deadline=NOW()+%s*interval '1 second',updated_at=NOW() "
                "WHERE id=%s RETURNING *",
                (worker, lease["token"], DEADLINE_SECONDS, row["id"]),
            )
            job = dict(
                cur.fetchone(), connector_id=row["connector_id"], client_name=row["client_name"]
            )
            cur.execute(
                "INSERT INTO securescope_evidence_job_attempts "
                "(client_id,job_id,attempt_number,fencing_token,worker_name) "
                "VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (job["client_id"], job["id"], job["attempt_count"], lease["token"], worker),
            )
            job["attempt_id"] = cur.fetchone()["id"]
            job["targets"] = _targets(cur, job["client_id"], job["schedule_id"])
            _audit(
                cur,
                job["client_id"],
                worker,
                "Collection claimed",
                job["schedule_id"],
                {"job_id": job["id"], "attempt": job["attempt_count"], "token": lease["token"]},
            )
            return job
    return None


def fence(cursor, job, *, authorize=True):
    """Lock and verify a live execution token in the same transaction as each side effect.

    Args:
        cursor: Write transaction; job: Claimed identity; authorize: Recheck delegation/context.
    Returns:
        Current job/schedule metadata.
    Raises:
        LeaseLost: If superseded, expired, cancelled or disabled; ScheduleError: On changed context.
    """
    if not worker_allowed(job["worker_name"]):
        raise LeaseLost("Worker execution gate is closed.")
    cursor.execute(
        "SELECT j.*,s.connector_id,s.enabled,s.approved_by FROM securescope_evidence_jobs j "
        "JOIN securescope_evidence_schedules s ON s.client_id=j.client_id AND s.id=j.schedule_id "
        "JOIN securescope_evidence_execution_leases l ON l.client_id=j.client_id "
        "AND l.connector_id=s.connector_id AND l.job_id=j.id "
        "WHERE j.client_id=%s AND j.id=%s AND j.status='Running' "
        "AND j.fencing_token=%s AND l.token=%s AND j.worker_name=%s AND l.worker_name=%s "
        "AND l.expires_at>clock_timestamp() AND j.execution_deadline>clock_timestamp() "
        "FOR UPDATE OF j,l",
        (
            job["client_id"],
            job["id"],
            job["fencing_token"],
            job["fencing_token"],
            job["worker_name"],
            job["worker_name"],
        ),
    )
    row = cursor.fetchone()
    if not row:
        raise LeaseLost("Collection lease expired, was cancelled or superseded.")
    if authorize:
        # Profile version creation locks the workspace row before allocating its version.
        # Share that boundary to prevent a new profile appearing mid-publication.
        cursor.execute(
            "SELECT id FROM securescope_clients WHERE id=%s FOR SHARE", (job["client_id"],)
        )
        cursor.execute(
            "SELECT m.role FROM securescope_workspace_memberships m "
            "JOIN securescope_users u ON u.id=m.user_id WHERE m.client_id=%s "
            "AND u.email=%s AND m.active AND u.active FOR SHARE OF m,u",
            (job["client_id"], row["approved_by"]),
        )
        membership = cursor.fetchone()
        if not membership or membership["role"] != "Administrator":
            raise ScheduleError("Authorizing membership is no longer active.")
        from securescope.integrations.wazuh_service import configured_connector_id

        if (
            not row["enabled"]
            or row["connector_id"] != configured_connector_id()
            or member_role(cursor, row["client_id"], row["approved_by"]) != "Administrator"
        ):
            raise ScheduleError("Collection delegation or connector changed.")
    return dict(row)


def renew(job):
    """Renew a current execution lease; return None; raise LeaseLost on invalid identity."""
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        fence(cur, job)
        cur.execute(
            "UPDATE securescope_evidence_execution_leases SET expires_at="
            "LEAST(clock_timestamp()+%s*interval '1 second',%s) "
            "WHERE client_id=%s AND connector_id=%s AND token=%s",
            (
                LEASE_SECONDS,
                job["execution_deadline"],
                job["client_id"],
                job["connector_id"],
                job["fencing_token"],
            ),
        )
        cur.execute(
            "UPDATE securescope_evidence_jobs SET heartbeat_at=clock_timestamp() "
            "WHERE client_id=%s AND id=%s",
            (job["client_id"], job["id"]),
        )


def finish(job, *, error_code="", retryable=False, partial=False, retry_after=0):
    """Complete or reschedule a fenced attempt, preserving previous outputs.

    Args:
        job: Claimed identity; error_code: Safe category; retryable: Transient failure.
        partial: Some targets succeeded; retry_after: Bounded server hint in seconds.
    Returns:
        Resulting job state.
    Raises:
        LeaseLost: On stale execution; DatabaseError: On failed transaction.
    """
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        current = fence(cur, job, authorize=False)
        retry = bool(
            error_code and retryable and current["attempt_count"] < current["max_attempts"]
        )
        state = "Queued" if retry else ("Failed" if error_code else "Succeeded")
        outcome = "partial" if partial else ("failed" if error_code else "succeeded")
        delay = min(
            300,
            max(
                float(retry_after), 30 * 2 ** (current["attempt_count"] - 1) + random.uniform(0, 10)
            ),
        )
        cur.execute(
            "UPDATE securescope_evidence_job_attempts SET completed_at=NOW(),outcome=%s,error_code=%s "
            "WHERE client_id=%s AND job_id=%s AND fencing_token=%s AND outcome='running'",
            (outcome, error_code, job["client_id"], job["id"], job["fencing_token"]),
        )
        cur.execute(
            "UPDATE securescope_evidence_jobs SET status=%s,diagnostic_outcome=%s,last_error=%s,"
            "completed_at=CASE WHEN %s THEN NULL ELSE NOW() END,available_at=NOW()+%s*interval '1 second' "
            "WHERE client_id=%s AND id=%s",
            (state, outcome, error_code, retry, delay, job["client_id"], job["id"]),
        )
        cur.execute(
            "UPDATE securescope_evidence_execution_leases SET expires_at=NOW() "
            "WHERE client_id=%s AND connector_id=%s AND token=%s",
            (job["client_id"], job["connector_id"], job["fencing_token"]),
        )
        if error_code and not retryable:
            cur.execute(
                "UPDATE securescope_evidence_schedules SET enabled=FALSE,pause_reason=%s "
                "WHERE client_id=%s AND id=%s",
                (error_code, job["client_id"], job["schedule_id"]),
            )
        _audit(
            cur,
            job["client_id"],
            job["worker_name"],
            "Collection attempt completed",
            job["schedule_id"],
            {"job_id": job["id"], "outcome": outcome, "retry": retry, "error_code": error_code},
        )
        return state


def recover_expired(worker):
    """Recover at most 50 expired running jobs; old fencing tokens remain invalid.

    Args:
        worker: Authorized worker identity.
    Returns:
        Number of jobs recovered.
    Raises:
        DatabaseError: On failed recovery transaction.
    """
    if not worker_allowed(worker):
        return 0
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT j.* FROM securescope_evidence_jobs j "
            "JOIN securescope_evidence_schedules s ON s.client_id=j.client_id AND s.id=j.schedule_id "
            "JOIN securescope_evidence_execution_leases l ON l.client_id=j.client_id "
            "AND l.connector_id=s.connector_id WHERE j.operation=%s AND j.status='Running' "
            "AND (l.expires_at<=NOW() OR j.execution_deadline<=NOW() OR l.token<>j.fencing_token) "
            "ORDER BY j.id LIMIT 50 FOR UPDATE OF j SKIP LOCKED",
            (OPERATION,),
        )
        rows = cur.fetchall()
        for job in rows:
            state = "Queued" if job["attempt_count"] < job["max_attempts"] else "Failed"
            cur.execute(
                "UPDATE securescope_evidence_job_attempts SET completed_at=NOW(),outcome='abandoned',"
                "error_code='lease_expired' WHERE client_id=%s AND job_id=%s AND outcome='running'",
                (job["client_id"], job["id"]),
            )
            cur.execute(
                "UPDATE securescope_evidence_jobs SET status=%s,last_error='lease_expired',"
                "available_at=NOW(),completed_at=CASE WHEN %s='Failed' THEN NOW() ELSE NULL END "
                "WHERE client_id=%s AND id=%s",
                (state, state, job["client_id"], job["id"]),
            )
            _audit(
                cur,
                job["client_id"],
                worker,
                "Expired collection recovered",
                job["schedule_id"],
                {"job_id": job["id"]},
            )
        return len(rows)


def cancel_job(client_name, actor, job_id):
    """Cancel an owned job; publication is serialized against its row lock.

    Args:
        client_name, actor: Trusted caller; job_id: Exact canonical job ID.
    Returns:
        None.
    Raises:
        ScheduleError: For absent/foreign jobs or insufficient membership.
    """
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT j.* FROM securescope_evidence_jobs j JOIN securescope_clients c ON c.id=j.client_id "
            "WHERE c.name=%s AND j.id=%s AND j.operation=%s FOR UPDATE OF j",
            (client_name, job_id, OPERATION),
        )
        job = cur.fetchone()
        if not job or member_role(cur, job["client_id"], actor) not in {
            "Administrator",
            "Consultant",
        }:
            raise ScheduleError("Authorized workspace collection access is required.")
        if job["status"] not in {"Queued", "Running"}:
            return
        cur.execute(
            "UPDATE securescope_evidence_jobs SET status='Cancelled',completed_at=NOW(),"
            "last_error='cancelled' WHERE id=%s",
            (job_id,),
        )
        cur.execute(
            "UPDATE securescope_evidence_job_attempts SET outcome='cancelled',completed_at=NOW() "
            "WHERE client_id=%s AND job_id=%s AND outcome='running'",
            (job["client_id"], job_id),
        )
        # Retain the lease until expiry: an in-flight HTTP request may still be returning.
        _audit(
            cur,
            job["client_id"],
            actor,
            "Collection cancelled",
            job["schedule_id"],
            {"job_id": job_id},
        )


def list_schedules(client_name, actor):
    """Return authorized operational schedules/jobs without credentials or source bytes.

    Args:
        client_name, actor: Trusted workspace context.
    Returns:
        Schedule dictionaries with recent jobs.
    Raises:
        ScheduleError: For an unauthorized workspace.
    """
    run_pending_migrations()
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id FROM securescope_clients WHERE name=%s", (client_name,))
        client = cur.fetchone()
        if not client or not member_role(cur, client["id"], actor):
            raise ScheduleError("Workspace membership required.")
        cur.execute(
            "SELECT * FROM securescope_evidence_schedules WHERE client_id=%s ORDER BY id DESC LIMIT 100",
            (client["id"],),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for row in rows:
            cur.execute(
                "SELECT id,status,attempt_count,max_attempts,available_at,claimed_at,heartbeat_at,"
                "completed_at,last_error,diagnostic_outcome,assurance_refresh_state,assurance_refresh_attempts FROM securescope_evidence_jobs "
                "WHERE client_id=%s AND schedule_id=%s ORDER BY id DESC LIMIT 20",
                (client["id"], row["id"]),
            )
            row["jobs"] = [dict(j) for j in cur.fetchall()]
            cur.execute(
                "SELECT MAX(completed_at) FILTER (WHERE status='Succeeded') AS last_success,"
                "MAX(claimed_at) AS last_attempt,"
                "GREATEST(0,EXTRACT(EPOCH FROM (NOW()-MIN(available_at) FILTER (WHERE status='Queued')))) AS queue_lag_seconds "
                "FROM securescope_evidence_jobs WHERE client_id=%s AND schedule_id=%s",
                (client["id"], row["id"]),
            )
            row.update(dict(cur.fetchone()))
            cur.execute(
                "SELECT count(*) AS failed_since_success FROM securescope_evidence_jobs "
                "WHERE client_id=%s AND schedule_id=%s AND status='Failed' "
                "AND completed_at>COALESCE(%s::timestamptz,'-infinity'::timestamptz)",
                (client["id"], row["id"], row["last_success"]),
            )
            row["failed_since_success"] = cur.fetchone()["failed_since_success"]
        return rows


def schedule_candidates(client_name, actor):
    """List current approved bound-asset requirements for schedule selection.

    Args:
        client_name, actor: Trusted workspace member identity.
    Returns:
        Validated target dictionaries with descriptive labels; no inferred scope memberships.
    Raises:
        ScheduleError: On missing workspace membership; DatabaseError: On failed reads.
    """
    from securescope.integrations.wazuh_service import configured_connector_id

    connector = configured_connector_id()
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id FROM securescope_clients WHERE name=%s", (client_name,))
        client = cur.fetchone()
        if not client or member_role(cur, client["id"], actor) not in {
            "Administrator",
            "Consultant",
        }:
            raise ScheduleError("Workspace reviewer membership required.")
        cur.execute(
            "SELECT DISTINCT ON (control_id,assessment_scope->'implementation_requirements'->>'scope_id') "
            "id,control_id,profile_version,assessment_scope->'implementation_requirements' AS config "
            "FROM securescope_control_assessment_profiles WHERE client_id=%s AND control_id IN ('A.8.15','A.8.16') "
            "ORDER BY control_id,assessment_scope->'implementation_requirements'->>'scope_id',profile_version DESC",
            (client["id"],),
        )
        profiles = [dict(p) for p in cur.fetchall()]
        cur.execute(
            "SELECT * FROM securescope_wazuh_bindings WHERE client_id=%s AND connector_id=%s AND revoked_at IS NULL",
            (client["id"], connector),
        )
        bindings = {b["asset_id"]: dict(b) for b in cur.fetchall()}
        targets = []
        for profile in profiles:
            config = profile["config"] or {}
            for requirement in config.get("requirements", []):
                for asset in requirement.get("asset_ids", []):
                    binding = bindings.get(asset)
                    if not binding or not all(
                        config.get(k) for k in ("scope_id", "engagement_id", "scope_version_id")
                    ):
                        continue
                    target = dict(
                        asset_id=asset,
                        binding_id=binding["id"],
                        profile_id=profile["id"],
                        control_id=profile["control_id"],
                        requirement_id=requirement["id"],
                        **{k: config[k] for k in ("scope_id", "engagement_id", "scope_version_id")},
                    )
                    try:
                        validated = validate_target(cur, client["id"], target, connector)
                    except ScheduleError:
                        continue
                    target.update(
                        label=f"{profile['control_id']} · scope {config['scope_id']} · v{profile['profile_version']} · "
                        f"{requirement.get('title',requirement['id'])} · {validated['asset_tag']}",
                        health_allowed=bool(requirement.get("allow_collection_health")),
                    )
                    targets.append(target)
        return targets


def queue_manual_context(client_name, actor, context):
    """Route on-demand collection to an explicitly approved schedule without scope inference.

    Args:
        client_name, actor: Existing trusted caller; context: Optional originating requirement.
    Returns:
        Existing collection-result shape with queued job IDs.
    Raises:
        ScheduleError: If no unambiguous approved selection exists.
    """
    context = context or {}
    if context and context.get("client") != client_name:
        raise ScheduleError("Collection context belongs to another workspace.")
    matches = []
    for schedule in list_schedules(client_name, actor):
        if not schedule["enabled"]:
            continue
        with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            targets = _targets(cur, schedule["client_id"], schedule["id"])
        if context:
            if not all(
                all(
                    t.get(k) == context.get(k)
                    for k in ("scope_id", "engagement_id", "control_id", "requirement_id")
                )
                and (not context.get("asset_ids") or t["asset_id"] in context["asset_ids"])
                for t in targets
            ):
                continue
        matches.append(schedule["id"])
    if len(matches) != 1:
        raise ScheduleError(
            "Select an approved schedule using Run now in recurring collection controls."
        )
    job_id = queue_now(client_name, actor, matches[0])
    return dict(outcome="queued", run_id=None, evidence_ids=[], rows=[], job_id=job_id)


def job_history(client_name, actor, job_id):
    """Return safe durable attempts, per-target outcomes and canonical result identities.

    Args:
        client_name, actor: Trusted member context; job_id: Workspace-owned collection.
    Returns:
        Dictionary of job metadata, attempts, target outcomes and result IDs.
    Raises:
        ScheduleError: For an absent or unauthorized job; DatabaseError: On failed reads.
    """
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT j.* FROM securescope_evidence_jobs j JOIN securescope_clients c ON c.id=j.client_id "
            "WHERE c.name=%s AND j.id=%s AND j.operation=%s",
            (client_name, job_id, OPERATION),
        )
        job = cur.fetchone()
        if not job or not member_role(cur, job["client_id"], actor):
            raise ScheduleError("Workspace membership and an owned collection are required.")
        cur.execute(
            "SELECT * FROM securescope_evidence_job_attempts WHERE client_id=%s AND job_id=%s ORDER BY attempt_number",
            (job["client_id"], job_id),
        )
        attempts = [dict(a) for a in cur.fetchall()]
        cur.execute(
            "SELECT t.*,a.attempt_number FROM securescope_evidence_target_attempts t "
            "JOIN securescope_evidence_job_attempts a ON a.client_id=t.client_id AND a.id=t.attempt_id "
            "WHERE a.client_id=%s AND a.job_id=%s ORDER BY a.attempt_number,t.target_id",
            (job["client_id"], job_id),
        )
        targets = [dict(t) for t in cur.fetchall()]
        cur.execute(
            "SELECT target_id,evidence_id FROM securescope_evidence_job_results WHERE client_id=%s AND job_id=%s",
            (job["client_id"], job_id),
        )
        return dict(
            job=dict(job),
            attempts=attempts,
            targets=targets,
            results=[dict(r) for r in cur.fetchall()],
        )
