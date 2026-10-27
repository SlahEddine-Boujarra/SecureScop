"""Typed Wazuh API dispatch in the existing Evidence Worker; excludes clock collection."""

import logging
import os
import re
from datetime import datetime, timezone

import requests
from psycopg2.extras import RealDictCursor

from securescope.evidence.collection_scheduler import admit_request, renewing_lease
from securescope.evidence.storage import EvidenceStorageError
from securescope.evidence.wazuh_bridge import normalized_source
from securescope.integrations.wazuh_collection_health import (
    CollectionFailure,
    acquire_health,
    policy_hash,
)
from securescope.integrations.wazuh_monitoring import evaluate_monitoring
from securescope.integrations.wazuh_service import WazuhClient, WazuhError, match_agents_to_assets
from securescope.persistence import evidence_schedule_repository as schedules
from securescope.persistence import wazuh_evidence_repository as sources
from securescope.persistence.db_service import DatabaseError
from securescope.persistence.evidence_repository import (
    EvidenceRepositoryError,
    create_evidence_record,
)

LOGGER = logging.getLogger(__name__)


def classify_error(error):
    """Return a safe Wazuh failure category; only known transport/server failures are retryable."""
    cause = error.__cause__
    if isinstance(cause, requests.exceptions.SSLError):
        return CollectionFailure("tls_verification_failed")
    if isinstance(cause, (requests.Timeout, requests.ConnectionError)):
        return CollectionFailure("wazuh_transport", retryable=True)
    status = re.search(r"\b(401|403|429|500|502|503|504)\b", str(error))
    if status:
        code = int(status[1])
        return CollectionFailure(
            f"wazuh_http_{code}",
            retryable=code in {429, 500, 502, 503, 504},
            retry_after=getattr(error, "retry_after", 0),
        )
    return CollectionFailure("wazuh_source_unavailable")


def collect_target(job, target, client):
    """Collect an exact bound agent and permitted proof streams; return facts and failure.

    Args:
        job: Lease; target: Approved frozen target; client: Existing authenticated API client.
    Returns:
        (allowlisted observation, optional CollectionFailure).
    Raises:
        ScheduleError: On invalid context. DatabaseError: On unavailable authorization.
    """
    with sources.connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        target, binding = sources.target_context(cur, job, target["id"])
    if (
        not client.verify_tls
        or not client.api_url.startswith("https://")
        or not os.getenv("WAZUH_INDEXER_URL", "").startswith("https://")
        or os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").lower() != "true"
    ):
        raise CollectionFailure("tls_verification_required")
    asset = dict(id=binding["asset_id"], ip=binding["ip"], asset_tag=binding["asset_tag"])
    failure, agents = None, []
    try:
        agents = client.list_agents(agent_ids=[binding["agent_id"]])
    except WazuhError as exc:
        failure = classify_error(exc)
    row = match_agents_to_assets([asset], agents, bindings=[binding])[0]
    row.update(
        schema_version=2,
        m2_collection=True,
        ip=binding["ip"],
        collected_at=datetime.now(timezone.utc),
        api_verified=not failure and client.verify_tls is True,
        source_health="unavailable" if failure else "healthy",
        telemetry={},
        health_policy_sha256=policy_hash(target["health_policy"]),
        health_max_age_seconds=target["health_policy"].get("max_age_seconds"),
        streams=dict(
            agents="failed" if failure else "succeeded",
            alerts="not_requested",
            health="not_requested",
        ),
    )
    if failure:
        row["source_error"] = failure.code
        return row, failure
    if client.verify_tls is not True:
        return dict(row, source_health="unavailable"), CollectionFailure(
            "tls_verification_required"
        )
    alert_failure = None
    try:
        row["telemetry"] = (
            client.search_last_alert_for_agent(
                agent_id=binding["agent_id"], manager_name=binding["manager_name"]
            )
            or {}
        )
        row["streams"]["alerts"] = "succeeded"
    except WazuhError as exc:
        alert_failure = classify_error(exc)
        row["streams"]["alerts"] = alert_failure.code
    # Only explicitly approved A.8.16 targets may use an independently working alternative.
    if evaluate_monitoring(row)["monitoring_state"] != "verified" and target["accept_health"]:
        try:
            health = acquire_health(client, binding, target["health_policy"])
            row["streams"]["health"] = "succeeded"
            if health:
                row["telemetry"] = health
        except CollectionFailure as exc:
            row["streams"]["health"] = exc.code
            failure = exc
    if evaluate_monitoring(row)["monitoring_state"] == "verified":
        return row, None
    failure = failure or alert_failure
    if failure:
        row.update(source_health="unavailable", source_error=failure.code)
    return row, failure


def publish(job, target, row):
    """Publish one exact protected source; return evidence ID or None for ineligible facts."""
    kind = "logging" if target["control_id"] == "A.8.15" else "monitoring"
    normalized = normalized_source(row, kind)
    if not normalized:
        return None
    payload, observed = normalized
    check = payload["metadata"]["automated_checks"][0]
    return create_evidence_record(
        job["client_name"],
        tool_id="wazuh",
        collection_method="Authenticated API",
        evidence_type="Automated technical evidence",
        title=check["display_name"],
        summary=check["explanation"],
        scope_description="Pinned approved schedule target",
        source_asset_or_system=row["ip"],
        owner=job["requested_by"],
        submitted_by="system:wazuh-connector",
        collected_at=observed,
        expires_at=evaluate_monitoring(row)["verified_until"],
        confidence="Medium",
        normalized=payload,
        suggested_controls=check["mapped_controls"],
        system_source=dict(
            provider="wazuh",
            kind=kind,
            record_id=row["id"],
            requested_by=job["requested_by"],
            scheduled_job=job,
            target_id=target["id"],
        ),
    )


def process_scheduled_job(job):
    """Resume completed acquisitions, retry failed targets and finalize this fenced attempt.

    Args:
        job: Claimed typed job with frozen targets, attempt identity and lease token.
    Returns:
        Succeeded/Queued/Failed, or abandoned if ownership was lost.
    Raises:
        DatabaseError: If completion cannot be recorded; lease recovery handles process crashes.
    """
    failures, successes = [], 0
    try:
        with renewing_lease(job):
            client = WazuhClient()
            client.timeout = min(client.timeout, 30)
            client.before_request = lambda: admit_request(job)
            for target in job["targets"]:
                acquired = False
                observation_id = None
                try:
                    schedules.renew(job)
                    row = sources.existing_source(job, target)
                    if row is None:
                        row, failure = collect_target(job, target, client)
                        acquired = failure is None
                        observation_id = sources.save_source(
                            job, target, row, error_code=failure.code if failure else ""
                        )
                        if failure:
                            raise failure
                        row = sources.existing_source(job, target)
                    acquired = True
                    observation_id = row["id"]
                    sources.status(
                        job,
                        target["id"],
                        acquisition="succeeded",
                        ingestion="pending",
                        observation_id=observation_id,
                    )
                    evidence_id = publish(job, target, row)
                    sources.status(
                        job,
                        target["id"],
                        acquisition="succeeded",
                        ingestion="published" if evidence_id else "not_eligible",
                        observation_id=observation_id,
                    )
                    successes += 1
                except CollectionFailure as exc:
                    failures.append(exc)
                    sources.status(
                        job,
                        target["id"],
                        acquisition="failed",
                        ingestion="not_started",
                        error_code=exc.code,
                        observation_id=observation_id,
                    )
                except EvidenceStorageError:
                    failure = CollectionFailure("artifact_protection_failed", retryable=True)
                    failures.append(failure)
                    sources.status(
                        job,
                        target["id"],
                        acquisition="succeeded" if acquired else "failed",
                        ingestion="failed",
                        error_code=failure.code,
                        observation_id=observation_id,
                    )
                except schedules.LeaseLost:
                    raise
                except EvidenceRepositoryError:
                    failure = CollectionFailure("authorization_or_context_changed")
                    failures.append(failure)
                    sources.status(
                        job,
                        target["id"],
                        acquisition="succeeded" if acquired else "failed",
                        ingestion="blocked",
                        error_code=failure.code,
                        observation_id=observation_id,
                    )
                    break
            fatal = next((f for f in failures if not f.retryable), None)
            failure = fatal or (failures[0] if failures else None)
            state = schedules.finish(
                job,
                error_code=failure.code if failure else "",
                retryable=bool(failure and failure.retryable),
                partial=bool(failures and successes),
                retry_after=max((f.retry_after for f in failures), default=0),
            )
        refresh_targets(job)
        return state
    except schedules.LeaseLost:
        LOGGER.warning("Stale/cancelled Wazuh execution stopped: job %s", job["id"])
        return "abandoned"
    except WazuhError as exc:
        failure = classify_error(exc)
        return schedules.finish(job, error_code=failure.code, retryable=failure.retryable)


def refresh_targets(job):
    """Append bounded automated assurance snapshots; never mutate human assessment decisions."""
    from securescope.integrations.credential_store import CredentialStoreError
    from securescope.persistence.assurance_workspace_repository import record_evaluation
    from securescope.persistence.foundation_repository import FoundationError

    with sources.connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET assurance_refresh_state='running',"
            "assurance_refresh_attempts=assurance_refresh_attempts+1,"
            "assurance_refresh_available_at=NOW()+interval '5 minutes' "
            "WHERE client_id=%s AND id=%s AND assurance_refresh_attempts<3 "
            "AND assurance_refresh_available_at<=NOW() RETURNING assurance_refresh_attempts",
            (job["client_id"], job["id"]),
        )
        claimed = cur.fetchone()
        if not claimed:
            return False
        refresh_attempt = claimed["assurance_refresh_attempts"]
    contexts = {(t["control_id"], t["engagement_id"], t["scope_id"]) for t in job["targets"]}
    refreshed = True
    for control, engagement, scope in sorted(contexts):
        try:
            record_evaluation(job["client_name"], control, job["requested_by"], engagement, scope)
        except (
            FoundationError,
            EvidenceRepositoryError,
            CredentialStoreError,
            DatabaseError,
            ValueError,
        ):
            refreshed = False
            LOGGER.warning(
                "Automated assurance refresh unavailable for job %s scope %s", job["id"], scope
            )

    with sources.connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE securescope_evidence_jobs SET assurance_refresh_state=%s "
            "WHERE client_id=%s AND id=%s AND assurance_refresh_attempts=%s",
            ("succeeded" if refreshed else "failed", job["client_id"], job["id"], refresh_attempt),
        )
        schedules._audit(
            cur,
            job["client_id"],
            job["worker_name"],
            "Automated assurance refresh",
            job["schedule_id"],
            dict(job_id=job["id"], succeeded=refreshed),
        )
    return refreshed


def refresh_pending(worker):
    """Retry at most ten failed snapshot refreshes, capped at three passes per job.

    Args:
        worker: Allowlisted development worker identity.
    Returns:
        Number of successful refreshes. Derived read-time coverage remains independent.
    Raises:
        DatabaseError: If the durable retry list or outcome cannot be persisted.
    """
    if not schedules.worker_allowed(worker):
        return 0
    with sources.connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT j.*,c.name AS client_name FROM securescope_evidence_jobs j "
            "JOIN securescope_clients c ON c.id=j.client_id WHERE j.operation=%s "
            "AND j.status IN ('Succeeded','Failed') AND j.assurance_refresh_state<>'succeeded' "
            "AND j.assurance_refresh_attempts<3 AND j.assurance_refresh_available_at<=NOW() ORDER BY j.id LIMIT 10",
            (schedules.OPERATION,),
        )
        jobs = [dict(j) for j in cur.fetchall()]
        for job in jobs:
            job["targets"] = schedules._targets(cur, job["client_id"], job["schedule_id"])
    return sum(refresh_targets(job) for job in jobs)
