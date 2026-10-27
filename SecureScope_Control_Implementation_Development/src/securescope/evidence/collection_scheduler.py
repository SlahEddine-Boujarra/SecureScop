"""Scheduling and renewable lease support inside the existing Evidence Worker."""

import logging
from contextlib import contextmanager
from threading import Event, Thread

from psycopg2.extras import RealDictCursor

from securescope.integrations.wazuh_collection_health import CollectionFailure
from securescope.persistence import evidence_schedule_repository as schedules
from securescope.persistence.db_service import DatabaseError

LOGGER = logging.getLogger(__name__)


def tick(worker):
    """Run one bounded scheduling/recovery pass; return queued count; raise DatabaseError on failure."""
    return schedules.tick(worker)


@contextmanager
def renewing_lease(job):
    """Renew a claimed lease during bounded HTTP calls; yield and stop renewal on exit.

    Args:
        job: Claimed PostgreSQL job identity.
    Yields:
        None. Every write independently checks the fence even if renewal fails.
    Raises:
        Exceptions from the caller's collection body are propagated.
    """
    stop = Event()

    def renew():
        """Renew until cancellation, database failure or context-manager exit."""
        while not stop.wait(15):
            try:
                schedules.renew(job)
            except (schedules.ScheduleError, DatabaseError):
                LOGGER.warning("Collection lease renewal stopped for job %s", job["id"])
                return

    thread = Thread(target=renew, name="evidence-lease-renewal", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2)


def admit_request(job):
    """Rate-limit a connector to one admitted request/second across workspaces.

    Args:
        job: Live execution identity.
    Returns:
        None after a maximum five-second admission wait and renewed fence check.
    Raises:
        CollectionFailure: On a full rate budget; LeaseLost: On cancelled/stale ownership.
    """
    with schedules.connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        schedules.fence(cur, job)
        cur.execute(
            "INSERT INTO securescope_evidence_connector_budget(connector_id) VALUES (%s) "
            "ON CONFLICT DO NOTHING",
            (job["connector_id"],),
        )
        cur.execute(
            "SELECT EXTRACT(EPOCH FROM (next_request_at-clock_timestamp())) AS delay "
            "FROM securescope_evidence_connector_budget WHERE connector_id=%s FOR UPDATE",
            (job["connector_id"],),
        )
        delay = max(0, float(cur.fetchone()["delay"]))
        if delay > 5:
            raise CollectionFailure("connector_rate_limit", retryable=True, retry_after=5)
        cur.execute(
            "UPDATE securescope_evidence_connector_budget SET next_request_at="
            "GREATEST(next_request_at,clock_timestamp())+interval '1 second' WHERE connector_id=%s",
            (job["connector_id"],),
        )
    Event().wait(delay)
    schedules.renew(job)
