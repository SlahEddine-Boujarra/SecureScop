"""Mandatory native PostgreSQL multi-process gates. Embedded engines are explicitly rejected."""

import multiprocessing
import os
import signal
from threading import Event

import pytest

from securescope.persistence import evidence_schedule_repository as schedules
from securescope.persistence.evidence_repository import _append_audit_event
from tests.test_m1_evidence_postgres import database  # noqa: F401
from tests.test_m2_scheduling_postgres import scheduled  # noqa: F401

pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Native PostgreSQL not configured"
)


@pytest.fixture
def native(scheduled):
    """Refuse to report concurrency results from PGlite/WASM or without real fork processes."""
    database, identity, target = scheduled
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT version()")
        version = cur.fetchone()[0]
    if "pglite" in version.lower() or "wasm" in version.lower():
        pytest.skip("Native PostgreSQL required; embedded PostgreSQL cannot verify concurrency")
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("Linux fork process harness required")
    return database, identity, target


def test_two_processes_tick_and_claim_one_occurrence(native):
    """Two actual worker processes compete; one occurrence and one lease must win."""
    database, _, _ = native
    context = multiprocessing.get_context("fork")
    start, output = context.Event(), context.Queue()

    def compete(name):
        """Wait for simultaneous start, then use independent database connections."""
        start.wait(10)
        queued = schedules.tick(name)
        job = schedules.claim(name)
        output.put((queued, job["id"] if job else None))

    processes = [
        context.Process(target=compete, args=(name,)) for name in ("test-worker", "other-worker")
    ]
    for process in processes:
        process.start()
    start.set()
    results = [output.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert sum(r[0] for r in results) == 1
    assert sum(r[1] is not None for r in results) == 1
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM securescope_evidence_job_attempts")
        assert cur.fetchone()[0] == 1


def test_killed_process_recovers_and_cannot_renew_old_token(native):
    """Terminate a claimant process; another process's recovery fences its saved identity."""
    database, _, _ = native
    schedules.tick("test-worker")
    context = multiprocessing.get_context("fork")
    output = context.Queue()

    def claimant():
        """Claim and simulate an in-flight process awaiting external I/O."""
        output.put(schedules.claim("test-worker"))
        Event().wait(30)

    process = context.Process(target=claimant)
    process.start()
    old = output.get(timeout=20)
    os.kill(process.pid, signal.SIGKILL)
    process.join(10)
    assert process.exitcode == -signal.SIGKILL
    # Advance persisted expiry instead of waiting 90 seconds in the test suite.
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE securescope_evidence_execution_leases SET expires_at=NOW()-interval '1 second'"
        )
    assert schedules.recover_expired("other-worker") == 1
    current = schedules.claim("other-worker")
    assert current["fencing_token"] > old["fencing_token"]
    with pytest.raises(schedules.LeaseLost):
        schedules.renew(old)


def test_concurrent_first_audit_writes_remain_one_chain(native):
    """An empty tenant audit chain has exactly one root under concurrent appends."""
    database, _, _ = native
    context = multiprocessing.get_context("fork")
    start = context.Event()

    def append(identity):
        """Append to the untouched Beta audit chain in an independent transaction."""
        start.wait(10)
        with database() as conn, conn.cursor() as cur:
            _append_audit_event(
                cur,
                202,
                event_type="Concurrency test",
                entity_type="Test",
                entity_id=str(identity),
                actor="fixture",
                summary="Synthetic append",
            )

    processes = [context.Process(target=append, args=(i,)) for i in range(4)]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    with database() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT previous_event_hash,event_hash FROM securescope_evidence_audit_events WHERE client_id=202 ORDER BY id"
        )
        rows = cur.fetchall()
    assert len(rows) == 4 and not rows[0][0]
    assert all(rows[i][0] == rows[i - 1][1] for i in range(1, 4))
