"""Native-only multiprocess Nuclei attribution publication gate."""

import multiprocessing
import os

import pytest

from tests.test_m1_evidence_postgres import database, ingest  # noqa: F401
from tests.test_m3_postgres import profile, queued_job

pytestmark = pytest.mark.skipif(
    not os.getenv("SECURESCOPE_TEST_DATABASE_URL"), reason="Native PostgreSQL not configured"
)


def test_concurrent_canonical_ingestion_has_one_source_and_one_attribution(database):
    """Two independent processes publish the same attempt without duplicate records or links."""
    with database() as conn, conn.cursor() as cur:
        cur.execute("SELECT version()")
        version = cur.fetchone()[0].lower()
    if "pglite" in version or "wasm" in version:
        pytest.skip("Native PostgreSQL required; embedded execution cannot verify concurrency")
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("Linux fork process harness required")
    profile(database)
    job = queued_job(database)["job_uuid"]
    context = multiprocessing.get_context("fork")
    start, output = context.Event(), context.Queue()

    def publish():
        """Publish one identical completed attempt using an independent connection."""
        start.wait(10)
        output.put(ingest(job))

    processes = [context.Process(target=publish) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        assert results[0] == results[1]
        with database() as conn, conn.cursor() as cur:
            for table in (
                "securescope_nuclei_requirement_sources",
                "securescope_requirement_check_attributions",
            ):
                cur.execute(f"SELECT count(*) FROM {table}")
                assert cur.fetchone()[0] == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
