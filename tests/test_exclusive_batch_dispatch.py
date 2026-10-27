from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"


def test_queue_starter_has_no_global_historical_fallback():
    source = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(
        encoding="utf-8"
    )
    block = source.split("def _run_openvas_queue_start_cycle_unlocked()", 1)[1]
    block = block.split("def process_openvas_queue_start_cycle()", 1)[0]
    assert "get_latest_dispatchable_openvas_batch_id()" in block
    assert "_start_queued_openvas_jobs()" not in block
    assert "count_pending_openvas_dispatch_jobs" in block


def test_batch_dispatch_migration_and_exclusive_activation_exist():
    source = (ROOT / "persistence" / "openvas_persistence.py").read_text(encoding="utf-8")
    assert "dispatch_enabled BOOLEAN NOT NULL DEFAULT FALSE" in source
    assert "def activate_openvas_batch_dispatch(" in source
    assert "WHERE dispatch_enabled = TRUE" in source
    assert "def get_latest_dispatchable_openvas_batch_id()" in source


def test_cleanup_is_explicit_not_automatic():
    worker = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(
        encoding="utf-8"
    )
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "def stop_other_securescope_tasks(" in worker
    assert "Stop older SecureScope tasks outside this batch" in app
    queue_block = worker.split("def _run_openvas_queue_start_cycle_unlocked()", 1)[1]
    queue_block = queue_block.split("def process_openvas_queue_start_cycle()", 1)[0]
    assert "stop_other_securescope_tasks(" not in queue_block
