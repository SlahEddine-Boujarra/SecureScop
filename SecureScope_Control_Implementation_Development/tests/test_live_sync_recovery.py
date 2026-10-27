from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
EMBEDDED = (ROOT / "scanners" / "openvas" / "openvas_embedded_worker.py").read_text(
    encoding="utf-8"
)
WORKER = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(encoding="utf-8")


def test_visible_batch_gets_continuous_watch_in_single_lane() -> None:
    assert "def watch_batch" in EMBEDDED
    assert "watched_batch = self._active_watched_batch()" in EMBEDDED
    assert "process_openvas_fast_status_cycle(" in EMBEDDED
    assert "batch_id=int(watched_batch)" in EMBEDDED


def test_bulk_snapshot_then_documented_exact_fallback() -> None:
    assert "def _load_live_task_nodes" in WORKER
    assert "_get_task_via_official_get_tasks_command" in WORKER
