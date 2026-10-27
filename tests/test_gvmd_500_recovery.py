from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
WORKER = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(encoding="utf-8")


def test_precreated_new_task_skips_exact_lookup_before_first_start() -> None:
    assert "known_task_status = raw_task_status_hint or local_provider_status" in WORKER
    assert '"new", "created", "not started", "checking task"' in WORKER
    assert "and not has_start_evidence" in WORKER


def test_ambiguous_task_lookup_uses_documented_get_tasks_command() -> None:
    assert "def _read_task_snapshot_resilient" in WORKER
    assert "nodes = _load_live_task_nodes(gmp, {normalized})" in WORKER
    assert 'return task, "get_tasks snapshot"' in WORKER
    assert "_get_task_via_official_get_tasks_command" in WORKER
    assert '"get_tasks task_id command"' in WORKER


def test_gvmd_500_is_transient() -> None:
    assert "def _is_transient_gvmd_internal_error" in WORKER
    assert "def _defer_gvmd_start_request" in WORKER
    assert "def _defer_gvmd_task_lookup" in WORKER
