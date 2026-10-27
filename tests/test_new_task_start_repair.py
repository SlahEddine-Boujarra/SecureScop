from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
WORKER = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(encoding="utf-8")
PERSISTENCE = (ROOT / "persistence" / "openvas_persistence.py").read_text(encoding="utf-8")


def test_queue_timestamp_is_not_start_evidence() -> None:
    start = WORKER.index("raw_task_status_hint = str(")
    end = WORKER.index("already_started = {", start)
    block = WORKER[start:end]
    assert 'job.get("submitted_at")' not in block
    assert "known_task_status = raw_task_status_hint or local_provider_status" in block
    assert '"new", "created", "not started", "checking task"' in block


def test_claim_keeps_new_provider_state_for_precreated_task() -> None:
    assert "THEN COALESCE(NULLIF(provider_status, ''), 'New')" in PERSISTENCE
