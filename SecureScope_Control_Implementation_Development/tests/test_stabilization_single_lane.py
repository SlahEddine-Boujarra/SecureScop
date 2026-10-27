from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
WORKER = (ROOT / "scanners" / "openvas" / "openvas_worker_service.py").read_text(encoding="utf-8")
EMBEDDED = (ROOT / "scanners" / "openvas" / "openvas_embedded_worker.py").read_text(
    encoding="utf-8"
)
PERSISTENCE = (ROOT / "persistence" / "openvas_persistence.py").read_text(encoding="utf-8")
DOCTOR = (ROOT / "scanners" / "openvas" / "openvas_live_doctor.py").read_text(encoding="utf-8")


def test_one_process_wide_gmp_lane() -> None:
    assert "_GMP_IO_LOCK = threading.RLock()" in WORKER
    assert "with _GMP_IO_LOCK:" in WORKER


def test_official_exact_task_command_replaces_get_task_fallback() -> None:
    assert "def _get_task_via_official_get_tasks_command" in WORKER
    assert '<get_tasks task_id="{normalized}" details="0"/>' in WORKER
    assert '"get_tasks task_id command"' in WORKER


def test_new_task_start_uses_local_provider_hint() -> None:
    assert "known_task_status = raw_task_status_hint or local_provider_status" in WORKER
    assert '"new", "created", "not started", "checking task"' in WORKER


def test_start_commands_are_not_threadpooled() -> None:
    start = WORKER.index("def _start_prepared_openvas_tasks_for_batch_unlocked")
    end = WORKER.index("def start_openvas_batch_parallel", start)
    block = WORKER[start:end]
    assert "ThreadPoolExecutor" not in block
    assert '"submission_mode": "serialized GMP commands"' in block
    assert "for raw_job in selected:" in block


def test_task_claim_preserves_new_provider_status() -> None:
    assert "THEN COALESCE(NULLIF(provider_status, ''), 'New')" in PERSISTENCE


def test_embedded_worker_has_one_real_thread() -> None:
    assert "Single-lane embedded OpenVAS worker" in EMBEDDED
    assert "self.starter_thread = self.thread" in EMBEDDED
    assert "self.deep_thread = self.thread" in EMBEDDED
    assert "self.priority_thread = self.thread" in EMBEDDED


def test_doctor_never_creates_targets_or_tasks() -> None:
    assert "--repair-new" in DOCTOR
    assert "gmp.start_task(task_id)" in DOCTOR
    assert "create_target" not in DOCTOR
    assert "create_task" not in DOCTOR
