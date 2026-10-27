"""Unit tests for truthful cross-provider metric aggregation."""

from securescope.ui.dual_engine_ui import _summarize_nuclei_jobs, _summarize_openvas_jobs


def test_openvas_counts_each_job_once() -> None:
    jobs = [
        {"status": "Queued"},
        {"status": "Running"},
        {"status": "Completed"},
        {"status": "Failed"},
    ]
    assert _summarize_openvas_jobs(jobs) == {
        "queued": 1,
        "active": 1,
        "completed": 1,
        "attention": 1,
    }


def test_nuclei_truthful_counts() -> None:
    jobs = [
        {"ui_status": "Queued", "is_current_attempt": True},
        {"ui_status": "Running", "is_current_attempt": True},
        {"ui_status": "Completed", "is_current_attempt": True},
        {"ui_status": "Interrupted", "is_current_attempt": True},
        {"ui_status": "Completed", "is_current_attempt": False},
    ]
    assert _summarize_nuclei_jobs(jobs) == {
        "queued": 1,
        "active": 1,
        "completed": 1,
        "attention": 1,
    }
