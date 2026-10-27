from pathlib import Path


def test_streamlit_launch_does_not_call_greenbone_synchronously() -> None:
    source = Path("src/securescope/app.py").read_text(encoding="utf-8")
    start = source.index('if st.session_state.pop(\n            "openvas_parallel_pending_launch"')
    end = source.index("        action_col1, action_col2, action_col3", start)
    block = source[start:end]

    assert "activate_openvas_batch_dispatch(" in block
    assert "OPENVAS_WORKER_BOOTSTRAP.wake(batch_id=batch_id)" in block
    assert "prepare_and_start_openvas_batch_parallel(" not in block
    assert "start_openvas_batch_parallel(" not in block
    assert "trigger_openvas_queue_start_cycle(" not in block
