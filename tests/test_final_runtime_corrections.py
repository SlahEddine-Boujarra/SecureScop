"""Runtime regressions for retained multi-step values and scoped profile saves."""

from streamlit.testing.v1 import AppTest

from securescope.ui.grc_workspace.scope_editor import _prefix


def test_scope_editor_retains_every_step_and_supports_back_navigation():
    app = AppTest.from_string(
        """
import streamlit as st
from securescope.ui.grc_workspace.scope_editor import start_scope_editor, render_scope_editor
if 'initialized' not in st.session_state:
    start_scope_editor('Client', 2, dict(id=9, scope_code='S-1',
                                      name='Scope', scope_statement='Statement'))
    st.session_state.initialized = True
render_scope_editor('Client', 2, 'reviewer', 'selected_scope')
"""
    ).run()
    for step in range(5):
        assert not app.exception
        for field in app.text_area:
            field.set_value(f"Content for step {step}: {field.label}")
        next(b for b in app.button if b.label == "Save & continue").click().run()
    assert not app.exception
    prefix = _prefix("Client", 2)
    assert app.session_state[prefix + "scope_statement"].startswith("Content for step 0")
    assert app.session_state[prefix + "boundaries"].startswith("Content for step 3")
    for step in range(5):
        next(b for b in app.button if b.label.startswith("← Back to")).click().run()
        assert not app.exception
    assert app.session_state[prefix + "scope_name"] == "Scope"
    assert app.session_state[prefix + "source_scope_id"] == 9


def test_scope_editor_context_keys_do_not_collide():
    assert _prefix("Acme-Co", 2) != _prefix("Acme Co", 2)
    assert _prefix("Client", 2) != _prefix("client", 2)
    assert _prefix("Client", 2) != _prefix("Client", 3)


def test_control_reference_cannot_close_a_remediation_task(monkeypatch):
    from unittest.mock import MagicMock
    import pytest
    from securescope.persistence import exposure_repository as repository

    connect = MagicMock()
    monkeypatch.setattr(repository, "connect", connect)
    with pytest.raises(repository.ExposureRepositoryError, match="control ID is not evidence"):
        repository.transition_remediation_work_item(
            "Client",
            "task",
            7,
            "Completed",
            actor="reviewer",
            reason="Verified",
            evidence_reference="A.8.15",
        )
    connect.assert_not_called()


def test_duplicate_finding_plan_reuses_canonical_id_before_inserting(monkeypatch):
    from datetime import date, timedelta
    from unittest.mock import MagicMock
    from securescope.persistence import exposure_repository as repository
    from securescope.core.remediation_domain import RemediationPlanInput

    cursor = MagicMock()
    cursor.fetchone.side_effect = [(2,), (41,)]
    connect = MagicMock()
    connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(repository, "connect", connect)
    monkeypatch.setattr(repository, "_client_id", lambda *args: 1)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    due = date.today() + timedelta(days=30)
    plan = RemediationPlanInput(
        title="Fix finding",
        description="Apply patch",
        priority="High",
        treatment_decision="Remediate",
        remediation_owner="Owner",
        technical_owner="Engineer",
        business_owner="Manager",
        risk_owner="Risk owner",
        due_date=due,
        sla_days=30,
        success_criteria="Rescan is clear",
        validation_method="Rescan",
    )
    task = dict(
        title="Patch",
        owner="Engineer",
        priority="High",
        due_date=due,
        sla_days=30,
        success_criteria="Fixed",
        verification_method="Rescan",
        milestone_title="Installed",
        milestone_owner="Engineer",
        milestone_due_date=due,
        milestone_success_criteria="Installed",
    )
    assert (
        repository.create_remediation_plan(
            "Client", plan, [8, 7, 8], actor="reviewer", initial_task=task
        )
        == 41
    )
    sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
    assert "pg_advisory_xact_lock" in sql
    assert "INSERT" not in sql
    assert cursor.execute.call_args.args[1] == (1, [7, 8])
