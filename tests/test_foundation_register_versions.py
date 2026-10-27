"""Authorization, stale review and UI regression coverage for Foundation."""

from contextlib import contextmanager
from unittest.mock import Mock, patch

import pytest
from streamlit.testing.v1 import AppTest

from securescope.grc.formal_registers import next_status, validate_records
from securescope.persistence import foundation_repository as repo


@pytest.mark.parametrize("role", ["", "Auditor", "Consultant", "Client contributor"])
def test_only_admin_approves(role):
    with pytest.raises(ValueError):
        next_status("In review", "Approved", role, "Reviewed")


@pytest.mark.parametrize("previous", ["Not started", "Suggested", "Draft", "Approved"])
def test_approval_requires_review(previous):
    with pytest.raises(ValueError):
        next_status(previous, "Approved", "Administrator", "Reviewed")


@pytest.mark.parametrize("rating", [True, 1.0, "3", 0, 6])
def test_ratings_require_bounded_integers(rating):
    with pytest.raises(ValueError):
        validate_records(
            "risks",
            [
                dict(
                    risk_ref=1,
                    threat="Loss",
                    risk_owner="Owner",
                    pre_likelihood=rating,
                    pre_impact=3,
                    treatment_option="Modify",
                )
            ],
        )


def test_bad_host_code_never_opens_database(monkeypatch):
    monkeypatch.setenv("SECURESCOPE_LOCAL_SETUP_CODE", "a" * 40)
    with patch.object(repo, "workspace_cursor") as database:
        with pytest.raises(repo.FoundationError):
            repo.local_administrator("Client", "a@example.com", "Admin", "wrong🔒")
        database.assert_not_called()


def install_cursor(monkeypatch, responses, rows=()):
    cursor = Mock()
    cursor.fetchone.side_effect = responses
    cursor.fetchall.return_value = rows

    @contextmanager
    def transaction(_client):
        yield cursor, 7

    monkeypatch.setattr(repo, "workspace_cursor", transaction)
    return cursor


def test_bootstrap_cannot_replace_existing_admin(monkeypatch):
    monkeypatch.setenv("SECURESCOPE_LOCAL_SETUP_CODE", "a" * 40)
    install_cursor(monkeypatch, [None, {"exists": 1}])
    with patch.object(repo, "_write_member") as write:
        with pytest.raises(repo.FoundationError, match="already complete"):
            repo.local_administrator("Client", "a@example.com", "Admin", "a" * 40)
        write.assert_not_called()


def test_first_admin_records_bootstrap(monkeypatch):
    monkeypatch.setenv("SECURESCOPE_LOCAL_SETUP_CODE", "a" * 40)
    cursor = install_cursor(monkeypatch, [None, None, None])
    with patch.object(repo, "_write_member") as write:
        assert (
            repo.local_administrator("Client", "A@example.com", "Admin", "a" * 40)
            == "a@example.com"
        )
        assert write.call_args.args[4] == "Administrator"
        assert "workspace_bootstraps" in cursor.execute.call_args.args[0]


def test_last_admin_cannot_be_demoted(monkeypatch):
    install_cursor(
        monkeypatch, [{"role": "Administrator"}, {"role": "Administrator"}, {"count": 1}]
    )
    with pytest.raises(repo.FoundationError, match="at least one"):
        repo.save_member(
            "Client", actor="a@example.com", email="a@example.com", name="Admin", role="Auditor"
        )


@pytest.mark.parametrize("changed", ["risk", "owner", "version"])
def test_stale_approval_is_rejected(monkeypatch, changed):
    risk = dict(
        risk_ref=1,
        revision=1,
        threat="Loss",
        risk_owner="Owner",
        pre_likelihood=3,
        pre_impact=3,
        treatment_option="Modify",
    )
    previous = dict(version=2, status="In review", records=[risk], owner="Owner")
    current = dict(risk, revision=2 if changed == "risk" else 1)
    cursor = install_cursor(
        monkeypatch, [{"exists": 1}, {"role": "Administrator"}, previous], [current]
    )
    with pytest.raises(repo.FoundationError):
        repo.save_version(
            "Client",
            1,
            2,
            "risks",
            [],
            actor="a@example.com",
            owner="Changed" if changed == "owner" else "Owner",
            status="Approved",
            expected_version=1 if changed == "version" else 2,
            note="Reviewed",
        )
    assert not any(
        "INSERT INTO securescope_foundation_versions" in call.args[0]
        for call in cursor.execute.call_args_list
    )


@pytest.mark.parametrize("kind", ["policy", "objectives", "risks"])
def test_formal_screen_renders_for_auditor(kind):
    script = (
        "\nfrom unittest.mock import patch\nfrom "
        "securescope.ui.grc_workspace import formal\nwith "
        'patch.object(formal, "versions", return_value=[]), '
        'patch.object(formal, "get_workspace_role", '
        'return_value="Auditor"), patch.object(formal, '
        '"list_risk_register", return_value=[]), '
        'patch("securescope.ui.grc_workspace.overview.load_policies", '
        "return_value=([], [])), "
        'patch("securescope.ui.grc_workspace.overview.list_risk_register", '
        "return_value=[]):\n    "
        'formal.legacy_render_formal_register("Client", '
        '{"selected_engagement_id": 1, "selected_scope_id": 2}, '
        f"{kind!r}"
        ")\n"
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert all(
        button.disabled
        for button in app.button
        if button.label
        in {"Save draft version", "Approve reviewed version", "Submit reviewed version"}
    )


def test_overview_failed_reads_are_not_zero():
    script = (
        "\nfrom unittest.mock import patch\nfrom "
        "securescope.ui.grc_workspace import formal\n\ndef "
        "section(client, engagement, scope, kind):\n    if kind == "
        '"context":\n        raise '
        'formal.GrcWorkspaceServiceError("Connection unavailable")\n  '
        '  return {"interested_parties": [{"id": 1}], '
        '"organizational_units": [{"id": 2}], "role_assignments": []}\n\nwith '
        'patch.object(formal.SERVICE, "load_section", '
        'side_effect=section), patch.object(formal, "versions", '
        "return_value=[]), patch.object(formal, "
        '"list_risk_register", return_value=[]), '
        'patch("securescope.ui.grc_workspace.overview.load_policies", '
        "return_value=([], [])), "
        'patch("securescope.ui.grc_workspace.overview.list_risk_register", '
        "return_value=[]):\n    "
        'formal.render_foundation_overview("Client", '
        '{"selected_engagement_id": 1, "selected_scope_id": 2, '
        '"scopes": [{"id": 2, "latest_status": "Draft"}]}, lambda '
        "section: None)\n"
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert any("Connection unavailable" in item.value for item in app.caption)
    assert any("Unavailable" in item.value for item in app.markdown)
    assert any("Records</span><strong>1</strong>" in item.value for item in app.markdown)


def test_approval_captures_canonical_risks_not_caller_rows(monkeypatch):
    risk = dict(
        risk_ref=1,
        revision=1,
        threat="Loss",
        risk_owner="Owner",
        pre_likelihood=3,
        pre_impact=3,
        treatment_option="Modify",
    )
    prior = dict(version=2, status="In review", records=[risk], owner="Owner")
    cursor = install_cursor(monkeypatch, [{"exists": 1}, {"role": "Administrator"}, prior], [risk])
    assert (
        repo.save_version(
            "Client",
            1,
            2,
            "risks",
            [{"forged": True}],
            actor="admin@example.com",
            owner="Owner",
            status="Approved",
            expected_version=2,
            note="Reviewed",
        )
        == 3
    )
    values = cursor.execute.call_args.args[1]
    assert values[6].adapted == [risk]
    assert values[-1] == "admin@example.com"


def test_policy_draft_save_from_ui():
    script = (
        "\nimport streamlit as st\nfrom unittest.mock import "
        "patch\nfrom securescope.ui.grc_workspace import formal\n\ndef "
        'save(*args, **kwargs):\n    st.session_state["saved"] = '
        '{"records": args[4], "status": kwargs["status"]}\n\nwith '
        'patch.object(formal, "versions", return_value=[]), '
        'patch.object(formal, "get_workspace_role", '
        'return_value="Administrator"), patch.object(formal, '
        '"save_version", side_effect=save):\n    '
        'formal.legacy_render_formal_register("Client", '
        '{"selected_engagement_id": 1, "selected_scope_id": 2}, '
        '"policy")\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    next(item for item in app.text_area if item.label == "Title").input("Security policy")
    next(item for item in app.text_area if item.label == "Policy text").input(
        "Management commits to reviewing security."
    )
    next(item for item in app.text_area if item.label == "Owner").input("Owner")
    next(item for item in app.button if item.label == "Keep record in draft").click().run()
    assert not app.exception
    next(item for item in app.button if item.label == "Save draft version").click().run()
    assert not app.exception
    assert app.session_state["saved"]["status"] == "Draft"
    assert app.session_state["saved"]["records"][0]["title"] == "Security policy"


def test_foundation_groups_navigate_to_formal_registers():
    script = (
        "\nimport streamlit as st\nfrom unittest.mock import "
        "patch\nfrom securescope.ui.grc_workspace import "
        'router\ncontext = {"selected_engagement_id": 1, '
        '"selected_scope_id": 2}\nwith patch.object(router, '
        '"render_access_notice"), patch.object(router, '
        '"render_context_or_error", return_value=context), '
        'patch.object(router, "scope_editor_is_open", '
        "return_value=False), patch.object(router.SERVICE, "
        '"load_section", return_value={}), patch.object(router, '
        '"_render_selected_section", side_effect=lambda client, '
        'context, section, records: st.write("Selected: " + '
        "section)), "
        'patch("securescope.ui.grc_workspace.stitch_records.render_stitch_'
        'records", side_effect=lambda client, context, section, records: '
        'st.write("Selected: " + section)):\n    '
        'router.render_programme_setup("Client")\n'
    )
    app = AppTest.from_string(script).run()
    assert not app.exception
    assert not app.radio
    app.session_state["programme_section_control::Client"] = "governance"
    app.run()
    assert not app.exception
    assert any(item.value == "Selected: roles" for item in app.markdown)
    app.session_state["programme_governance::Client"] = "objectives"
    app.run()
    assert any(item.value == "Selected: objectives" for item in app.markdown)
