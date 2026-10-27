"""Regression coverage for the evidence correction pass (Part I excluded)."""

from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from securescope.evidence.automated_checks import classify_nuclei, usable_evidence
from securescope.evidence.freshness import evidence_freshness
from securescope.evidence.wazuh_bridge import normalized_source
from securescope.grc.assurance_requirements import evaluate_requirement
from securescope.grc.requirement_templates import baseline_requirements, merge_baseline
from securescope.persistence import evidence_repository as repository
from tests.test_nuclei_evidence_pipeline import NOW, evidence


@pytest.mark.parametrize(
    "template,control",
    [
        ("missing-x-frame-options", "A.8.9"),
        ("cookies-without-httponly", "A.8.9"),
        ("ssh-weak-algo", "A.8.24"),
    ],
)
def test_precise_added_mappings(template, control):
    checks = classify_nuclei(template)
    assert len(checks) == 1
    assert checks[0].mapped_controls == (control,)
    assert checks[0].effect == "gap"
    assert checks[0].mapped_requirements


@pytest.mark.parametrize("template", ["tls-version", "exposed-panel"])
def test_observations_without_deterministic_gap_stay_unmapped(template):
    assert not classify_nuclei(template, ["ssl", "tls", "panel"])


@pytest.mark.parametrize("control", ["A.8.9", "A.8.24", "A.8.5", "A.8.17"])
def test_technical_seed_preserves_manual_requirements(control):
    rows = baseline_requirements(control)
    assert len(rows) == 4
    assert sum(r["rule"] == "Manual validation" for r in rows) == 3
    assert rows[-1]["machine_verifiable"]


def test_v1_monitoring_upgrade_preserves_custom_boundary_and_identity():
    original = baseline_requirements("A.8.16")[0]
    original.update(
        rule="Log source coverage",
        template_version=1,
        asset_ids=[42],
        evidence_links=[{"evidence_id": 19}],
    )
    rows, changed = merge_baseline(
        "A.8.16", {"baseline_template_version": 1, "requirements": [original]}
    )
    assert changed
    assert rows[0]["id"] == original["id"]
    assert rows[0]["rule"] == "Monitoring coverage"
    assert rows[0]["asset_ids"] == [42]
    assert rows[0]["evidence_links"] == original["evidence_links"]
    assert original["rule"] == "Log source coverage"


def test_customized_criterion_supersedes_seed_without_losing_provenance():
    seed = baseline_requirements("A.8.8")[0]
    custom = {**deepcopy(seed), "id": "custom", "asset_ids": [42]}
    custom.pop("template_id")
    rows, _ = merge_baseline(
        "A.8.8", {"baseline_template_version": 2, "requirements": [seed, custom]}
    )
    assert len(rows) == 1
    assert rows[0]["id"] == "custom"
    assert rows[0]["template_id"] == seed["template_id"]
    assert rows[0]["asset_ids"] == [42]


def technical_fixture():
    """Return one gap observation and two configured assets."""
    check = classify_nuclei("missing-x-frame-options")[0]
    row = evidence(1)
    row["control_id"] = "A.8.9"
    row["normalized_payload"]["metadata"]["automated_checks"] = [check.to_dict()]
    rule = baseline_requirements("A.8.9")[-1]
    rule["asset_ids"] = [1, 2]
    from securescope.evidence.nuclei_assurance import source_facts

    row["nuclei_verified_source"] = source_facts(
        b'{"template-id":"missing-x-frame-options","host":"192.0.2.1"}', 1, "192.0.2.1", NOW
    )
    row["eligible_requirement_ids"] = [rule["id"]]
    return rule, dict(scope_id=3, engagement_id=2, requirement_evidence=[row])


def test_gap_and_uncollected_asset_are_independently_reported():
    rule, bundle = technical_fixture()
    result = evaluate_requirement(rule, bundle, NOW)
    assert result["result"] == "FAIL"
    assert result["asset_results"] == {"1": "FAIL", "2": "NOT COLLECTED"}
    assert result["evidence_ids"] == [1]


def test_clean_scan_does_not_prove_headers_passed():
    rule, bundle = technical_fixture()
    bundle["requirement_evidence"] = [evidence(1)]
    result = evaluate_requirement(rule, bundle, NOW)
    assert result["result"] != "PASS"
    assert set(result["asset_results"].values()) == {"NOT COLLECTED"}


def test_unconfigured_assets_have_actionable_message_and_visible_gap():
    rule, bundle = technical_fixture()
    rule["asset_ids"] = []
    result = evaluate_requirement(rule, bundle, NOW)
    assert result["result"] == "UNKNOWN"
    assert result["reason_code"] == "assets_unassigned"
    assert result["candidate_observations"]


def test_expiry_and_criterion_age_share_strictest_deadline():
    row = dict(
        collected_at=NOW - timedelta(days=20),
        expires_at=NOW + timedelta(days=70),
        freshness_status="Current",
        max_age_days=10,
    )
    assert evidence_freshness(row, 90, NOW) == "Stale"
    assert row["freshness_status"] == "Current"  # Historical record is not mutated.
    row["max_age_days"] = 90
    assert evidence_freshness(row, 90, NOW) == "Current"
    row["expires_at"] = NOW
    assert evidence_freshness(row, 90, NOW) == "Stale"


def wazuh_row():
    """Return an exact persisted Wazuh source with independently observable fields."""
    return dict(
        id=71,
        asset_id=42,
        asset_tag="SERVER",
        wazuh_agent_id="007",
        wazuh_status="active",
        wazuh_last_keep_alive=NOW,
        collected_at=NOW,
        last_alert_time=None,
        status="Unknown",
        observed_at=NOW,
        payload={"clock_evidence_source": "Wazuh endpoint command"},
    )


def test_agent_presence_proves_neither_logging_nor_clock():
    row = wazuh_row()
    assert normalized_source(row, "logging") is None
    assert normalized_source(row, "clock") is None
    assert normalized_source(row, "monitoring", now=NOW) is None


@pytest.mark.parametrize(
    "kind,field,value,control",
    [
        ("logging", "last_alert_time", NOW, "A.8.15"),
        ("monitoring", "wazuh_status", "active", "A.8.16"),
        ("clock", "status", "Synchronized", "A.8.17"),
    ],
)
def test_wazuh_checks_map_only_their_own_control(kind, field, value, control):
    row = wazuh_row()
    row[field] = value
    if kind != "clock":
        row.update(
            schema_version=2,
            identity_verified=True,
            binding_id=1,
            connector_id="source",
            manager_name="manager",
            api_verified=True,
            source_health="healthy",
            heartbeat_max_age_seconds=300,
            telemetry_max_age_seconds=3600,
            telemetry=dict(
                authenticated=True,
                kind="security_event",
                agent_id="007",
                manager_name="manager",
                source_event_id="i:e",
                rule_id="1",
                observed_at=NOW,
            ),
        )
    payload, timestamp = normalized_source(row, kind, now=NOW)
    assert timestamp == NOW
    assert list(payload["metadata"]["assurance"]) == [kind]
    assert payload["metadata"]["automated_checks"][0]["mapped_controls"] == (control,)
    assert payload["metadata"]["provenance"]["asset_id"] == 42


def test_unsynchronized_clock_is_a_gap_and_manual_clock_not_trusted():
    row = wazuh_row()
    row["status"] = "Not synchronized"
    payload, _ = normalized_source(row, "clock")
    assert payload["metadata"]["automated_checks"][0]["effect"] == "gap"
    assert payload["metadata"]["assurance"]["clock"]["satisfied_asset_ids"] == []
    row["payload"] = {}
    assert normalized_source(row, "clock") is None


def test_manual_wazuh_upload_cannot_claim_system_verification():
    row = dict(
        evidence(42),
        tool_id="wazuh",
        validator="system:wazuh-connector",
        source_key="wazuh:monitoring:71",
        collection_method="Report import",
    )
    assert not usable_evidence(row, {"wazuh"})
    row["collection_method"] = "Authenticated API"
    assert usable_evidence(row, {"wazuh"})


def test_origin_maps_controls_but_does_not_infer_asset_scope(monkeypatch):
    cursor = MagicMock()
    cursor.fetchall.return_value = []
    cursor.fetchone.side_effect = [
        {
            "config": {
                "scope_id": 3,
                "engagement_id": 2,
                "requirements": [{"id": "origin", "asset_ids": []}],
            }
        },
        {"id": 3},
    ]
    checks = [
        classify_nuclei(t)[0].to_dict()
        for t in ["missing-x-frame-options", "ssl-expired", "grafana-default-login"]
    ]
    source = dict(
        asset_id=42,
        checks=checks,
        collection_context=dict(
            scope_id=3, engagement_id=2, control_id="A.8.8", requirement_id="origin"
        ),
    )
    link = MagicMock()
    monkeypatch.setattr(repository, "_insert_evidence_scope_link", link)
    repository._link_system_evidence(cursor, 1, 19, source, ["A.8.9", "A.8.24", "A.8.5"])
    link.assert_not_called()
    mappings = [
        c.args[1][2]
        for c in cursor.execute.call_args_list
        if str(c.args[0]).startswith("INSERT INTO securescope_evidence_control_mappings")
    ]
    assert set(mappings) == {"A.8.9", "A.8.24", "A.8.5"}


def test_unknown_asset_scope_does_not_guess_membership(monkeypatch):
    cursor = MagicMock()
    cursor.fetchall.return_value = []
    link = MagicMock()
    monkeypatch.setattr(repository, "_insert_evidence_scope_link", link)
    repository._link_system_evidence(cursor, 1, 19, dict(asset_id=42, checks=[]), [])
    link.assert_not_called()


def test_windows_launcher_enables_utf8_before_python_launch():
    root = Path(__file__).parents[1]
    launcher = (root / "start_securescope.ps1").read_text(encoding="utf-8")
    assert '$env:PYTHONUTF8 = "1"' in launcher
    for name in ["assurance_workbench", "assurance_pages", "assurance_plan", "policy_editor"]:
        source = (root / f"src/securescope/ui/components_v2/{name}.py").read_text(encoding="utf-8")
        assert ".read_text()" not in source
        assert 'encoding="utf-8"' in source


@pytest.mark.parametrize(
    "provider,destination",
    [
        ("nuclei", "3 · Scan Center"),
        ("wazuh", "5 · SIEM & Wazuh"),
        ("openscap", "Collect Evidence"),
        ("manual", "Manual Evidence"),
    ],
)
def test_requirement_collection_preserves_single_context(monkeypatch, provider, destination):
    from types import SimpleNamespace

    from securescope.ui import evidence_collection_context as context
    from securescope.ui import navigation_runtime

    state = {}
    monkeypatch.setattr(context, "st", SimpleNamespace(session_state=state, rerun=lambda: None))
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 3))
    navigate = MagicMock()
    monkeypatch.setattr(navigation_runtime, "navigate_to", navigate)
    context.begin_collection("Client", "A.8.8", {"id": "r1", "asset_ids": [42]}, provider)
    origin = state[context.KEY]
    assert (origin["client"], origin["engagement_id"], origin["scope_id"]) == ("Client", 2, 3)
    assert origin["control_id"] == "A.8.8" and origin["requirement_id"] == "r1"
    assert origin["asset_ids"] == [42]
    if provider in {"nuclei", "wazuh"}:
        navigate.assert_called_once_with(destination)
        assert "evidence_section::Client" not in state
    else:
        assert state["evidence_section::Client"] == destination
    assert context.current_collection_context("Other") == {}
    monkeypatch.setattr(context, "selected_context_ids", lambda client: (2, 99))
    assert context.current_collection_context("Client") == {}


def test_backfill_second_run_repairs_same_identity_without_duplicate(monkeypatch, tmp_path):
    from securescope.cli import backfill_nuclei_evidence as backfill

    artifact = tmp_path / "scan.jsonl"
    artifact.write_bytes(b"")
    job = dict(
        id=1,
        evidence_id=None,
        job_uuid="job",
        attempt_number=1,
        output_path=str(artifact),
        report_id="report",
        asset_ip="192.0.2.1",
        profile_name="standard",
        completed_at=NOW,
    )
    connection, cursor = MagicMock(), MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchall.side_effect = lambda: [dict(job)]
    monkeypatch.setattr(backfill, "connect", lambda: connection)
    monkeypatch.setattr(backfill, "run_pending_migrations", lambda: None)

    def ingest(*args, **kwargs):
        job["evidence_id"] = 19
        return 19

    ingest_mock = MagicMock(side_effect=ingest)
    repair = MagicMock(return_value=True)
    monkeypatch.setattr(backfill, "ingest_nuclei_scan_output", ingest_mock)
    monkeypatch.setattr(backfill, "repair_nuclei_evidence", repair)
    first = backfill.backfill("Client")
    artifact.unlink()  # Existing evidence can be repaired without the old worker artifact.
    second = backfill.backfill("Client")
    assert first["created"] == 1 and second["created"] == 0
    assert second["revisited"] == 1
    ingest_mock.assert_called_once()
    repair.assert_called_once_with("Client", 19)


def test_soa_draft_allows_justified_exclusion_but_approval_does_not(monkeypatch):
    from securescope.persistence import grc_repository as soa
    from tests.test_final_consistency import cursor_for

    cursor = cursor_for(monkeypatch, soa)
    cursor.fetchone.side_effect = [(1,), ("Administrator",), (3,), (17,), None]
    item = dict(
        control_id="A.5.2",
        applicability="Not applicable",
        exclusion_justification="Outside the approved boundary",
        approved=False,
    )
    assert (
        soa.save_statement_of_applicability(
            "Client", [item], prepared_by="actor", engagement_id=7, scope_id=9, actor="actor"
        )
        == 3
    )
    with pytest.raises(soa.GrcRepositoryError, match="exclusions still require approval"):
        soa.save_statement_of_applicability(
            "Client", [item], prepared_by="actor", approved_by="actor", approve=True
        )


def test_soa_validation_reports_all_missing_justifications():
    from securescope.persistence.grc_repository import (
        GrcRepositoryError,
        save_statement_of_applicability,
    )

    items = [
        dict(control_id=control, applicability="Not applicable", exclusion_justification="")
        for control in ["A.5.2", "A.5.3"]
    ]
    with pytest.raises(GrcRepositoryError, match="2 controls.*A.5.2, A.5.3"):
        save_statement_of_applicability("Client", items, prepared_by="actor")


def test_client_wide_freshness_ignores_unrelated_scope_criteria():
    from datetime import datetime, timezone

    row = dict(
        id=19,
        control_id="A.8.9",
        collected_at=datetime.now(timezone.utc) - timedelta(days=20),
        normalized_payload={
            "metadata": {
                "automated_checks": [classify_nuclei("missing-x-frame-options")[0].to_dict()]
            }
        },
        freshness_status="Current",
    )
    cursor = MagicMock()
    cursor.fetchall.return_value = [
        dict(
            control_id="A.8.9",
            evidence_ids=[99],
            config={
                "scope_id": 7,
                "requirements": [{"rule": "Secure web configuration baseline", "max_age_days": 1}],
            },
        )
    ]
    repository.apply_evidence_currency(cursor, 1, [row])
    assert row["freshness_status"] == "Current"
    cursor.fetchall.return_value[0]["evidence_ids"] = [19]
    repository.apply_evidence_currency(cursor, 1, [row])
    assert row["freshness_status"] == "Stale"


@pytest.mark.parametrize("role", [None, "Auditor"])
def test_generic_worker_rechecks_real_membership_before_storage(monkeypatch, role):
    from securescope.evidence import evidence_service as service

    monkeypatch.setattr(repository, "get_workspace_role", lambda *args: role)
    store = MagicMock()
    monkeypatch.setattr(service, "store_artifact", store)
    with pytest.raises(service.EvidenceServiceError, match="authorized requesting member"):
        service.ingest_collector_output(
            "Client",
            tool_id="lynis",
            filename="lynis.dat",
            content=b"",
            requested_by="revoked@example.test",
            target="/approved",
        )
    store.assert_not_called()


def test_generic_worker_keeps_pending_review_and_original_context(monkeypatch):
    from securescope.evidence import evidence_service as service

    monkeypatch.setattr(repository, "get_workspace_role", lambda *args: "Consultant")
    monkeypatch.setattr(service, "get_client_id", lambda *args, **kwargs: 1)
    monkeypatch.setattr(service, "normalize_report", MagicMock())
    monkeypatch.setattr(service, "store_artifact", MagicMock())
    monkeypatch.setattr(service, "_correlate_report_findings", MagicMock())
    create = MagicMock(return_value=19)
    monkeypatch.setattr(service, "create_evidence_record", create)
    assert (
        service.ingest_collector_output(
            "Client",
            tool_id="lynis",
            filename="lynis.dat",
            content=b"",
            requested_by="consultant@example.test",
            target="/approved",
            engagement_id=2,
            scope_id=3,
        )
        == 19
    )
    values = create.call_args.kwargs
    assert (values["engagement_id"], values["scope_id"]) == (2, 3)
    assert values["submitted_by"] == "consultant@example.test"
    assert "system_source" not in values
    assert "validation_status" not in values
