"""Trusted scanner provenance, coverage and delivery regression tests."""

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from securescope.evidence import evidence_service as service
from securescope.evidence.automated_checks import SCAN_COMPLETED, classify_nuclei, usable_evidence
from securescope.evidence.storage import EvidenceStorageError, store_artifact
from securescope.grc.assurance_requirements import evaluate_requirement
from securescope.persistence import evidence_repository as repository
from securescope.reporting.nuclei_report import parse_nuclei_jsonl

NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)


def evidence(asset, identity=1):
    """Return a canonical system evidence row for a single verified asset."""
    return dict(
        id=identity,
        source_verification_current=True,
        eligible_requirement_ids=["recent"],
        nuclei_verified_source=dict(
            version=3,
            complete=True,
            asset_id=asset,
            observed_at=(NOW - timedelta(days=1)).isoformat(),
            observations=[],
        ),
        scope_id=3,
        engagement_id=2,
        tool_id="nuclei",
        validation_status="Validated",
        mapping_approved=False,
        mapping_origin="Automated check",
        verification_origin="System collector",
        validator="system:nuclei-worker",
        source_key=f"nuclei:job-{identity}:attempt:1",
        collection_method="Existing worker",
        collected_at=NOW - timedelta(days=1),
        normalized_payload={
            "metadata": {
                "assurance": {"complete": True, "asset_ids": [asset]},
                "automated_checks": [SCAN_COMPLETED.to_dict()],
            }
        },
    )


def criterion():
    """Return a configured three-asset vulnerability collection requirement."""
    return dict(
        id="recent",
        title="Recent vulnerability scan",
        rule="Recent vulnerability scan",
        asset_ids=[1, 2, 3],
        machine_verifiable=True,
        max_age_days=90,
        threshold=100,
    )


@pytest.mark.parametrize(
    "count,status", [(0, "NO EVIDENCE"), (1, "PARTIAL"), (2, "PARTIAL"), (3, "PASS")]
)
def test_coverage_unions_assets(count, status):
    """Independent scans collectively cover only their actual canonical assets."""
    bundle = dict(
        scope_id=3,
        engagement_id=2,
        requirement_evidence=[evidence(i, i) for i in range(1, count + 1)],
    )
    result = evaluate_requirement(criterion(), bundle, NOW)
    assert result["result"] == status
    assert result["verified_assets"] == count
    assert result["applicable_assets"] == 3
    assert result["affected_assets"] == list(range(count + 1, 4))


def test_stale_foreign_and_duplicate_assets_do_not_inflate_coverage():
    """Staleness reduces the union; tenant-context checks and sets prevent inflation."""
    rows = [evidence(i, i) for i in range(1, 4)]
    rows[1]["collected_at"] = NOW - timedelta(days=100)
    rows += [evidence(1, 4), dict(evidence(2, 5), scope_id=99)]
    result = evaluate_requirement(
        criterion(), dict(scope_id=3, engagement_id=2, requirement_evidence=rows), NOW
    )
    assert result["verified_assets"] == 2
    assert result["result"] == "PARTIAL"


@pytest.mark.parametrize(
    "field,value",
    [
        ("verification_origin", "Human review"),
        ("collection_method", "Report import"),
        ("mapping_origin", "Catalog suggestion"),
        ("validator", "consultant"),
        ("source_key", None),
        ("tool_id", "manual"),
        ("validation_status", "Pending"),
    ],
)
def test_uploaded_data_cannot_bypass_review(field, value):
    """Each trusted provenance condition is required independently."""
    row = evidence(1)
    row[field] = value
    assert not usable_evidence(row, {"nuclei"})


def test_catalogue_unknown_and_precise_gap_mapping():
    """Descriptions cannot guess controls; known header observations remain gaps."""
    finding = {"template-id": "unknown-observation", "info": {"name": "auth tls cve vulnerability"}}
    rows, _ = parse_nuclei_jsonl(json.dumps(finding).encode(), report_id="r", asset_ip="192.0.2.1")
    assert rows[0]["ISO Mapping"] == []
    check = classify_nuclei("http-missing-security-headers")[0]
    assert check.effect == "gap"
    assert check.mapped_controls == ("A.8.9",)
    assert check.mapped_requirements == ("Secure web configuration baseline",)


@pytest.mark.parametrize("count", [0, 11])
def test_scan_ingestion_is_one_record_with_all_observations(monkeypatch, tmp_path, count):
    """Empty successful output and eleven findings each produce one canonical record."""
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_STORAGE_ROOT", str(tmp_path))
    monkeypatch.setattr(service, "get_client_id", lambda *a, **k: 1)
    monkeypatch.setattr(
        repository, "resolve_nuclei_asset", lambda *a: dict(id=1, asset_tag="AST-00001")
    )
    create = MagicMock(return_value=19)
    monkeypatch.setattr(service, "create_evidence_record", create)
    payload = {"template-id": "http-missing-security-headers", "info": {"name": "Missing headers"}}
    content = (json.dumps(payload) + "\n").encode() * count
    assert (
        service.ingest_nuclei_scan_output(
            "Client",
            job_uuid="job",
            attempt_number=1,
            report_id="r",
            asset_ip="192.0.2.1",
            profile="standard",
            collected_at=NOW,
            content=content,
            successful=True,
        )
        == 19
    )
    create.assert_called_once()
    args = create.call_args.kwargs
    assert len(args["normalized"]["observations"]) == count
    assert args["normalized"]["metadata"]["assurance"] == dict(
        complete=True, asset_ids=[1], asset_ips=["192.0.2.1"]
    )
    assert args["artifact_factory"](1).byte_size == len(content)
    assert args["suggested_controls"] == (["A.8.8", "A.8.9"] if count else ["A.8.8"])


def test_failed_or_corrupt_collection_cannot_be_verified():
    """Unsuccessful or partially corrupt output is rejected before storage."""
    for success, content in [(False, b""), (True, b"{invalid")]:
        with pytest.raises(service.EvidenceServiceError):
            service.ingest_nuclei_scan_output(
                "Client",
                job_uuid="job",
                attempt_number=1,
                report_id="r",
                asset_ip="192.0.2.1",
                profile="standard",
                collected_at=NOW,
                content=content,
                successful=success,
            )


def test_manual_empty_artifact_still_rejected(tmp_path, monkeypatch):
    """Empty artifacts are allowed only through the explicit trusted call."""
    monkeypatch.setenv("SECURESCOPE_EVIDENCE_STORAGE_ROOT", str(tmp_path))
    with pytest.raises(EvidenceStorageError):
        store_artifact(1, "manual.jsonl", b"")


@pytest.mark.parametrize("kind,signature", [("pdf", b"%PDF-"), ("docx", b"PK")])
def test_policy_export_payload_and_immutability(monkeypatch, kind, signature):
    """Export returns real serialized bytes without mutating saved policy or versions."""
    from securescope.policies.suggestions import policy_template
    from securescope.ui import assurance_workbench as ui

    policy = policy_template("Information Security", "Client")
    policy.update(policy_id="p1", policy_version=1, status="Draft", title="../../Security Policy")
    before = copy.deepcopy(policy)
    monkeypatch.setattr(ui.st, "session_state", {"k::selected": "p1"})
    save = MagicMock()
    monkeypatch.setattr(ui, "save_policy", save)
    response = ui.dispatch_policy(
        "Client",
        2,
        3,
        "admin",
        [policy],
        1,
        "k",
        dict(action="export", payload={"format": kind}, selected="p1", expected=1),
    )
    assert base64.b64decode(response["content_base64"]).startswith(signature)
    assert response["filename"] == f"Security_Policy_v1.{kind}"
    json.dumps(response)
    assert policy == before
    save.assert_not_called()


def test_finalization_retry_reuses_evidence_without_inserting(monkeypatch):
    """A locked completed job with an existing source key returns its canonical ID."""
    cursor = MagicMock()
    cursor.fetchone.side_effect = [{"id": 1}, {"id": 7, "asset_id": 1}, {"id": 19}]
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    connection.__enter__.return_value = connection
    monkeypatch.setattr(repository, "connect", lambda: connection)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    artifact_factory = MagicMock()
    result = repository.create_evidence_record(
        "Client",
        tool_id="nuclei",
        collection_method="Existing worker",
        evidence_type="Automated technical evidence",
        title="Scan",
        summary="Completed",
        scope_description="Configured assets",
        source_asset_or_system="192.0.2.1",
        owner="system:nuclei-worker",
        submitted_by="system:nuclei-worker",
        collected_at=NOW,
        expires_at=None,
        confidence="Medium",
        normalized={},
        suggested_controls=["A.8.8"],
        artifact_factory=artifact_factory,
        system_source=dict(
            job_uuid="job", attempt_number=1, asset_id=1, checks=[SCAN_COMPLETED.to_dict()]
        ),
    )
    assert result == 19
    artifact_factory.assert_not_called()
    sql = " ".join(str(call.args[0]) for call in cursor.execute.call_args_list)
    assert "FOR UPDATE OF j" in sql
    assert "INSERT INTO securescope_evidence_records" not in sql
    assert "INSERT INTO securescope_evidence_artifacts" not in sql


def test_system_scope_association_uses_current_configured_assets(monkeypatch):
    """One evidence gets multiple legitimate scope links; unrelated asset scopes are excluded."""
    cursor = MagicMock()
    cursor.fetchall.return_value = [
        {"config": {"scope_id": 3, "engagement_id": 2, "requirements": [{"asset_ids": [1, 2]}]}},
        {"config": {"scope_id": 4, "engagement_id": 2, "requirements": [{"asset_ids": [1]}]}},
        {"config": {"scope_id": 5, "engagement_id": 2, "requirements": [{"asset_ids": [99]}]}},
    ]
    cursor.fetchone.side_effect = [{"id": 3}, {"id": 4}]
    link = MagicMock()
    monkeypatch.setattr(repository, "_insert_evidence_scope_link", link)
    repository._link_system_evidence(
        cursor, 1, 19, dict(asset_id=1, checks=[SCAN_COMPLETED.to_dict()]), ["A.8.8"]
    )
    assert [call.args[3] for call in link.call_args_list] == [3, 4]
    assert all(call.kwargs["origin"] == "Automated collection" for call in link.call_args_list)
    mapping_sql = " ".join(str(call.args[0]) for call in cursor.execute.call_args_list)
    assert "Automated check" in mapping_sql
    assert "approved_by" not in mapping_sql


def test_worker_environment_uses_canonical_path_without_overriding(tmp_path):
    """Standalone imports load the canonical file without polluting the test process."""
    import os
    import subprocess
    import sys

    env_file = tmp_path / "worker.env"
    env_file.write_text("SECURESCOPE_DATABASE_URL=postgresql://example.invalid/test\n")
    environment = dict(os.environ)
    environment.pop("SECURESCOPE_DATABASE_URL", None)
    code = """
import importlib
import os
import sys
from pathlib import Path
from securescope import paths
paths.ENV_FILE = Path(sys.argv[1])
from securescope.evidence import evidence_worker as worker
assert os.environ['SECURESCOPE_DATABASE_URL'] == 'postgresql://example.invalid/test'
os.environ['SECURESCOPE_DATABASE_URL'] = 'postgresql://override.invalid/test'
importlib.reload(worker)
assert os.environ['SECURESCOPE_DATABASE_URL'] == 'postgresql://override.invalid/test'
"""
    subprocess.run([sys.executable, "-c", code, str(env_file)], env=environment, check=True)


def test_worker_initializes_before_poll_and_preserves_job_context(monkeypatch):
    """Startup migration precedes queue polling; job context reaches canonical ingestion."""
    from securescope.evidence import continuous_assurance
    from securescope.evidence import evidence_worker as worker

    events = []
    monkeypatch.setattr(worker, "run_pending_migrations", lambda: events.append("migrate"))

    def claim(name, *, schema_initialized=False):
        """Record the worker's already-initialized queue read."""
        assert schema_initialized
        events.append("claim")
        return None

    monkeypatch.setattr(worker, "claim_evidence_job", claim)
    monkeypatch.setattr(continuous_assurance, "refresh_continuous_assurance", lambda **kwargs: None)
    assert worker.run_worker(once=True) == 0
    assert events == ["migrate", "claim"]


def test_gap_only_evidence_cannot_satisfy_scan_requirement():
    """A gap mapping is not positive support even if the artifact's scan completed."""
    row = evidence(1)
    row["normalized_payload"]["metadata"]["automated_checks"] = [
        classify_nuclei("http-missing-security-headers")[0].to_dict()
    ]
    result = evaluate_requirement(
        dict(criterion(), follow_provider=True),
        dict(scope_id=3, engagement_id=2, requirement_evidence=[row]),
        NOW,
    )
    assert result["result"] == "NO EVIDENCE"


def test_system_collection_does_not_make_final_assurance_decision():
    """Complete collection coverage requires a human final control assessment."""
    from securescope.grc.assurance_requirements import evaluate_assurance

    requirement = dict(
        criterion(), type="Technical", mandatory=True, expected_result="Current scan"
    )
    bundle = dict(
        scope_id=3,
        engagement_id=2,
        profile={
            "assessment_scope": {"implementation_requirements": {"requirements": [requirement]}}
        },
        requirement_evidence=[evidence(i, i) for i in range(1, 4)],
        soa={"applicability": "Applicable"},
    )
    result = evaluate_assurance(bundle, now=NOW)
    assert result["requirements"][0]["result"] == "PASS"
    assert result["implementation"] != "Implemented"
    assert result["assurance"] != "Effective"
    assert not result["auto_verified"]


def test_generic_worker_propagates_context(monkeypatch, tmp_path):
    """Known generic collection context reaches ingestion without granting system trust."""
    from types import SimpleNamespace

    from securescope.evidence import evidence_worker as worker

    monkeypatch.setenv("SECURESCOPE_EVIDENCE_WORK_ROOT", str(tmp_path))
    monkeypatch.setattr(
        worker,
        "build_collection_plan",
        lambda *a, **k: SimpleNamespace(output_path=tmp_path / "findings.json"),
    )
    monkeypatch.setattr(worker, "execute_collection_plan", lambda *a: b"{}")
    ingest = MagicMock(return_value=9)
    monkeypatch.setattr(worker, "ingest_collector_output", ingest)
    job = dict(
        tool_id="lynis",
        job_uuid="j",
        client_name="Client",
        requested_by="consultant",
        request_payload=dict(target="/approved", engagement_id=2, scope_id=3),
    )
    assert worker.process_job(job) == 9
    assert ingest.call_args.kwargs["scope_id"] == 3
    assert ingest.call_args.kwargs["engagement_id"] == 2
    assert "verification_origin" not in ingest.call_args.kwargs


def test_profile_detail_bypasses_list_widgets(monkeypatch):
    """Real Streamlit page branches hide list-only widgets on detail and restore them on return."""
    from streamlit.testing.v1 import AppTest

    from securescope.ui import exposure_management_ui as page

    monkeypatch.setattr(page, "list_control_overview", lambda *a, **k: [])
    monkeypatch.setattr(page, "list_control_gaps_and_actions", lambda *a, **k: [])
    monkeypatch.setattr(page, "components_v2_available", lambda: True)

    def render(client, profiles, summaries):
        """Render a route marker without replacing the page's tab/filter behavior."""
        import streamlit as st

        if st.session_state.get(f"control_drawers::{client}::implementation"):
            st.header("Back to Control Profiles")
        else:
            st.header("Control Profiles list")

    monkeypatch.setattr(page, "render_control_profiles", render)
    app = AppTest.from_string(
        """
import streamlit as st
from securescope.ui.exposure_management_ui import render_gap_assessment_page
st.session_state['assurance_active_tab::Client']=':material/table_view: Control profiles'
render_gap_assessment_page('Client', [])
"""
    ).run()
    assert not app.exception
    assert any(s.label == "Assessment filter" for s in app.selectbox)
    assert any("Showing 0 of 0 controls" in c.value for c in app.caption)
    app.session_state["control_drawers::Client::implementation"] = "A.8.8"
    app.run()
    assert not app.exception
    assert not any(s.label == "Assessment filter" for s in app.selectbox)
    assert not any("Showing 0 of 0 controls" in c.value for c in app.caption)
    assert any(h.value == "Back to Control Profiles" for h in app.header)
    del app.session_state["control_drawers::Client::implementation"]
    app.run()
    assert any(s.label == "Assessment filter" for s in app.selectbox)


@pytest.mark.parametrize("fails", [False, True])
def test_finalization_waits_for_canonical_evidence(monkeypatch, tmp_path, fails):
    """Require evidence before reports complete; retain existing recovery on failure."""
    from securescope.scanners.nuclei import nuclei_worker_service as worker

    artifact = tmp_path / "findings.jsonl"
    artifact.write_bytes(b"")
    job = dict(
        id=1,
        job_uuid="job",
        attempt_number=1,
        client_id=1,
        batch_id=1,
        asset_ip="192.0.2.1",
        output_path=str(artifact),
    )
    monkeypatch.setattr(worker, "get_nuclei_job", lambda *a: job)
    monkeypatch.setattr(worker, "get_client_name_by_id", lambda *a: "Client")
    monkeypatch.setattr(worker, "get_nuclei_batch", lambda *a: {"profile_name": "standard"})
    monkeypatch.setattr(worker, "generate_nuclei_pdf", lambda *a, **k: b"%PDF-test")
    monkeypatch.setattr(
        worker, "save_report_bundle", lambda **k: (artifact, tmp_path / "report.pdf")
    )
    monkeypatch.setattr(worker, "_sync_ciso", lambda **k: ("Not configured", {}))
    events = []
    monkeypatch.setattr(worker, "update_nuclei_job", lambda *a, **k: events.append(k["status"]))
    monkeypatch.setattr(
        worker, "upsert_scan_record_for_client", lambda *a: events.append("scan saved")
    )
    monkeypatch.setattr(worker, "mark_asset_scanned_for_engine", lambda *a: None)

    def ingest(*args, **kwargs):
        """Simulate a deterministic persistence success or recoverable failure."""
        events.append("evidence")
        assert kwargs["content"] == b""
        if fails:
            raise repository.EvidenceRepositoryError("Unavailable")
        return 19

    monkeypatch.setattr(service, "ingest_nuclei_scan_output", ingest)
    worker._finalize_job(job, {"exit_code": 0, "completed_at": NOW.isoformat()})
    assert events[:2] == ["Finalizing", "evidence"]
    if fails:
        assert events[-1] == "Processing"
        assert "Completed" not in events
        assert "scan saved" not in events
    else:
        assert events == ["Finalizing", "evidence", "scan saved", "Completed"]
