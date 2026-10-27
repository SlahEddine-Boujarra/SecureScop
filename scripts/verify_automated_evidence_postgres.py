"""Recorded-provider regression helper for the guarded fresh-database verification script.

This writes fixtures only; it never starts a scanner or contacts a target.
Invoke scripts/verify_evidence_scope_postgres.py against an EMPTY disposable PostgreSQL database.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from psycopg2.extras import Json


def verify_automated_evidence(client: str, actor: str, engagement: int, scope: int, other: int):
    """Exercise real canonical persistence with recorded successful scanner outputs.

    Args:
        client: Disposable workspace created by the guarded caller.
        actor: Administrator fixture identity.
        engagement: Canonical engagement ID.
        scope: Primary Scope ID.
        other: Independent Scope ID.
    Returns:
        None; fixture records and artifacts remain available for app verification.
    Raises:
        AssertionError: An ingestion, isolation, coverage or repair invariant failed.
        DatabaseError: A repository transaction failed.
    """
    from securescope.cli.backfill_nuclei_evidence import backfill
    from securescope.evidence.evidence_service import ingest_nuclei_scan_output
    from securescope.grc.assurance_requirements import evaluate_requirement
    from securescope.grc.requirement_templates import baseline_requirements
    from securescope.persistence.assurance_workspace_repository import _evidence
    from securescope.persistence.foundation_repository import workspace_cursor
    from securescope.persistence.grc_repository import seed_control_profiles
    from securescope.persistence.nuclei_persistence import (
        create_nuclei_batch,
        load_nuclei_batch_jobs,
    )

    seed_control_profiles(client)
    root = Path(tempfile.mkdtemp(prefix="securescope-pg-evidence-"))
    os.environ["SECURESCOPE_EVIDENCE_STORAGE_ROOT"] = str(root / "evidence")
    assets = []
    with workspace_cursor(client) as (cursor, client_id):
        for number in range(1, 5):
            asset = dict(ip=f"192.0.2.{number}", asset_tag=f"AST-{number:05}")
            cursor.execute(
                "INSERT INTO securescope_assets(client_id,ip,asset_tag,payload) "
                "VALUES (%s,%s,%s,%s) RETURNING id",
                (client_id, asset["ip"], asset["asset_tag"], Json(asset)),
            )
            asset["id"] = cursor.fetchone()["id"]
            assets.append(asset)
        requirement = baseline_requirements("A.8.8")[0]
        config = dict(scope_id=scope, engagement_id=engagement, requirements=[requirement])
        cursor.execute(
            "UPDATE securescope_control_assessment_profiles SET assessment_scope=%s "
            "WHERE client_id=%s AND control_id='A.8.8'",
            (Json({"implementation_requirements": config}), client_id),
        )
    context = dict(
        client=client,
        engagement_id=engagement,
        scope_id=scope,
        control_id="A.8.8",
        requirement_id=requirement["id"],
        asset_ids=[],
    )
    batch = create_nuclei_batch(
        client_name=client,
        assets=assets,
        scan_mode="standard",
        profile_name="standard",
        collection_context=context,
        actor=actor,
    )
    jobs = load_nuclei_batch_jobs(batch["id"])
    now = datetime.now(timezone.utc)
    content = (
        b"\n".join(
            json.dumps({"template-id": template, "info": {"name": template}}).encode()
            for template in ["missing-x-frame-options", "ssl-expired", "default-login-example"]
        )
        + b"\n"
    )
    first_id = None
    for index, job in enumerate(jobs):
        raw = content if index == 0 else b""
        output = root / f'{job["job_uuid"]}.jsonl'
        output.write_bytes(raw)
        with workspace_cursor(client) as (cursor, client_id):
            cursor.execute(
                "UPDATE securescope_nuclei_jobs SET status='Completed',"
                "provider_status='Completed',completed_at=%s,output_path=%s "
                "WHERE client_id=%s AND id=%s",
                (now, str(output), client_id, job["id"]),
            )
        identity = ingest_nuclei_scan_output(
            client,
            job_uuid=job["job_uuid"],
            attempt_number=1,
            report_id=job["job_uuid"],
            asset_ip=job["asset_ip"],
            profile="standard",
            collected_at=now,
            content=raw,
            successful=True,
        )
        with workspace_cursor(client) as (cursor, client_id):
            if index == 0:
                first_id = identity
                for control in ["A.8.5", "A.8.8", "A.8.9", "A.8.24"]:
                    assert identity in {
                        r["id"] for r in _evidence(cursor, client_id, control, engagement, scope)
                    }
                    assert not _evidence(cursor, client_id, control, engagement, other)
                requirement["asset_ids"] = [a["id"] for a in assets]
                cursor.execute(
                    "UPDATE securescope_control_assessment_profiles "
                    "SET assessment_scope=%s WHERE client_id=%s AND control_id='A.8.8'",
                    (Json({"implementation_requirements": config}), client_id),
                )
            rows = _evidence(cursor, client_id, "A.8.8", engagement, scope)
            result = evaluate_requirement(
                requirement,
                dict(scope_id=scope, engagement_id=engagement, requirement_evidence=rows),
                now,
            )
            assert result["verified_assets"] == index + 1
            assert result["result"] == ("PASS" if index == 3 else "PARTIAL")
    # Simulate a pre-bridge completion and an old missing scope association.
    missing = create_nuclei_batch(
        client_name=client, assets=assets[:1], scan_mode="standard", profile_name="standard"
    )
    job = load_nuclei_batch_jobs(missing["id"])[0]
    output = root / "historical.jsonl"
    output.write_bytes(b"")
    with workspace_cursor(client) as (cursor, client_id):
        cursor.execute(
            "UPDATE securescope_nuclei_jobs SET status='Completed',"
            "provider_status='Completed',completed_at=%s,output_path=%s WHERE id=%s",
            (now, str(output), job["id"]),
        )
        cursor.execute(
            "DELETE FROM securescope_engagement_record_links "
            "WHERE client_id=%s AND evidence_id=%s",
            (client_id, first_id),
        )
        cursor.execute(
            "UPDATE securescope_nuclei_batches SET status='Completed' " "WHERE id=ANY(%s)",
            ([batch["id"], missing["id"]],),
        )
    first, second = backfill(client), backfill(client)
    assert first["created"] == 1 and second["created"] == 0
    assert first["errors"] == second["errors"] == 0
    with workspace_cursor(client) as (cursor, client_id):
        assert first_id in {
            r["id"] for r in _evidence(cursor, client_id, "A.8.9", engagement, scope)
        }
        assert not _evidence(cursor, client_id, "A.8.8", engagement, other)
    print(
        "PASS: recorded Nuclei output, four-control linkage with no assigned assets, "
        "scope isolation, 1/4 through 4/4 coverage, clean scan, backfill and repeat repair."
    )


def verify_wazuh_fixtures(client: str, actor: str, engagement: int, scope: int, other: int):
    """Verify three independent persisted Wazuh facts through the real evidence repository.

    Args:
        client: Disposable workspace with the scanner fixture's canonical inventory.
        actor: Authorized fixture principal.
        engagement: Current engagement.
        scope: Scope containing the recorded fixture asset.
        other: Scope without that asset.
    Returns:
        None; retains records for real-app inspection.
    Raises:
        AssertionError: Provenance, repeat ingestion or scope isolation fails.
        DatabaseError: Fixture persistence fails.
    """
    from securescope.evidence.wazuh_bridge import ingest_wazuh_evidence
    from securescope.persistence.assurance_workspace_repository import _evidence
    from securescope.persistence.clock_evidence_persistence import save_clock_evidence
    from securescope.persistence.db_wazuh_service import save_wazuh_snapshot
    from securescope.persistence.foundation_repository import workspace_cursor

    now = datetime.now(timezone.utc).isoformat()
    save_wazuh_snapshot(
        client,
        [],
        [
            dict(
                asset_ip="192.0.2.1",
                asset_tag="AST-00001",
                match_type="ip",
                wazuh_agent_id="001",
                wazuh_status="active",
                wazuh_last_keep_alive=now,
                last_alert={
                    "timestamp": now,
                    "rule_id": "1001",
                    "rule_description": "Recorded test event",
                },
            )
        ],
        None,
    )
    save_clock_evidence(
        client,
        [
            dict(
                asset_ip="192.0.2.1",
                wazuh_agent_id="001",
                clock_sync_status="Synchronized",
                clock_evidence_source="Wazuh endpoint command",
                clock_last_checked=now,
                clock_source="ntp.example.test",
                clock_offset_ms=1,
            )
        ],
    )
    identities = ingest_wazuh_evidence(client, actor)
    assert len(set(identities)) == 3
    assert set(ingest_wazuh_evidence(client, actor)) == set(identities)
    with workspace_cursor(client) as (cursor, client_id):
        for control, key in [("A.8.15", "logging"), ("A.8.16", "monitoring"), ("A.8.17", "clock")]:
            rows = _evidence(cursor, client_id, control, engagement, scope)
            sources = [row for row in rows if row["tool_id"] == "wazuh"]
            assert len(sources) == 1
            row = sources[0]
            assert row["validator"] == "system:wazuh-connector"
            assert row["mapping_origin"] == "Automated check"
            assert not row["mapping_approved"]
            assert list(row["normalized_payload"]["metadata"]["assurance"]) == [key]
            assert not _evidence(cursor, client_id, control, engagement, other)
    print(
        "PASS: recorded Wazuh log, monitoring and clock facts persist independently, "
        "remain scope-isolated and reuse canonical identities on repeat ingestion."
    )
