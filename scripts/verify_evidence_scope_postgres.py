"""Verify evidence scope persistence using an explicitly supplied EMPTY PostgreSQL database.

Run with SECURESCOPE_TEST_DATABASE_URL set. Refuses databases with application tables.
This creates test records and retains them for subsequent real-app UI verification.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import psycopg2

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> None:
    """Run real migrations and verify submissions, scope isolation and approval reads.

    Returns:
        None; prints checks passed and leaves the disposable database available.
    Raises:
        RuntimeError: If no explicit test URL is supplied or the database is nonempty.
        AssertionError: If any persistence or isolation regression occurs.
        psycopg2.Error: If PostgreSQL is unavailable.
    """
    url = os.environ.get("SECURESCOPE_TEST_DATABASE_URL")
    if not url:
        raise RuntimeError("Set SECURESCOPE_TEST_DATABASE_URL to an empty disposable database.")
    with psycopg2.connect(url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema')"
            )
            if cursor.fetchone()[0]:
                raise RuntimeError("Refusing a nonempty database; use a new disposable database.")
    os.environ["SECURESCOPE_DATABASE_URL"] = url
    os.environ["SECURESCOPE_LOCAL_SETUP_CODE"] = secrets.token_urlsafe(32)

    from securescope.evidence.evidence_service import consultant_review, submit_manual_evidence
    from securescope.grc.engagement_models import ScopeDraft
    from securescope.persistence.assurance_workspace_repository import _evidence
    from securescope.persistence.evidence_repository import (
        EvidenceRepositoryError,
        list_evidence_records,
    )
    from securescope.persistence.foundation_repository import local_administrator, workspace_cursor
    from securescope.persistence.grc_workspace_repository import (
        create_scope_version,
        ensure_workspace_foundation,
    )
    from securescope.persistence.migration_service import run_pending_migrations

    migrations = run_pending_migrations()
    client, actor = "Default Client", "evidence-review@example.test"
    local_administrator(
        client, actor, "Evidence Review", os.environ["SECURESCOPE_LOCAL_SETUP_CODE"]
    )
    context = ensure_workspace_foundation(client, actor=actor)
    engagement, scope = context["engagement_id"], context["scope_id"]
    other = create_scope_version(
        client,
        engagement,
        ScopeDraft(scope_code="OTHER", name="Other scope", scope_statement="Separate services"),
        actor=actor,
    )["scope_id"]
    arguments = dict(
        role="Administrator",
        control_ids=["4.1"],
        evidence_type="Record",
        title="Context review",
        summary="Minutes reviewed by the consultant",
        scope_description="Primary scope",
        source_asset_or_system="Governance",
        owner=actor,
        submitted_by=actor,
    )
    unassigned = submit_manual_evidence(client, **arguments)
    identity = submit_manual_evidence(client, engagement_id=engagement, scope_id=scope, **arguments)
    scoped = list_evidence_records(client, scope_id=scope, engagement_id=engagement)
    assert [r["id"] for r in scoped] == [identity]
    assert {r["id"] for r in list_evidence_records(client)} == {identity, unassigned}
    assert not list_evidence_records(client, scope_id=other, engagement_id=engagement)
    assert identity in {r["id"] for r in list_evidence_records(client, validation_status="Pending")}
    try:
        submit_manual_evidence(client, engagement_id=engagement, scope_id=-1, **arguments)
    except EvidenceRepositoryError:
        pass
    else:
        raise AssertionError("Invalid scope was accepted")
    assert len(list_evidence_records(client)) == 2, "Failed submission leaked a record"
    consultant_review(
        client,
        identity,
        role="Administrator",
        decision="Validated",
        validator=actor,
        comment="Reviewed original minutes and confirmed scope coverage",
        approved_controls=["4.1"],
    )
    scoped = list_evidence_records(client, scope_id=scope, engagement_id=engagement)
    assert scoped[0]["validation_status"] == "Validated"
    assert scoped[0]["validator"] == actor and scoped[0]["validated_at"]
    assert scoped[0]["controls"][0]["approved"]
    with workspace_cursor(client) as (cursor, client_id):
        downstream = _evidence(cursor, client_id, "4.1", engagement, scope)
        assert downstream[0]["id"] == identity
        assert downstream[0]["mapping_approved"]
        assert downstream[0]["validation_status"] == "Validated"
        assert not _evidence(cursor, client_id, "4.1", engagement, other)
    print(
        f"PASS: {len(migrations)} migrations; scoped/client-wide reads, unassigned preservation, "
        "scope isolation, rollback, consultant review, and Control Assurance evidence reader."
    )
    from verify_automated_evidence_postgres import verify_automated_evidence, verify_wazuh_fixtures

    verify_automated_evidence(client, actor, engagement, scope, other)
    verify_wazuh_fixtures(client, actor, engagement, scope, other)
    print("Pending: real-app screenshots/counters and live Wazuh endpoint verification.")


if __name__ == "__main__":
    main()
