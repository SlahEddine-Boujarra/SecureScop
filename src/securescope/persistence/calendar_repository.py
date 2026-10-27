"""Client calendar projections from saved dates, without inferred schedules."""

from __future__ import annotations

from securescope.persistence.foundation_repository import workspace_cursor
from securescope.persistence.workspace_planning import list_records


def calendar_events(client: str) -> list[dict]:
    """Collect manual events, policy renewals, risk reviews, tasks and audit dates."""
    events = [
        dict(row["payload"], event_id=row["record_key"], revision=row["revision"], source="Manual")
        for row in list_records(client, "calendar_event")
    ]
    with workspace_cursor(client) as (cursor, client_id):
        cursor.execute(
            (
                "SELECT DISTINCT ON (engagement_id,scope_id) "
                "engagement_id,scope_id,records FROM "
                "securescope_foundation_versions WHERE client_id=%s AND "
                "register_key='policy' ORDER BY engagement_id,scope_id,version "
                "DESC"
            ),
            (client_id,),
        )
        for snapshot in cursor.fetchall():
            for row in snapshot["records"]:
                if row.get("review_date") and row.get("status") != "Archived":
                    events.append(
                        {
                            "title": row.get("title", "Policy renewal"),
                            "starts_at": row["review_date"],
                            "source": "Policy renewal",
                            "route": "Policies",
                            "policy_id": row.get("policy_id"),
                            "scope": snapshot["scope_id"],
                            "engagement": snapshot["engagement_id"],
                        }
                    )
        cursor.execute(
            (
                "SELECT id,audit_no,planned_start,planned_end FROM "
                "securescope_audit_scopes WHERE client_id=%s"
            ),
            (client_id,),
        )
        for row in cursor.fetchall():
            for field, label in [("planned_start", "Audit starts"), ("planned_end", "Audit ends")]:
                if row.get(field):
                    events.append(
                        {
                            "title": f"{label}: {row['audit_no']}",
                            "starts_at": str(row[field]),
                            "source": "Audit",
                            "route": "Gap Assessment",
                            "audit_id": row["id"],
                        }
                    )
        # Queued jobs have a queue timestamp, not a promised execution date.
        for table, label in [
            ("securescope_nuclei_jobs", "Nuclei"),
            ("securescope_openvas_jobs", "OpenVAS"),
        ]:
            cursor.execute("SELECT to_regclass(%s) AS relation", (table,))
            if cursor.fetchone()["relation"]:
                from psycopg2 import sql

                cursor.execute(
                    sql.SQL(
                        (
                            "SELECT id,asset_ip,created_at FROM {} WHERE client_id=%s AND "
                            "status='Queued'"
                        )
                    ).format(sql.Identifier(table)),
                    (client_id,),
                )
                for row in cursor.fetchall():
                    events.append(
                        {
                            "title": f"{label} queued: {row['asset_ip']}",
                            "starts_at": str(row["created_at"]),
                            "source": "Queued scan (queued at)",
                            "route": "3 · Scan Center",
                        }
                    )
    for kind, field, label in [
        ("risk_detail", "review_due", "Risk review"),
        ("risk_task", "due", "Risk action"),
    ]:
        for record in list_records(client, kind):
            row = record["payload"]
            if row.get(field):
                events.append(
                    {
                        "title": row.get("title") or f"Risk {row['risk_ref']} review",
                        "starts_at": row[field],
                        "source": label,
                        "route": "Risk",
                        "risk_ref": row["risk_ref"],
                    }
                )
    return events
