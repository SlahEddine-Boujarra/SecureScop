"""Client-scoped ISO audit scope and annual schedule persistence."""

from __future__ import annotations

from datetime import date
from typing import Any, Mapping, Sequence

from psycopg2.extras import RealDictCursor

from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.migration_service import run_pending_migrations

MONTH_KEYS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")


AUDIT_SCHEDULE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "row_key": "4",
        "iso_ref": "4",
        "row_label": "4. CONTEXT OF THE ORGANIZATION",
        "row_type": "section",
    },
    {
        "row_key": "4.1",
        "iso_ref": "4.1",
        "row_label": "Understanding the organization and its context",
        "row_type": "requirement",
    },
    {
        "row_key": "4.2",
        "iso_ref": "4.2",
        "row_label": "Understanding the needs and expectations of interested parties",
        "row_type": "requirement",
    },
    {
        "row_key": "4.3",
        "iso_ref": "4.3",
        "row_label": "Determining the scope of the information security management system",
        "row_type": "requirement",
    },
    {
        "row_key": "4.4",
        "iso_ref": "4.4",
        "row_label": "Information security management system",
        "row_type": "requirement",
    },
    {"row_key": "5", "iso_ref": "5", "row_label": "5. LEADERSHIP", "row_type": "section"},
    {
        "row_key": "5.1",
        "iso_ref": "5.1",
        "row_label": "Leadership and commitment",
        "row_type": "requirement",
    },
    {"row_key": "5.2", "iso_ref": "5.2", "row_label": "Policy", "row_type": "requirement"},
    {
        "row_key": "5.3",
        "iso_ref": "5.3",
        "row_label": "Organizational roles, responsibilities and authorities",
        "row_type": "requirement",
    },
    {"row_key": "6", "iso_ref": "6", "row_label": "6. PLANNING", "row_type": "section"},
    {
        "row_key": "6.1",
        "iso_ref": "6.1",
        "row_label": "Actions to address risks and opportunities",
        "row_type": "requirement",
    },
    {
        "row_key": "6.2",
        "iso_ref": "6.2",
        "row_label": "Information security objectives and planning to achieve them",
        "row_type": "requirement",
    },
    {
        "row_key": "6.3",
        "iso_ref": "6.3",
        "row_label": "Planning of changes",
        "row_type": "requirement",
    },
    {
        "row_key": "6.soa",
        "iso_ref": "SoA",
        "row_label": "Review Statement of Applicability",
        "row_type": "requirement",
    },
    {"row_key": "7", "iso_ref": "7", "row_label": "7. SUPPORT", "row_type": "section"},
    {"row_key": "7.1", "iso_ref": "7.1", "row_label": "Resources", "row_type": "requirement"},
    {"row_key": "7.2", "iso_ref": "7.2", "row_label": "Competence", "row_type": "requirement"},
    {"row_key": "7.3", "iso_ref": "7.3", "row_label": "Awareness", "row_type": "requirement"},
    {"row_key": "7.4", "iso_ref": "7.4", "row_label": "Communication", "row_type": "requirement"},
    {
        "row_key": "7.5",
        "iso_ref": "7.5",
        "row_label": "Documented information",
        "row_type": "requirement",
    },
    {"row_key": "8", "iso_ref": "8", "row_label": "8. OPERATION", "row_type": "section"},
    {
        "row_key": "8.1",
        "iso_ref": "8.1",
        "row_label": "Operational planning and control",
        "row_type": "requirement",
    },
    {
        "row_key": "8.2",
        "iso_ref": "8.2",
        "row_label": "Information security risk assessment",
        "row_type": "requirement",
    },
    {
        "row_key": "8.3",
        "iso_ref": "8.3",
        "row_label": "Information security risk treatment",
        "row_type": "requirement",
    },
    {
        "row_key": "9",
        "iso_ref": "9",
        "row_label": "9. PERFORMANCE EVALUATION",
        "row_type": "section",
    },
    {
        "row_key": "9.1",
        "iso_ref": "9.1",
        "row_label": "Monitoring, measurement, analysis and evaluation",
        "row_type": "requirement",
    },
    {"row_key": "9.2", "iso_ref": "9.2", "row_label": "Internal audit", "row_type": "requirement"},
    {
        "row_key": "9.3",
        "iso_ref": "9.3",
        "row_label": "Management review",
        "row_type": "requirement",
    },
    {"row_key": "10", "iso_ref": "10", "row_label": "10. IMPROVEMENT", "row_type": "section"},
    {
        "row_key": "10.1",
        "iso_ref": "10.1",
        "row_label": "Continual improvement",
        "row_type": "requirement",
    },
    {
        "row_key": "10.2",
        "iso_ref": "10.2",
        "row_label": "Nonconformity and corrective action",
        "row_type": "requirement",
    },
    {
        "row_key": "A.5",
        "iso_ref": "A.5",
        "row_label": "A.5 Organizational controls",
        "row_type": "control_family",
    },
    {
        "row_key": "A.6",
        "iso_ref": "A.6",
        "row_label": "A.6 People controls",
        "row_type": "control_family",
    },
    {
        "row_key": "A.7",
        "iso_ref": "A.7",
        "row_label": "A.7 Physical controls",
        "row_type": "control_family",
    },
    {
        "row_key": "A.8",
        "iso_ref": "A.8",
        "row_label": "A.8 Technological controls",
        "row_type": "control_family",
    },
)


def _client_id(cursor: Any, client_name: str) -> int:
    cursor.execute("SELECT id FROM securescope_clients WHERE name = %s;", (client_name,))
    row = cursor.fetchone()
    if not row:
        raise GrcRepositoryError(f"Client workspace not found: {client_name}")
    return int(row["id"] if isinstance(row, Mapping) else row[0])


def default_schedule_rows() -> list[dict[str, Any]]:
    """Return the supplied clause and Annex A schedule rows with blank months."""

    return [
        {
            **row,
            "audit_no": "",
            **{month: "" for month in MONTH_KEYS},
            "notes": "",
        }
        for row in AUDIT_SCHEDULE_CATALOG
    ]


def load_audit_scope(client_name: str) -> dict[str, Any] | None:
    """Load the latest audit scope and its annual schedule for one workspace."""

    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    "SELECT * FROM securescope_audit_scopes WHERE client_id = %s "
                    "ORDER BY audit_year DESC, id DESC LIMIT 1;",
                    (client_id,),
                )
                scope = cursor.fetchone()
                if not scope:
                    return None
                result = dict(scope)
                cursor.execute(
                    "SELECT * FROM securescope_audit_schedule_rows "
                    "WHERE client_id = %s AND audit_scope_id = %s "
                    "ORDER BY row_key;",
                    (client_id, int(scope["id"])),
                )
                result["schedule"] = [dict(row) for row in cursor.fetchall()]
                return result
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc


def save_audit_scope(
    client_name: str,
    fields: Mapping[str, Any],
    schedule_rows: Sequence[Mapping[str, Any]],
    *,
    actor: str,
    expected_revision: int = 0,
) -> int:
    """Upsert a scope and schedule atomically with optimistic revision checks."""

    audit_no = str(fields.get("audit_no") or "").strip()
    if not audit_no:
        raise GrcRepositoryError("Audit number is required.")
    try:
        audit_year = int(fields.get("audit_year") or date.today().year)
    except (TypeError, ValueError) as exc:
        raise GrcRepositoryError("Audit year must be numeric.") from exc
    if not 2000 <= audit_year <= 2200:
        raise GrcRepositoryError("Audit year must be between 2000 and 2200.")
    actor_text = str(actor or "").strip() or "securescope-ui"
    run_pending_migrations()
    try:
        with connect() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                client_id = _client_id(cursor, client_name)
                cursor.execute(
                    (
                        "SELECT * FROM securescope_audit_scopes WHERE client_id = %s AND "
                        "audit_no = %s FOR UPDATE;"
                    ),
                    (client_id, audit_no),
                )
                previous = cursor.fetchone()
                actual_revision = int(previous["revision"]) if previous else 0
                if expected_revision and actual_revision != expected_revision:
                    raise GrcRepositoryError(
                        "The audit scope changed. Reload it before saving again."
                    )
                revision = actual_revision + 1
                cursor.execute(
                    (
                        "\n                    INSERT INTO securescope_audit_scopes "
                        "(\n                        client_id, audit_no, audit_year, "
                        "status, scope_statement,\n                        "
                        "objectives, criteria, sites, processes, systems, "
                        "exclusions,\n                        lead_auditor, "
                        "planned_start, planned_end, approved_by,\n                   "
                        "     approved_at, approval_comment, revision, updated_by\n   "
                        "                 ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, "
                        "%s, %s, %s,\n                              %s, %s, %s, %s, "
                        "%s, %s, %s, %s)\n                    ON CONFLICT (client_id, "
                        "audit_no) DO UPDATE SET\n                        audit_year "
                        "= EXCLUDED.audit_year, status = EXCLUDED.status,\n           "
                        "             scope_statement = EXCLUDED.scope_statement, "
                        "objectives = EXCLUDED.objectives,\n                        "
                        "criteria = EXCLUDED.criteria, sites = EXCLUDED.sites, "
                        "processes = EXCLUDED.processes,\n                        "
                        "systems = EXCLUDED.systems, exclusions = "
                        "EXCLUDED.exclusions,\n                        lead_auditor = "
                        "EXCLUDED.lead_auditor, planned_start = "
                        "EXCLUDED.planned_start,\n                        planned_end "
                        "= EXCLUDED.planned_end, approved_by = "
                        "EXCLUDED.approved_by,\n                        approved_at = "
                        "EXCLUDED.approved_at, approval_comment = "
                        "EXCLUDED.approval_comment,\n                        revision "
                        "= EXCLUDED.revision, updated_by = EXCLUDED.updated_by, "
                        "updated_at = NOW()\n                    RETURNING id;\n       "
                        "             "
                    ),
                    (
                        client_id,
                        audit_no,
                        audit_year,
                        str(fields.get("status") or "Draft"),
                        str(fields.get("scope_statement") or "").strip(),
                        str(fields.get("objectives") or "").strip(),
                        str(fields.get("criteria") or "ISO/IEC 27001:2022").strip(),
                        str(fields.get("sites") or "").strip(),
                        str(fields.get("processes") or "").strip(),
                        str(fields.get("systems") or "").strip(),
                        str(fields.get("exclusions") or "").strip(),
                        str(fields.get("lead_auditor") or "").strip(),
                        fields.get("planned_start"),
                        fields.get("planned_end"),
                        str(fields.get("approved_by") or "").strip() or None,
                        fields.get("approved_at"),
                        str(fields.get("approval_comment") or "").strip(),
                        revision,
                        actor_text,
                    ),
                )
                scope_id = int(cursor.fetchone()["id"])
                for row in schedule_rows:
                    row_key = str(row.get("row_key") or "").strip()
                    if not row_key:
                        continue
                    values = [str(row.get(month) or "").strip() for month in MONTH_KEYS]
                    cursor.execute(
                        (
                            "\n                        INSERT INTO "
                            "securescope_audit_schedule_rows (\n                          "
                            "  client_id, audit_scope_id, row_key, iso_ref, row_label, "
                            "row_type,\n                            audit_no, jan, feb, "
                            "mar, apr, may, jun, jul, aug, sep, oct, nov, dec,\n          "
                            "                  notes, updated_by\n                        "
                            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)\n                    "
                            "    ON CONFLICT (client_id, audit_scope_id, row_key) DO "
                            "UPDATE SET\n                            iso_ref = "
                            "EXCLUDED.iso_ref, row_label = EXCLUDED.row_label,\n          "
                            "                  row_type = EXCLUDED.row_type, audit_no = "
                            "EXCLUDED.audit_no,\n                            jan = "
                            "EXCLUDED.jan, feb = EXCLUDED.feb, mar = EXCLUDED.mar,\n      "
                            "                      apr = EXCLUDED.apr, may = "
                            "EXCLUDED.may, jun = EXCLUDED.jun,\n                          "
                            "  jul = EXCLUDED.jul, aug = EXCLUDED.aug, sep = "
                            "EXCLUDED.sep,\n                            oct = "
                            "EXCLUDED.oct, nov = EXCLUDED.nov, dec = EXCLUDED.dec,\n      "
                            "                      notes = EXCLUDED.notes, updated_by = "
                            "EXCLUDED.updated_by, updated_at = NOW();\n                   "
                            "     "
                        ),
                        (
                            client_id,
                            scope_id,
                            row_key,
                            str(row.get("iso_ref") or ""),
                            str(row.get("row_label") or ""),
                            str(row.get("row_type") or "requirement"),
                            str(row.get("audit_no") or ""),
                            *values,
                            str(row.get("notes") or ""),
                            actor_text,
                        ),
                    )
                return revision
    except DatabaseError as exc:
        raise GrcRepositoryError(str(exc)) from exc
