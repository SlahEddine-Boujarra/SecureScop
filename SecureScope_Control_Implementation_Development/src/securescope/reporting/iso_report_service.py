"""ISO/IEC 27001:2022 technical-assurance reporting for SecureScope."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable
from zipfile import ZIP_DEFLATED, ZipFile

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from securescope.compliance.iso_control_assessment_service import assessment_summary

NAVY = colors.HexColor("#0B1F3A")
TEAL = colors.HexColor("#0F7C82")
LIGHT = colors.HexColor("#F3F6F8")
BORDER = colors.HexColor("#D5DEE7")
TEXT = colors.HexColor("#172033")


def _styles() -> dict[str, ParagraphStyle]:
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ISO_Title",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=NAVY,
        ),
        "subtitle": ParagraphStyle(
            "ISO_Subtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#5D6B7C"),
        ),
        "section": ParagraphStyle(
            "ISO_Section",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=8,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "ISO_Body",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=TEXT,
        ),
        "small": ParagraphStyle(
            "ISO_Small",
            parent=styles["BodyText"],
            fontSize=6.8,
            leading=9,
            textColor=TEXT,
        ),
    }


def _text(value: Any, limit: int = 500) -> str:
    if isinstance(value, list):
        value = " • ".join(str(item) for item in value)
    text = str(value or "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text[:limit]


def build_iso_assurance_pdf(
    *,
    client_name: str,
    assessments: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    clock_summary: dict[str, Any],
) -> bytes:
    """Generate an audit-oriented Annex A.8 technical-assurance PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"SecureScope ISO 27001 Technical Assurance — {client_name}",
    )
    styles = _styles()
    summary = assessment_summary(assessments)
    generated = datetime.now(timezone.utc).isoformat()

    story = [
        Paragraph("ISO/IEC 27001:2022 Technical Assurance", styles["title"]),
        Paragraph(
            f"Client workspace: {_text(client_name)} · Generated: {_text(generated)}",
            styles["subtitle"],
        ),
        Spacer(1, 6 * mm),
    ]

    metrics = [
        ["Readiness", "Maturity", "Controls", "Gaps", "Partial", "Evidence gaps"],
        [
            f"{summary['readiness_score']}%",
            f"{summary['maturity_level']} — {summary['maturity_label']}",
            summary["controls_total"],
            summary["gap_controls"],
            summary["partial_controls"],
            summary["insufficient_evidence"],
        ],
    ]
    metric_table = Table(metrics, colWidths=[42 * mm] * 6)
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), LIGHT),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(metric_table)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Clock synchronization assurance — A.8.17", styles["section"]))
    story.append(
        Paragraph(
            _text(
                f"Fleet status: {clock_summary.get('status')} · "
                f"Evidence {clock_summary.get('assets_with_endpoint_evidence', 0)}/"
                f"{clock_summary.get('assets_total', 0)} · "
                f"Synchronized {clock_summary.get('synchronized_assets', 0)} · "
                f"Gaps {clock_summary.get('gap_assets', 0)} · "
                f"Sources: {clock_summary.get('sources') or 'none'}"
            ),
            styles["body"],
        )
    )

    story.append(Paragraph("Annex A.8 control assessment", styles["section"]))
    rows = [["Control", "Name", "Automatic", "Final", "Score", "Maturity", "Evidence", "Gaps"]]
    for item in assessments:
        rows.append(
            [
                Paragraph(
                    _text(item.get("Control") or item.get("control_id"), 20), styles["small"]
                ),
                Paragraph(
                    _text(item.get("Control name") or item.get("control_name"), 100),
                    styles["small"],
                ),
                Paragraph(
                    _text(item.get("Automatic status") or item.get("automated_status"), 50),
                    styles["small"],
                ),
                Paragraph(_text(item.get("final_status"), 80), styles["small"]),
                Paragraph(_text(item.get("Score") or item.get("score"), 10), styles["small"]),
                Paragraph(_text(item.get("Maturity"), 30), styles["small"]),
                Paragraph(
                    _text(item.get("Evidence") or item.get("evidence"), 350), styles["small"]
                ),
                Paragraph(_text(item.get("Gaps") or item.get("gaps"), 350), styles["small"]),
            ]
        )
    table = Table(
        rows,
        repeatRows=1,
        colWidths=[18 * mm, 35 * mm, 28 * mm, 32 * mm, 13 * mm, 25 * mm, 57 * mm, 57 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(table)

    story.append(PageBreak())
    story.append(Paragraph("Corrective action plan", styles["section"]))
    if actions:
        action_rows = [["ID", "Control", "Priority", "Status", "Owner", "Due", "Action"]]
        for item in actions:
            action_rows.append(
                [
                    item.get("id"),
                    item.get("control_id"),
                    item.get("priority"),
                    item.get("status"),
                    Paragraph(_text(item.get("owner"), 60), styles["small"]),
                    item.get("due_date") or "—",
                    Paragraph(_text(item.get("description"), 600), styles["small"]),
                ]
            )
        action_table = Table(
            action_rows,
            repeatRows=1,
            colWidths=[12 * mm, 20 * mm, 20 * mm, 30 * mm, 30 * mm, 25 * mm, 130 * mm],
        )
        action_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ]
            )
        )
        story.append(action_table)
    else:
        story.append(Paragraph("No corrective actions were recorded.", styles["body"]))

    story.append(Spacer(1, 5 * mm))
    story.append(
        Paragraph(
            "Scope note: this report automates technical evidence and GAP analysis. "
            "Certification and final control implementation decisions require competent "
            "human review and the applicable organizational evidence.",
            styles["subtitle"],
        )
    )
    doc.build(story)
    return buffer.getvalue()


def build_iso_evidence_zip(
    *,
    client_name: str,
    assessments: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    clock_rows: Iterable[dict[str, Any]],
    assets: Iterable[dict[str, Any]],
    scan_history: Iterable[dict[str, Any]],
) -> bytes:
    """Create a portable JSON evidence package."""
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        files = {
            "assessment.json": assessments,
            "corrective_actions.json": actions,
            "clock_evidence.json": list(clock_rows),
            "asset_inventory.json": list(assets),
            "scan_history.json": list(scan_history),
            "manifest.json": {
                "client_name": client_name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scope": "ISO/IEC 27001:2022 Annex A.8 technical assurance",
                "automated_result_is_certification": False,
            },
        }
        for name, payload in files.items():
            archive.writestr(
                name,
                json.dumps(payload, indent=2, default=str),
            )
    return buffer.getvalue()
