"""SecureScope provider-neutral per-asset PDF report generator.

Creates an original security report inspired by common executive vulnerability
report layouts: summary, risk score, key findings, vulnerability checklist,
detailed findings, prioritized recommendations and ISO control references.
"""

from __future__ import annotations

import html
import io
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List
from zipfile import ZIP_DEFLATED, ZipFile

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

NAVY = colors.HexColor("#0B1F3A")
BLUE = colors.HexColor("#12678F")
CYAN = colors.HexColor("#1FA8C0")
LIGHT_BLUE = colors.HexColor("#EAF5FA")
SLATE = colors.HexColor("#475569")
LIGHT_SLATE = colors.HexColor("#E2E8F0")
PAGE_BG = colors.HexColor("#F8FAFC")
SUCCESS = colors.HexColor("#15803D")
CRITICAL = colors.HexColor("#8B1E3F")
HIGH = colors.HexColor("#C2410C")
MEDIUM = colors.HexColor("#D97706")
LOW = colors.HexColor("#0284C7")
INFO = colors.HexColor("#64748B")
WHITE = colors.white
BLACK = colors.HexColor("#0F172A")

SEVERITY_COLORS = {
    "Critical": CRITICAL,
    "High": HIGH,
    "Medium": MEDIUM,
    "Low": LOW,
    "Info": INFO,
}


def _safe(value: Any) -> str:
    return html.escape(str(value or "-"))


def _slug(value: Any) -> str:
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "report")).strip("._")
    return raw or "report"


def severity_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {key: 0 for key in ("Critical", "High", "Medium", "Low", "Info")}
    for finding in findings:
        severity = str(finding.get("Severity") or "Info")
        counts[severity if severity in counts else "Info"] += 1
    return counts


def security_score(findings: Iterable[Dict[str, Any]]) -> int:
    counts = severity_counts(findings)
    penalty = (
        counts["Critical"] * 22 + counts["High"] * 12 + counts["Medium"] * 6 + counts["Low"] * 2
    )
    return max(0, min(100, 100 - penalty))


def overall_risk(findings: Iterable[Dict[str, Any]]) -> str:
    counts = severity_counts(findings)
    for severity in ("Critical", "High", "Medium", "Low"):
        if counts[severity] > 0:
            return severity
    return "Low"


def _styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            textColor=NAVY,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=SLATE,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=NAVY,
            spaceBefore=8,
            spaceAfter=7,
            borderColor=BLUE,
            borderWidth=0,
            borderPadding=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=BLACK,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=12.5,
            textColor=BLACK,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=NAVY,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="WhiteSmall",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=WHITE,
            alignment=TA_CENTER,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CardValue",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=19,
            textColor=NAVY,
            alignment=TA_CENTER,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CardLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=SLATE,
            alignment=TA_CENTER,
        )
    )
    return styles


def _header_footer(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate, client_name: str) -> None:
    canvas_obj.saveState()
    width, height = A4
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, height - 13 * mm, width, 13 * mm, fill=1, stroke=0)
    canvas_obj.setFillColor(WHITE)
    canvas_obj.setFont("Helvetica-Bold", 8.5)
    canvas_obj.drawString(17 * mm, height - 8.5 * mm, "SecureScope Vulnerability Intelligence")
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawRightString(
        width - 17 * mm, height - 8.5 * mm, str(client_name or "Client workspace")
    )

    canvas_obj.setStrokeColor(LIGHT_SLATE)
    canvas_obj.line(17 * mm, 13 * mm, width - 17 * mm, 13 * mm)
    canvas_obj.setFillColor(SLATE)
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawString(
        17 * mm, 8.5 * mm, "Authorized security assessment - generated by SecureScope"
    )
    canvas_obj.drawRightString(width - 17 * mm, 8.5 * mm, f"Page {doc.page}")
    canvas_obj.restoreState()


def _risk_color(risk: str):
    return SEVERITY_COLORS.get(risk, INFO)


def _paragraph_list(items: Iterable[str], styles) -> List[Any]:
    result: List[Any] = []
    for item in items:
        if not str(item or "").strip():
            continue
        result.append(Paragraph(f"• {_safe(item)}", styles["Body"]))
        result.append(Spacer(1, 1.5 * mm))
    return result


def generate_asset_report_pdf(record: Dict[str, Any], client_name: str = "Default Client") -> bytes:
    """Generate one original, downloadable PDF vulnerability report."""
    buffer = io.BytesIO()
    styles = _styles()
    asset = dict(record.get("asset") or {})
    findings = list(record.get("findings") or [])
    counts = severity_counts(findings)
    score = security_score(findings)
    risk = overall_risk(findings)
    scanner = str(record.get("scanner") or record.get("scanner_engine") or "OpenVAS").strip()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"SecureScope Security Report - {asset.get('ip', 'asset')}",
        author="SecureScope",
        subject=f"{scanner} vulnerability assessment report",
    )

    story: List[Any] = []
    story.append(Spacer(1, 5 * mm))
    engine_records = list(record.get("engine_records") or [])
    report_title = (
        "Dual-Engine Vulnerability Scan Report"
        if len(engine_records) > 1
        or str(record.get("scanner_engine") or "").lower() == "dual engine"
        else "Vulnerability Scan Report"
    )
    story.append(Paragraph(report_title, styles["ReportTitle"]))
    story.append(
        Paragraph(
            (
                "Executive and technical report generated from "
                f"{scanner}"
                " findings, Nmap inventory context, risk prioritization and "
                "ISO/IEC 27001:2022 evidence "
                "mapping."
            ),
            styles["ReportSubtitle"],
        )
    )

    meta = [
        ["Client workspace", _safe(client_name), "Asset tag", _safe(asset.get("asset_tag"))],
        [
            "Target scanned",
            _safe(record.get("asset_ip") or asset.get("ip")),
            "Hostname",
            _safe(asset.get("hostname")),
        ],
        ["Scanner engine(s)", _safe(scanner), "Criticality", _safe(asset.get("criticality"))],
        ["Scan date", _safe(record.get("scanned_at")), "Report ID", _safe(record.get("report_id"))],
    ]
    meta_table = Table(meta, colWidths=[31 * mm, 60 * mm, 31 * mm, 51 * mm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
                ("BACKGROUND", (2, 0), (2, -1), LIGHT_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, -1), BLACK),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTNAME", (3, 0), (3, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 5 * mm))

    cards = [
        [
            Paragraph(str(score), styles["CardValue"]),
            Paragraph(risk, styles["CardValue"]),
            Paragraph(str(len(findings)), styles["CardValue"]),
        ],
        [
            Paragraph("SECURITY SCORE / 100", styles["CardLabel"]),
            Paragraph("OVERALL RISK", styles["CardLabel"]),
            Paragraph("TOTAL FINDINGS", styles["CardLabel"]),
        ],
    ]
    card_table = Table(cards, colWidths=[58 * mm, 58 * mm, 58 * mm], rowHeights=[14 * mm, 8 * mm])
    card_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    colors.Color(
                        _risk_color(risk).red,
                        _risk_color(risk).green,
                        _risk_color(risk).blue,
                        alpha=0.13,
                    ),
                ),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EEF2FF")),
                ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_SLATE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(card_table)
    story.append(Spacer(1, 3 * mm))

    risk_banner = Table(
        [
            [
                Paragraph("OVERALL RISK LEVEL", styles["WhiteSmall"]),
                Paragraph(_safe(risk), styles["WhiteSmall"]),
            ]
        ],
        colWidths=[48 * mm, 126 * mm],
        rowHeights=[9 * mm],
    )
    risk_banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), NAVY),
                ("BACKGROUND", (1, 0), (1, 0), _risk_color(risk)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_SLATE),
            ]
        )
    )
    story.append(risk_banner)

    story.append(Paragraph("Severity distribution", styles["SectionTitle"]))
    severity_data = [
        [
            Paragraph("Critical", styles["WhiteSmall"]),
            Paragraph("High", styles["WhiteSmall"]),
            Paragraph("Medium", styles["WhiteSmall"]),
            Paragraph("Low", styles["WhiteSmall"]),
            Paragraph("Info", styles["WhiteSmall"]),
        ],
        [
            str(counts["Critical"]),
            str(counts["High"]),
            str(counts["Medium"]),
            str(counts["Low"]),
            str(counts["Info"]),
        ],
    ]
    severity_table = Table(severity_data, colWidths=[34.8 * mm] * 5, rowHeights=[8 * mm, 9 * mm])
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), CRITICAL),
                ("BACKGROUND", (1, 0), (1, 0), HIGH),
                ("BACKGROUND", (2, 0), (2, 0), MEDIUM),
                ("BACKGROUND", (3, 0), (3, 0), LOW),
                ("BACKGROUND", (4, 0), (4, 0), INFO),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, 1), 11),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.4, WHITE),
                ("BACKGROUND", (0, 1), (-1, 1), PAGE_BG),
                ("TEXTCOLOR", (0, 1), (-1, 1), BLACK),
            ]
        )
    )
    story.append(severity_table)

    story.append(Paragraph("Key findings", styles["SectionTitle"]))
    top_findings = sorted(findings, key=lambda item: float(item.get("CVSS") or 0), reverse=True)[:5]
    if top_findings:
        for finding in top_findings:
            engine_label = (
                finding.get("Scanner Engine")
                or finding.get("scanner_engine")
                or finding.get("Scanner")
                or scanner
            )
            story.append(
                Paragraph(
                    f"<b>{_safe(finding.get('Severity'))} - CVSS {_safe(finding.get('CVSS'))}</b>: "
                    f"{_safe(finding.get('Finding'))}"
                    f" on {_safe(finding.get('Host') or asset.get('ip'))} "
                    f"({_safe(finding.get('Port'))})"
                    f" - {_safe(engine_label)}",
                    styles["Body"],
                )
            )
            story.append(Spacer(1, 1.5 * mm))
    else:
        story.append(
            Paragraph(
                f"No vulnerabilities were returned in the stored {scanner} result set.",
                styles["Body"],
            )
        )

    story.append(Paragraph("Detailed vulnerability checklist", styles["SectionTitle"]))
    checklist_header = ["Finding", "Engine", "Severity", "CVSS", "Target / port", "ISO controls"]
    checklist_rows = [checklist_header]
    for finding in findings[:80]:
        engine_label = (
            finding.get("Scanner Engine")
            or finding.get("scanner_engine")
            or finding.get("Scanner")
            or scanner
        )
        target_label = (
            f"{finding.get('Host') or asset.get('ip') or '-'} {finding.get('Port') or ''}".strip()
        )
        checklist_rows.append(
            [
                Paragraph(_safe(finding.get("Finding")), styles["Small"]),
                Paragraph(_safe(engine_label), styles["Small"]),
                Paragraph(_safe(finding.get("Severity")), styles["Small"]),
                Paragraph(_safe(finding.get("CVSS")), styles["Small"]),
                Paragraph(_safe(target_label), styles["Small"]),
                Paragraph(_safe(finding.get("ISO Controls")), styles["Small"]),
            ]
        )
    if len(checklist_rows) == 1:
        checklist_rows.append(
            ["No stored vulnerability findings", scanner, "Info", "0.0", "-", "-"]
        )

    checklist = Table(
        checklist_rows,
        colWidths=[58 * mm, 27 * mm, 18 * mm, 12 * mm, 30 * mm, 29 * mm],
        repeatRows=1,
    )
    checklist.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 7),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PAGE_BG]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(checklist)

    story.append(PageBreak())
    story.append(Paragraph("Asset and exposure context", styles["SectionTitle"]))
    exposure_rows = [
        ["MAC address", _safe(asset.get("mac_address"))],
        ["Manufacturer", _safe(asset.get("manufacturer"))],
        ["Open ports / services", _safe(asset.get("open_ports"))],
        ["Detected products", _safe(asset.get("products"))],
        ["Owner", _safe(asset.get("owner"))],
        ["Location", _safe(asset.get("location"))],
        ["VLAN", _safe(asset.get("vlan_id") or asset.get("vlan_name"))],
        ["Information classification", _safe(asset.get("information_classification"))],
    ]
    exposure = Table(exposure_rows, colWidths=[47 * mm, 127 * mm])
    exposure.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(exposure)

    story.append(Paragraph("Assessment coverage", styles["SectionTitle"]))
    if engine_records:
        coverage_rows = [["Engine", "Scan date", "Findings", "Profile / source"]]
        for item in engine_records:
            coverage_rows.append(
                [
                    Paragraph(_safe(item.get("engine")), styles["Small"]),
                    Paragraph(_safe(item.get("scanned_at")), styles["Small"]),
                    Paragraph(_safe(item.get("findings_count")), styles["Small"]),
                    Paragraph(
                        _safe(item.get("profile_name") or item.get("source_format")),
                        styles["Small"],
                    ),
                ]
            )
        coverage_table = Table(
            coverage_rows, colWidths=[38 * mm, 48 * mm, 20 * mm, 68 * mm], repeatRows=1
        )
        coverage_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_SLATE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PAGE_BG]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(coverage_table)
    else:
        story.append(
            Paragraph(
                f"This report contains the finalized {scanner} result set for the selected asset.",
                styles["Body"],
            )
        )

    story.append(Paragraph("Detailed findings and remediation", styles["SectionTitle"]))
    if not findings:
        story.append(
            Paragraph(
                "No detailed vulnerability records are available for this report.", styles["Body"]
            )
        )
    else:
        for index, finding in enumerate(findings[:50], start=1):
            sev = str(finding.get("Severity") or "Info")
            sev_color = SEVERITY_COLORS.get(sev, INFO)
            heading = Table(
                [[Paragraph(f"{index}. {_safe(finding.get('Finding'))}", styles["FindingTitle"])]],
                colWidths=[174 * mm],
            )
            heading.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.Color(
                                sev_color.red, sev_color.green, sev_color.blue, alpha=0.10
                            ),
                        ),
                        ("BOX", (0, 0), (-1, -1), 0.7, sev_color),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            detail_table = Table(
                [
                    [
                        "Severity",
                        sev,
                        "CVSS",
                        _safe(finding.get("CVSS")),
                        "Engine",
                        _safe(
                            finding.get("Scanner Engine")
                            or finding.get("scanner_engine")
                            or finding.get("Scanner")
                            or scanner
                        ),
                    ],
                    [
                        "Host",
                        _safe(finding.get("Host")),
                        "Port",
                        _safe(finding.get("Port")),
                        "CVE",
                        _safe(finding.get("CVE")),
                    ],
                    [
                        "ISO controls",
                        Paragraph(_safe(finding.get("ISO Controls")), styles["Small"]),
                        "",
                        "",
                        "",
                        "",
                    ],
                ],
                colWidths=[18 * mm, 30 * mm, 13 * mm, 20 * mm, 13 * mm, 80 * mm],
            )
            detail_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), PAGE_BG),
                        ("BACKGROUND", (2, 0), (2, 1), PAGE_BG),
                        ("BACKGROUND", (4, 0), (4, 1), PAGE_BG),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (2, 0), (2, 1), "Helvetica-Bold"),
                        ("FONTNAME", (4, 0), (4, 1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.3),
                        ("SPAN", (1, 2), (5, 2)),
                        ("GRID", (0, 0), (-1, -1), 0.3, LIGHT_SLATE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            body = [
                heading,
                Spacer(1, 1.5 * mm),
                detail_table,
                Spacer(1, 2 * mm),
                Paragraph("<b>Description</b>", styles["Body"]),
                Paragraph(_safe(finding.get("Description")), styles["Body"]),
                Spacer(1, 1.5 * mm),
                Paragraph("<b>Recommended remediation</b>", styles["Body"]),
                Paragraph(_safe(finding.get("Solution")), styles["Body"]),
                Spacer(1, 4 * mm),
            ]
            story.append(KeepTogether(body))

    story.append(Paragraph("Prioritized recommendations", styles["SectionTitle"]))
    recommendations = []
    for finding in sorted(findings, key=lambda item: float(item.get("CVSS") or 0), reverse=True):
        solution = str(finding.get("Solution") or "").strip()
        if solution and solution not in recommendations:
            recommendations.append(solution)
    if recommendations:
        story.extend(_paragraph_list(recommendations[:15], styles))
    else:
        story.append(
            Paragraph(
                "Maintain the current vulnerability management cycle, confirm scan coverage, "
                "review exposed services and schedule periodic re-tests.",
                styles["Body"],
            )
        )

    story.append(Paragraph("ISO/IEC 27001:2022 evidence references", styles["SectionTitle"]))
    iso_controls = []
    for finding in findings:
        for mapping in finding.get("ISO Mapping") or []:
            value = f"{mapping.get('id')} - {mapping.get('name')}"
            if value not in iso_controls:
                iso_controls.append(value)
    if iso_controls:
        story.extend(_paragraph_list(iso_controls[:25], styles))
    else:
        story.append(
            Paragraph(
                "No finding-specific ISO mappings are available. Review asset inventory, "
                "scan coverage and operational evidence in the SecureScope ISO Mapping workspace.",
                styles["Body"],
            )
        )

    story.append(Paragraph("Assessment limitations", styles["SectionTitle"]))
    story.append(
        Paragraph(
            f"This report is based on the stored {scanner} result set and available asset context. "
            "A clean scan does not prove that every security control is implemented. Findings may "
            "require manual validation, authenticated testing, configuration "
            "review and business-context analysis.",
            styles["Body"],
        )
    )

    doc.build(
        story,
        onFirstPage=lambda c, d: _header_footer(c, d, client_name),
        onLaterPages=lambda c, d: _header_footer(c, d, client_name),
    )
    return buffer.getvalue()


def report_filename(record: Dict[str, Any]) -> str:
    asset = dict(record.get("asset") or {})
    tag = _slug(asset.get("asset_tag") or "asset")
    ip = _slug(record.get("asset_ip") or asset.get("ip") or "unknown")
    report_id = _slug(str(record.get("report_id") or "report")[:18])
    return f"SecureScope_{tag}_{ip}_{report_id}.pdf"


def save_asset_report_pdf(
    record: Dict[str, Any],
    client_name: str,
    output_root: str | os.PathLike[str] = "reports",
) -> Path:
    output_dir = (
        Path(output_root) / _slug(client_name) / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / report_filename(record)
    path.write_bytes(generate_asset_report_pdf(record, client_name))
    return path


def build_reports_zip(report_paths: Iterable[str | os.PathLike[str]]) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for raw_path in report_paths:
            path = Path(raw_path)
            if path.exists() and path.is_file():
                archive.write(path, arcname=path.name)
    return buffer.getvalue()
