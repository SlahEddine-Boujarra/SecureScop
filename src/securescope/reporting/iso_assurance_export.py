"""Excel workbook export for ISO gap, SoA, audit and risk workspaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from io import BytesIO
from typing import Any

from openpyxl import Workbook
from openpyxl.chart import BarChart, RadarChart, Reference
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from securescope.grc.gap_dashboard import area_summaries, dashboard_entries
from securescope.grc.risk_register import risk_row_with_scores
from securescope.reporting.spreadsheet_safety import spreadsheet_text

TEAL = "00685F"
TEAL_LIGHT = "DDEFEF"
NAVY = "142033"
MUTED = "667085"
GRID = "D9E2EC"
AMBER = "F4B740"
RED = "D94841"
GREEN = "4C9F70"
BLUE = "3C78D8"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _text(value: Any) -> str:
    """Return a spreadsheet-safe display string."""

    return spreadsheet_text(value)


def _style_title(sheet: Any, title: str, subtitle: str, width: int) -> None:
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=width)
    sheet.cell(1, 1).value = spreadsheet_text(title)
    sheet.cell(1, 1).font = Font(name="Aptos Display", size=16, bold=True, color="FFFFFF")
    sheet.cell(1, 1).fill = PatternFill("solid", fgColor=TEAL)
    sheet.cell(1, 1).alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 28
    sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=width)
    sheet.cell(2, 1).value = spreadsheet_text(subtitle)
    sheet.cell(2, 1).font = Font(name="Aptos", size=10, italic=True, color=MUTED)
    sheet.cell(2, 1).alignment = Alignment(wrap_text=True, vertical="top")
    sheet.row_dimensions[2].height = 30
    sheet.sheet_view.showGridLines = False


def _write_table(
    sheet: Any,
    start_row: int,
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    table_name: str,
) -> int:
    """Write a styled, filterable table and return its final row."""

    for col, header in enumerate(headers, start=1):
        cell = sheet.cell(start_row, col, header)
        cell.font = Font(name="Aptos", size=10, bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=TEAL)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    sheet.row_dimensions[start_row].height = 32
    for row_index, values in enumerate(rows, start=start_row + 1):
        for col, value in enumerate(values, start=1):
            if isinstance(value, str):
                value = spreadsheet_text(value)
            cell = sheet.cell(row_index, col, value)
            if isinstance(value, str):
                cell.data_type = "s"
            cell.font = Font(name="Aptos", size=10, color=NAVY)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = Border(bottom=Side(style="hair", color=GRID))
    end_row = start_row + max(len(rows), 1)
    if rows:
        ref = f"A{start_row}:{get_column_letter(len(headers))}{end_row}"
        table = Table(displayName=table_name, ref=ref)
        table.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        sheet.add_table(table)
    for col in range(1, len(headers) + 1):
        sheet.column_dimensions[get_column_letter(col)].width = min(
            42,
            max(
                12,
                max(
                    [len(_text(headers[col - 1]))] + [len(_text(row[col - 1])) for row in rows[:30]]
                )
                + 2,
            ),
        )
    sheet.freeze_panes = f"A{start_row + 1}"
    return end_row


def _set_percent(sheet: Any, cell_range: str) -> None:
    sheet[cell_range].number_format = "0%"


def _add_gap_sheet(workbook: Workbook, gap_rows: Sequence[Mapping[str, Any]]) -> None:
    sheet = workbook.create_sheet("Gap Dashboard")
    _style_title(
        sheet,
        "ISO/IEC 27001 Gap Assessment dashboard",
        (
            "Conformity is calculated from the current client-scoped "
            "assessment register. Charts are native Excel objects and update "
            "when the source table is edited."
        ),
        8,
    )
    entries = dashboard_entries(gap_rows)
    areas = area_summaries(entries)
    headers = (
        "Area of standard",
        "Entries",
        "In scope",
        "Met",
        "Partial",
        "Not met",
        "Not assessed",
        "Conformity",
    )
    rows: list[list[Any]] = []
    for area in areas:
        rows.append(
            [
                area["area"],
                area["entries"],
                area["in_scope"],
                area["met"],
                area["partial"],
                area["not_met"],
                area["not_assessed"],
                None,
            ]
        )
    total_row = 5 + len(rows)
    end_row = _write_table(sheet, 4, headers, rows, "GapSummary")
    for row_number in range(5, end_row + 1):
        sheet.cell(row_number, 8).value = f'=IF(C{row_number}=0,"",D{row_number}/C{row_number})'
        _set_percent(sheet, f"H{row_number}")
    sheet.cell(total_row, 1).value = "Total"
    for col in range(2, 8):
        letter = get_column_letter(col)
        sheet.cell(total_row, col).value = f"=SUM({letter}5:{letter}{end_row})"
    sheet.cell(total_row, 8).value = f'=IF(C{total_row}=0,"",D{total_row}/C{total_row})'
    _set_percent(sheet, f"H{total_row}")
    for cell in sheet[total_row]:
        cell.font = Font(name="Aptos", bold=True, color=NAVY)
        cell.fill = PatternFill("solid", fgColor=TEAL_LIGHT)
    sheet.column_dimensions["A"].width = 36
    sheet.column_dimensions["H"].width = 15
    chart = BarChart()
    chart.type = "bar"
    chart.style = 10
    chart.title = "Entries in scope and met by area"
    chart.y_axis.title = "Area"
    chart.x_axis.title = "Count"
    chart.add_data(
        Reference(sheet, min_col=3, max_col=4, min_row=4, max_row=end_row), titles_from_data=True
    )
    chart.set_categories(Reference(sheet, min_col=1, min_row=5, max_row=end_row))
    chart.height = 8
    chart.width = 15
    sheet.add_chart(chart, "J4")
    radar = RadarChart()
    radar.title = "Percentage level of conformity"
    radar.style = 26
    radar.add_data(Reference(sheet, min_col=8, min_row=4, max_row=end_row), titles_from_data=True)
    radar.set_categories(Reference(sheet, min_col=1, min_row=5, max_row=end_row))
    radar.height = 8
    radar.width = 15
    sheet.add_chart(radar, "J21")


def _soa_area(control_id: str) -> str:
    return (
        control_id.split(".", 2)[0] + "." + control_id.split(".", 2)[1]
        if control_id.startswith("A.")
        else "Other"
    )


def _add_soa_sheets(workbook: Workbook, soa_rows: Sequence[Mapping[str, Any]]) -> None:
    sheet = workbook.create_sheet("SoA Dashboard")
    _style_title(
        sheet,
        "Statement of Applicability results",
        (
            "Applicable and implemented counts are calculated from the "
            "control-level SoA register. A Not applicable decision must retain"
            " an exclusion justification and approval."
        ),
        7,
    )
    categories = (
        ("A.5", "Organizational controls"),
        ("A.6", "People controls"),
        ("A.7", "Physical controls"),
        ("A.8", "Technological controls"),
    )
    grouped: dict[str, list[Mapping[str, Any]]] = {code: [] for code, _ in categories}
    for row in soa_rows:
        grouped.setdefault(_soa_area(_text(row.get("control_id"))), []).append(row)
    headers = (
        "Area of standard",
        "No of controls",
        "Applicable",
        "% applicable",
        "Implemented",
        "% applicable implemented",
    )
    rows: list[list[Any]] = []
    for code, label in categories:
        group = grouped.get(code, [])
        applicable = [row for row in group if _text(row.get("applicability")) != "Not applicable"]
        implemented = [
            row
            for row in applicable
            if _text(row.get("implementation_status")).lower()
            in {"implemented", "implemented and effective", "effective", "met"}
        ]
        rows.append([f"{code} {label}", len(group), len(applicable), None, len(implemented), None])
    end_row = _write_table(sheet, 4, headers, rows, "SoASummary")
    for row_number in range(5, end_row + 1):
        sheet.cell(row_number, 4).value = f'=IF(B{row_number}=0,"",C{row_number}/B{row_number})'
        sheet.cell(row_number, 6).value = f'=IF(C{row_number}=0,"",E{row_number}/C{row_number})'
        _set_percent(sheet, f"D{row_number}")
        _set_percent(sheet, f"F{row_number}")
    total_row = end_row + 1
    sheet.cell(total_row, 1).value = "Total"
    for col in (2, 3, 5):
        letter = get_column_letter(col)
        sheet.cell(total_row, col).value = f"=SUM({letter}5:{letter}{end_row})"
    sheet.cell(total_row, 4).value = f'=IF(B{total_row}=0,"",C{total_row}/B{total_row})'
    sheet.cell(total_row, 6).value = f'=IF(C{total_row}=0,"",E{total_row}/C{total_row})'
    _set_percent(sheet, f"D{total_row}")
    _set_percent(sheet, f"F{total_row}")
    for cell in sheet[total_row]:
        cell.font = Font(name="Aptos", bold=True, color=NAVY)
        cell.fill = PatternFill("solid", fgColor=TEAL_LIGHT)
    chart = BarChart()
    chart.type = "col"
    chart.title = "Annex A controls applicable and implemented"
    chart.y_axis.title = "Control count"
    chart.add_data(
        Reference(sheet, min_col=3, max_col=5, min_row=4, max_row=end_row), titles_from_data=True
    )
    chart.set_categories(Reference(sheet, min_col=1, min_row=5, max_row=end_row))
    chart.height = 8
    chart.width = 16
    sheet.add_chart(chart, "H4")
    radar = RadarChart()
    radar.title = "Percentage of controls applicable and implemented"
    radar.add_data(
        Reference(sheet, min_col=4, max_col=6, min_row=4, max_row=end_row), titles_from_data=True
    )
    radar.set_categories(Reference(sheet, min_col=1, min_row=5, max_row=end_row))
    radar.height = 8
    radar.width = 16
    sheet.add_chart(radar, "H21")

    register = workbook.create_sheet("SoA Register")
    register_headers = (
        "Control",
        "Control name",
        "Necessary",
        "Applicability",
        "Inclusion justification",
        "Exclusion justification",
        "Implementation status",
        "Owner",
        "Related risks",
        "Treatment plans",
        "Evidence",
        "Effectiveness review",
        "Approved",
    )
    register_rows = []
    for row in soa_rows:
        register_rows.append(
            [
                row.get("control_id"),
                row.get("control_name"),
                bool(row.get("necessary_control", True)),
                row.get("applicability"),
                row.get("inclusion_justification"),
                row.get("exclusion_justification"),
                row.get("implementation_status"),
                row.get("control_owner"),
                row.get("related_risks"),
                row.get("related_treatment_plans"),
                row.get("evidence"),
                row.get("effectiveness_review"),
                bool(row.get("approved")),
            ]
        )
    _write_table(register, 4, register_headers, register_rows, "SoARegister")
    register.column_dimensions["B"].width = 44
    for col in (5, 6, 9, 10, 11, 12):
        register.column_dimensions[get_column_letter(col)].width = 36


def _add_audit_sheets(
    workbook: Workbook,
    audit_scope: Mapping[str, Any] | None,
    schedule_rows: Sequence[Mapping[str, Any]],
) -> None:
    scope = workbook.create_sheet("Audit Scope")
    _style_title(
        scope,
        "Scope of audit",
        (
            "Use this sheet to define the audit boundary, criteria, sites, "
            "processes and systems before assigning the annual schedule."
        ),
        4,
    )
    fields = (
        ("Audit no", "audit_no"),
        ("Audit year", "audit_year"),
        ("Status", "status"),
        ("Scope statement", "scope_statement"),
        ("Objectives", "objectives"),
        ("Criteria", "criteria"),
        ("Sites", "sites"),
        ("Processes", "processes"),
        ("Systems", "systems"),
        ("Exclusions", "exclusions"),
        ("Lead auditor", "lead_auditor"),
        ("Planned start", "planned_start"),
        ("Planned end", "planned_end"),
        ("Approved by", "approved_by"),
        ("Approval comment", "approval_comment"),
    )
    for index, (label, key) in enumerate(fields, start=4):
        scope.cell(index, 1).value = label
        scope.cell(index, 1).font = Font(bold=True, color=NAVY)
        scope.cell(index, 2).value = _text((audit_scope or {}).get(key))
        scope.cell(index, 2).alignment = Alignment(wrap_text=True, vertical="top")
        scope.cell(index, 2).fill = PatternFill("solid", fgColor="F7FAFC")
        scope.merge_cells(start_row=index, start_column=2, end_row=index, end_column=4)
        scope.row_dimensions[index].height = (
            30 if key in {"scope_statement", "objectives", "exclusions", "approval_comment"} else 20
        )
    scope.column_dimensions["A"].width = 24
    for col in ("B", "C", "D"):
        scope.column_dimensions[col].width = 28
    schedule = workbook.create_sheet("Audit Schedule")
    _style_title(
        schedule,
        "Annual audit schedule",
        (
            "Assign an audit number and month marker to each clause or Annex A"
            " area. Use short markers such as Planned, Fieldwork, Review or "
            "Closed."
        ),
        16,
    )
    headers = ("Scope of audit", "Audit no", *MONTHS, "Notes")
    rows = []
    for row in schedule_rows:
        rows.append(
            [
                f"{row.get('iso_ref') or ''} {row.get('row_label') or ''}".strip(),
                row.get("audit_no") or "",
                *[row.get(month.lower()) or "" for month in MONTHS],
                row.get("notes") or "",
            ]
        )
    end_row = _write_table(schedule, 4, headers, rows, "AuditSchedule")
    schedule.column_dimensions["A"].width = 58
    schedule.column_dimensions["P"].width = 34
    for row_number, source in enumerate(schedule_rows, start=5):
        if source.get("row_type") in {"section", "control_family"}:
            for col in range(1, 17):
                schedule.cell(row_number, col).fill = PatternFill("solid", fgColor=TEAL_LIGHT)
                schedule.cell(row_number, col).font = Font(bold=True, color=NAVY)
    schedule.auto_filter.ref = f"A4:P{end_row}"


def _add_risk_sheet(workbook: Workbook, risks: Sequence[Mapping[str, Any]]) -> None:
    sheet = workbook.create_sheet("Risk Register")
    _style_title(
        sheet,
        "Risk description, treatment plan and post-treatment assessment",
        (
            "Risk score = likelihood × impact on a 1–5 scale. Empty "
            "post-treatment values remain Not assessed until a human reviewer "
            "records the residual risk."
        ),
        31,
    )
    headers = (
        "Ref",
        "Asset group",
        "Sub-category",
        "Asset",
        "Threat",
        "Vulnerability",
        "Risk type",
        "Risk owner",
        "Existing controls",
        "Pre likelihood",
        "Pre likelihood rationale",
        "Pre impact",
        "Pre impact rationale",
        "Pre risk score",
        "Pre risk level",
        "Treatment option",
        "Proposed treatment action",
        "Annex A / control reference",
        "Treatment cost",
        "Action owner",
        "Timescale",
        "Progress",
        "Action status",
        "Post likelihood",
        "Post likelihood rationale",
        "Post impact",
        "Post impact rationale",
        "Post risk score",
        "Post risk level",
        "Comments",
    )
    rows = []
    for raw in risks:
        row = risk_row_with_scores(raw)
        refs = row.get("control_references") or []
        rows.append(
            [
                row.get("risk_ref"),
                row.get("asset_group"),
                row.get("asset_subcategory"),
                row.get("asset"),
                row.get("threat"),
                row.get("vulnerability"),
                row.get("risk_type"),
                row.get("risk_owner"),
                row.get("existing_controls"),
                row.get("pre_likelihood"),
                row.get("pre_likelihood_rationale"),
                row.get("pre_impact"),
                row.get("pre_impact_rationale"),
                None,
                None,
                row.get("treatment_option"),
                row.get("treatment_action"),
                ", ".join(map(str, refs)),
                row.get("treatment_cost"),
                row.get("treatment_action_owner"),
                row.get("treatment_action_timescale"),
                row.get("treatment_action_progress"),
                row.get("treatment_action_status"),
                row.get("post_likelihood"),
                row.get("post_likelihood_rationale"),
                row.get("post_impact"),
                row.get("post_impact_rationale"),
                None,
                None,
                row.get("comments"),
            ]
        )
    end_row = _write_table(sheet, 4, headers, rows, "RiskRegister")
    for row_number in range(5, end_row + 1):
        sheet.cell(row_number, 14).value = (
            f'=IF(OR(J{row_number}="",L{row_number}=""),"",J{row_number}*L{row_number})'
        )
        sheet.cell(row_number, 15).value = (
            "=IF(N"
            f"{row_number}"
            '="","",IF(N'
            f"{row_number}"
            '<=4,"Low",IF(N'
            f"{row_number}"
            '<=9,"Medium",IF(N'
            f"{row_number}"
            '<=16,"High","Critical"))))'
        )
        sheet.cell(row_number, 28).value = (
            f'=IF(OR(X{row_number}="",Z{row_number}=""),"",X{row_number}*Z{row_number})'
        )
        sheet.cell(row_number, 29).value = (
            "=IF(AB"
            f"{row_number}"
            '="","",IF(AB'
            f"{row_number}"
            '<=4,"Low",IF(AB'
            f"{row_number}"
            '<=9,"Medium",IF(AB'
            f"{row_number}"
            '<=16,"High","Critical"))))'
        )
        sheet.cell(row_number, 19).number_format = "#,##0.00"
    for col in (5, 6, 11, 13, 17, 21, 22, 25, 27, 30):
        sheet.column_dimensions[get_column_letter(col)].width = 34
    sheet.column_dimensions["A"].width = 8
    sheet.column_dimensions["D"].width = 22
    sheet.column_dimensions["N"].width = 13
    sheet.column_dimensions["O"].width = 14
    sheet.column_dimensions["AB"].width = 14
    sheet.column_dimensions["AC"].width = 15
    summary = workbook.create_sheet("Risk Charts")
    _style_title(
        summary,
        "Risk treatment dashboard",
        (
            "Charts are driven from the Risk Register sheet. Review residual "
            "risk after every treatment decision."
        ),
        8,
    )
    summary_headers = ("Risk level", "Pre-treatment", "Post-treatment")
    summary_rows = [[level, None, None] for level in ("Low", "Medium", "High", "Critical")]
    _write_table(summary, 4, summary_headers, summary_rows, "RiskSummary")
    for row_number, level in enumerate(("Low", "Medium", "High", "Critical"), start=5):
        summary.cell(row_number, 2).value = (
            f"=COUNTIF('Risk Register'!$O$5:$O${max(end_row, 5)},A{row_number})"
        )
        summary.cell(row_number, 3).value = (
            f"=COUNTIF('Risk Register'!$AC$5:$AC${max(end_row, 5)},A{row_number})"
        )
    chart = BarChart()
    chart.type = "col"
    chart.title = "Risks by level before and after treatment"
    chart.y_axis.title = "Number of risks"
    chart.add_data(
        Reference(summary, min_col=2, max_col=3, min_row=4, max_row=8), titles_from_data=True
    )
    chart.set_categories(Reference(summary, min_col=1, min_row=5, max_row=8))
    chart.height = 9
    chart.width = 16
    chart.legend.position = "b"
    summary.add_chart(chart, "E4")


def build_iso_assurance_workbook(
    *,
    client_name: str,
    gap_rows: Sequence[Mapping[str, Any]],
    soa_rows: Sequence[Mapping[str, Any]],
    audit_scope: Mapping[str, Any] | None = None,
    schedule_rows: Sequence[Mapping[str, Any]] = (),
    risks: Sequence[Mapping[str, Any]] = (),
) -> bytes:
    """Build a complete ISO assurance workbook with native charts."""

    workbook = Workbook()
    readme = workbook.active
    readme.title = "README"
    _style_title(
        readme,
        f"SecureScope ISO assurance export — {client_name}",
        (
            "Use the tabs in order: scope, annual schedule, control "
            "assessment, SoA, risks and dashboards. Exported data is client "
            "scoped and retains human decision fields."
        ),
        5,
    )
    guidance = [
        (
            "1",
            "Define scope",
            "Record the ISMS/audit boundary, criteria, sites, processes, systems and exclusions.",
        ),
        (
            "2",
            "Plan the audit",
            "Assign audit numbers and month markers to clauses 4–10 and Annex A families.",
        ),
        (
            "3",
            "Assess controls",
            (
                "Review design, implementation, evidence freshness, effectiveness "
                "and authorized validation."
            ),
        ),
        (
            "4",
            "Approve the SoA",
            "Mark controls applicable or not applicable and retain justification and approval.",
        ),
        (
            "5",
            "Treat risk",
            (
                "Record pre-treatment likelihood/impact, treatment action, owner, "
                "progress and residual risk."
            ),
        ),
        (
            "6",
            "Review and improve",
            "Use the charts to focus management review and internal-audit follow-up.",
        ),
    ]
    _write_table(
        readme, 4, ("Step", "Workflow", "What the user records"), guidance, "WorkflowGuide"
    )
    readme.column_dimensions["A"].width = 9
    readme.column_dimensions["B"].width = 24
    readme.column_dimensions["C"].width = 90
    _add_audit_sheets(workbook, audit_scope, schedule_rows)
    _add_soa_sheets(workbook, soa_rows)
    _add_gap_sheet(workbook, gap_rows)
    _add_risk_sheet(workbook, risks)
    return _export_workbook(workbook)


def _export_workbook(workbook: Workbook) -> bytes:
    """Serialize an openpyxl workbook to bytes for Streamlit downloads."""

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
