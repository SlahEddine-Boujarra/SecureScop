"""In-application Excel import/export for the supplied ISMS register layouts."""

from __future__ import annotations

from datetime import date
from io import BytesIO
from typing import Any
from zipfile import BadZipFile, ZipFile

from openpyxl import Workbook, load_workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

from securescope.grc.document_registers import (
    CALCULATED_FIELDS,
    DATE_FIELDS,
    REGISTER_SCHEMAS,
    SCORE_FIELDS,
    clean_cell,
    header_key,
    normalize_register_rows,
)
from securescope.reporting.iso_assurance_export import _style_title, _write_table


def import_register_workbook(content: bytes, kind: str) -> list[dict[str, Any]]:
    """Read either a supplied template or a SecureScope register export.

    Args:
        content: XLSX bytes selected by the user.
        kind: Target document schema.
    Returns:
        Validated records for review before any persistence.
    Raises:
        ValueError: If the workbook is oversized, malformed or has no matching table.
    """
    if len(content) > 20_000_000:
        raise ValueError("Choose a workbook smaller than 20 MB.")
    try:
        with ZipFile(BytesIO(content)) as archive:
            if sum(item.file_size for item in archive.infolist()) > 100_000_000:
                raise ValueError("The expanded workbook is too large.")
        workbook = load_workbook(BytesIO(content), read_only=True, data_only=True)
    except (BadZipFile, OSError, KeyError) as exc:
        raise ValueError("The file is not a readable XLSX workbook.") from exc
    fields = REGISTER_SCHEMAS[kind][1]
    expected = {header_key(label): key for key, label in fields.items()}
    expected.update({header_key(key): key for key in fields})
    matched = []
    table_found = False
    try:
        for sheet in workbook:
            if sheet.max_row > 6000 or sheet.max_column > 120:
                continue
            mapping = None
            for number, values in enumerate(sheet.iter_rows(values_only=True), 1):
                if mapping is None:
                    # CertiKit's supplied workbooks place the table header below
                    # a title and guidance block.  Allow a little more room for
                    # edited copies while still avoiding an unbounded scan.
                    if number > 80:
                        break
                    candidate = {
                        index: expected[header_key(value)]
                        for index, value in enumerate(values)
                        if header_key(value) in expected
                    }
                    if len(candidate) >= min(7, len(fields)):
                        mapping = candidate
                        table_found = True
                    continue
                row = {
                    key: clean_cell(values[index])
                    for index, key in mapping.items()
                    if key not in CALCULATED_FIELDS
                }
                if any(
                    row.get(key)
                    for key in (
                        "threat",
                        "risk_summary",
                        "risk_description",
                        "summary",
                        "description",
                    )
                ):
                    matched.append(row)
            if matched:
                break
    finally:
        workbook.close()
    if not matched and table_found:
        # A supplied template often contains only numbered blank rows.  Treat
        # that as a valid, empty import so the user can start editing in the
        # application instead of receiving a misleading "malformed workbook"
        # error.  The UI presents an informational message for this case.
        return []
    if not matched:
        raise ValueError(
            "No completed records were found for this document. Blank template rows are ignored."
        )
    return normalize_register_rows(kind, matched)


def build_register_workbook(kind: str, rows: list[dict[str, Any]], client_name: str) -> bytes:
    """Export saved records with matching headers, formulas and a native chart.

    Args:
        kind: Document schema identifier.
        rows: Current saved register rows.
        client_name: Workspace displayed in the export.
    Returns:
        Downloadable XLSX bytes.
    Raises:
        ValueError: If records contain invalid fields.
    """
    title, fields = REGISTER_SCHEMAS[kind]
    records = normalize_register_rows(kind, rows)
    book = Workbook()
    sheet = book.active
    sheet.title = "Register"
    _style_title(
        sheet,
        title,
        f"{client_name} · {date.today().isoformat()} · Saved working register",
        len(fields),
    )
    values = []
    for row in records:
        line = []
        for key in fields:
            value = row.get(key)
            if isinstance(value, list):
                value = ", ".join(map(str, value))
            if key in DATE_FIELDS and value:
                value = date.fromisoformat(str(value)[:10])
            line.append(value)
        values.append(line)
    end = _write_table(sheet, 4, list(fields.values()), values, "WorkingRegister")
    positions = {key: index for index, key in enumerate(fields, 1)}
    for key in SCORE_FIELDS.intersection(fields):
        validation = DataValidation(
            type="whole", operator="between", formula1=1, formula2=5, allow_blank=True
        )
        validation.showErrorMessage = True
        sheet.add_data_validation(validation)
        validation.add(
            (
                f"{get_column_letter(positions[key])}"
                "5:"
                f"{get_column_letter(positions[key])}"
                f"{max(1000, end)}"
            )
        )
    for number in range(5, end + 1):
        for key in DATE_FIELDS.intersection(fields):
            sheet.cell(number, positions[key]).number_format = "dd mmm yyyy"
        prefixes = (
            ("pre", "post")
            if kind.endswith("risks")
            else (("",) if kind == "opportunities" else ())
        )
        for prefix in prefixes:
            likelihood, impact, score, level = (
                (
                    f"{prefix}_likelihood",
                    f"{prefix}_impact",
                    f"{prefix}_risk_score",
                    f"{prefix}_risk_level",
                )
                if prefix
                else ("likelihood", "impact", "score", "level")
            )
            left = f"{get_column_letter(positions[likelihood])}{number}"
            right = f"{get_column_letter(positions[impact])}{number}"
            score_cell = f"{get_column_letter(positions[score])}{number}"
            sheet.cell(number, positions[score], f'=IF(OR({left}="",{right}=""),"",{left}*{right})')
            sheet.cell(
                number,
                positions[level],
                (
                    "=IF("
                    f"{score_cell}"
                    '="","Not assessed",IF('
                    f"{score_cell}"
                    '<=4,"Low",IF('
                    f"{score_cell}"
                    '<=9,"Medium",IF('
                    f"{score_cell}"
                    '<=16,"High","Critical"))))'
                ),
            )
    dashboard = book.create_sheet("Dashboard")
    _style_title(
        dashboard,
        title + " results",
        "Missing scores remain Not assessed. Post-treatment scores are estimates until verified.",
        6,
    )
    group_key = (
        "pre_risk_level"
        if kind.endswith("risks")
        else "level" if kind == "opportunities" else "status"
    )
    categories = (
        ["Low", "Medium", "High", "Critical", "Not assessed"]
        if kind != "changes"
        else sorted({str(row.get("status") or "Draft") for row in records}) or ["Draft"]
    )
    _write_table(
        dashboard,
        4,
        ["Level / status", "Records"],
        [[value, 0] for value in categories],
        "RegisterSummary",
    )
    column = get_column_letter(positions[group_key])
    for number in range(5, 5 + len(categories)):
        dashboard.cell(
            number, 2, f"=COUNTIF(Register!${column}$5:${column}${max(end, 5)},A{number})"
        )
    chart = BarChart()
    chart.title = "Records by level" if kind != "changes" else "Changes by status"
    chart.add_data(
        Reference(dashboard, min_col=2, min_row=4, max_row=4 + len(categories)),
        titles_from_data=True,
    )
    chart.set_categories(Reference(dashboard, min_col=1, min_row=5, max_row=4 + len(categories)))
    chart.legend = None
    dashboard.add_chart(chart, "D4")
    output = BytesIO()
    book.save(output)
    return output.getvalue()
