"""Populate the supplied ISO toolkit workbooks without rebuilding their design.

The toolkit files contain charts, pivot definitions, validation lists and
formula-driven score columns.  Re-saving those files through a high-level
workbook writer can discard unsupported extension parts.  This module therefore
patches only the existing worksheet cell XML while copying every other XLSX
part byte-for-byte.  Formula cells are never targets of a write operation.
"""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from lxml import etree as element_tree
from openpyxl.utils.cell import get_column_letter, range_boundaries, range_to_tuple

from securescope.core.output_sanitizer import display_tool_output
from securescope.grc.document_registers import (
    CALCULATED_FIELDS,
    REGISTER_SCHEMAS,
    normalize_register_rows,
)
from securescope.paths import CONFIG_ROOT
from securescope.reporting.spreadsheet_safety import spreadsheet_text


class TemplateToolkitError(ValueError):
    """The supplied toolkit workbook cannot be safely read or populated."""


@dataclass(frozen=True)
class ToolkitTemplateSpec:
    """Describe one source workbook and its editable worksheet.

    Args:
        kind: SecureScope register identifier.
        filename: Source filename under the configured template directory.
        sheet_name: Worksheet containing user-entered records.
        max_data_rows: Maximum number of row slots supported by the template.
        field_labels: Mapping from SecureScope field names to source headers.
        required_headers: Headers used to identify the worksheet.
    """

    kind: str
    filename: str
    sheet_name: str
    max_data_rows: int
    field_labels: Mapping[str, str]
    required_headers: tuple[str, ...]


_RISK_INPUT_FIELDS = {
    key: label
    for key, label in REGISTER_SCHEMAS["asset_risks"][1].items()
    if key not in CALCULATED_FIELDS
}
_SCENARIO_INPUT_FIELDS = {
    key: label
    for key, label in REGISTER_SCHEMAS["scenario_risks"][1].items()
    if key not in CALCULATED_FIELDS
}
_OPPORTUNITY_INPUT_FIELDS = {
    key: label
    for key, label in REGISTER_SCHEMAS["opportunities"][1].items()
    if key not in CALCULATED_FIELDS
}

TEMPLATE_SPECS: dict[str, ToolkitTemplateSpec] = {
    "asset_risks": ToolkitTemplateSpec(
        kind="asset_risks",
        filename="EXAMPLE_Asset-Based_Risk_Tool.xlsx",
        sheet_name="Risk Assessment",
        max_data_rows=20,
        field_labels=_RISK_INPUT_FIELDS,
        required_headers=("Ref", "Asset", "Threat", "Likelihood", "Impact"),
    ),
    "scenario_risks": ToolkitTemplateSpec(
        kind="scenario_risks",
        filename="EXAMPLE_Scenario-Based_Risk_Tool.xlsx",
        sheet_name="Risk Assessment",
        max_data_rows=20,
        field_labels=_SCENARIO_INPUT_FIELDS,
        required_headers=("Ref", "Risk Summary", "Risk Description", "Likelihood", "Impact"),
    ),
    "opportunities": ToolkitTemplateSpec(
        kind="opportunities",
        filename="EXAMPLE_Opportunity_Assessment_Tool.xlsx",
        sheet_name="Opportunity Assessment",
        max_data_rows=20,
        field_labels=_OPPORTUNITY_INPUT_FIELDS,
        required_headers=(
            "Ref",
            "Opportunity Summary",
            "Opportunity Description",
            "Likelihood",
            "Impact",
        ),
    ),
    "soa": ToolkitTemplateSpec(
        kind="soa",
        filename="EXAMPLE_Statement_of_Applicability.xlsx",
        sheet_name="ISO27001 Annex A Applicability",
        max_data_rows=110,
        field_labels={
            "control": "CONTROL",
            "applicability": "CONTROL APPLICABLE?",
            "implementation_status": "CONTROL IMPLEMENTED?",
            "justification": "JUSTIFICATION FOR INCLUSION OR EXCLUSION",
            "comments": "COMMENTS",
        },
        required_headers=(
            "AREA/SECTION",
            "CONTROL",
            "CONTROL APPLICABLE?",
            "CONTROL IMPLEMENTED?",
        ),
    ),
}

_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
_CELL_REF_PATTERN = re.compile(r"^([A-Z]+)([0-9]+)$")
_CONTROL_PATTERN = re.compile(r"^\s*(A\.\d+(?:\.\d+)?)\s+(.+?)\s*$", re.IGNORECASE)


def normalize_header(value: Any) -> str:
    """Normalize a toolkit header for punctuation-insensitive matching.

    Args:
        value: Header value from an XLSX cell.
    Returns:
        Lowercase alphanumeric header key.
    Raises:
        No exceptions are raised for ordinary values.
    """
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def template_directory() -> Path:
    """Return the configured directory containing source toolkit templates.

    Returns:
        User-configured directory, or the packaged ``config/toolkit_templates``.
    Raises:
        No exceptions are raised.
    """
    return Path(
        os.getenv("SECURESCOPE_TOOLKIT_TEMPLATES_DIR", str(CONFIG_ROOT / "toolkit_templates"))
    ).expanduser()


def template_path(kind: str) -> Path | None:
    """Resolve one toolkit source path without accepting a user path component.

    Args:
        kind: One of ``asset_risks``, ``scenario_risks``, ``opportunities`` or ``soa``.
    Returns:
        Existing source path, or ``None`` when it is not installed.
    Raises:
        TemplateToolkitError: If ``kind`` is not supported.
    """
    spec = TEMPLATE_SPECS.get(kind)
    if spec is None:
        raise TemplateToolkitError(f"Unsupported toolkit document: {kind}.")
    path = (template_directory() / spec.filename).resolve()
    root = template_directory().resolve()
    if root not in path.parents:
        raise TemplateToolkitError("Toolkit template path escaped its configured directory.")
    return path if path.is_file() else None


def _safe_zip_parts(content: bytes) -> dict[str, bytes]:
    """Read bounded XLSX parts and reject malformed or oversized archives."""
    if not content or len(content) > 30_000_000:
        raise TemplateToolkitError("Choose an XLSX workbook smaller than 30 MB.")
    try:
        with ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            if sum(member.file_size for member in members) > 150_000_000:
                raise TemplateToolkitError("The expanded workbook is too large.")
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                raise TemplateToolkitError("The workbook contains duplicate archive members.")
            if any(
                PurePosixPath(member.filename).is_absolute()
                or ".." in PurePosixPath(member.filename).parts
                for member in members
            ):
                raise TemplateToolkitError("The workbook contains an unsafe archive path.")
            return {member.filename: archive.read(member) for member in members}
    except (BadZipFile, OSError, KeyError) as exc:
        raise TemplateToolkitError("The file is not a readable XLSX workbook.") from exc


def _xml_part(parts: Mapping[str, bytes], name: str) -> element_tree.Element:
    """Parse one XML part with a consistent error boundary."""
    try:
        parser = element_tree.XMLParser(
            resolve_entities=False,
            load_dtd=False,
            no_network=True,
        )
        root = element_tree.fromstring(parts[name], parser=parser)
        if root.getroottree().docinfo.doctype:
            raise TemplateToolkitError("Workbook XML must not contain a document type.")
        return root
    except (KeyError, element_tree.XMLSyntaxError) as exc:
        raise TemplateToolkitError(f"The workbook is missing a valid {name} part.") from exc


def _relationship_target(parts: Mapping[str, bytes], relationship_id: str) -> str:
    """Resolve a workbook relationship to a normalized archive member path."""
    root = _xml_part(parts, "xl/_rels/workbook.xml.rels")
    for relationship in root.findall(f"{{{_PACKAGE_REL_NS}}}Relationship"):
        if relationship.get("Id") != relationship_id:
            continue
        target = str(relationship.get("Target") or "")
        if target.startswith("/"):
            return target.lstrip("/")
        return str(PurePosixPath("xl") / target)
    raise TemplateToolkitError("The workbook sheet relationship is missing.")


def _sheet_part(parts: Mapping[str, bytes], sheet_name: str) -> str:
    """Resolve a worksheet name to its XML archive member."""
    root = _xml_part(parts, "xl/workbook.xml")
    sheets = root.find(f"{{{_MAIN_NS}}}sheets")
    if sheets is None:
        raise TemplateToolkitError("The workbook has no worksheets.")
    for sheet in sheets.findall(f"{{{_MAIN_NS}}}sheet"):
        if sheet.get("name") == sheet_name:
            relationship_id = sheet.get(f"{{{_REL_NS}}}id")
            if relationship_id:
                return _relationship_target(parts, relationship_id)
    raise TemplateToolkitError(f"Workbook sheet not found: {sheet_name}.")


def _shared_strings(parts: Mapping[str, bytes]) -> list[str]:
    """Read shared strings used by source headers and template cells."""
    if "xl/sharedStrings.xml" not in parts:
        return []
    root = _xml_part(parts, "xl/sharedStrings.xml")
    values = []
    for item in root.findall(f"{{{_MAIN_NS}}}si"):
        values.append("".join(node.text or "" for node in item.iter(f"{{{_MAIN_NS}}}t")))
    return values


def _cell_value(cell: element_tree.Element, shared: Sequence[str]) -> str:
    """Decode a worksheet cell into text for header and control matching."""
    cell_type = cell.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.iter(f"{{{_MAIN_NS}}}t"))
    value = cell.find(f"{{{_MAIN_NS}}}v")
    if value is None:
        return ""
    raw = value.text or ""
    if cell_type == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError) as exc:
            raise TemplateToolkitError("The workbook contains an invalid shared string.") from exc
    return raw


def _rows(root: element_tree.Element) -> list[element_tree.Element]:
    """Return worksheet rows in document order."""
    sheet_data = root.find(f"{{{_MAIN_NS}}}sheetData")
    return [] if sheet_data is None else list(sheet_data.findall(f"{{{_MAIN_NS}}}row"))


def _header_mapping(
    root: element_tree.Element,
    shared: Sequence[str],
    spec: ToolkitTemplateSpec,
) -> tuple[int, dict[str, str]]:
    """Find the designated input header row and map field names to columns."""
    aliases = {normalize_header(label): key for key, label in spec.field_labels.items()}
    required = {normalize_header(label) for label in spec.required_headers}
    for row in _rows(root):
        row_number = int(row.get("r") or 0)
        if row_number > 80:
            break
        mapping: dict[str, str] = {}
        found_headers: set[str] = set()
        for cell in row.findall(f"{{{_MAIN_NS}}}c"):
            reference = str(cell.get("r") or "")
            match = _CELL_REF_PATTERN.match(reference)
            if not match:
                continue
            header = normalize_header(_cell_value(cell, shared))
            found_headers.add(header)
            field = aliases.get(header)
            if field:
                mapping[field] = match.group(1)
        if required.issubset(found_headers):
            return row_number, mapping
    raise TemplateToolkitError(f"Input headers not found in {spec.sheet_name}.")


def _set_calc_mode(parts: dict[str, bytes]) -> None:
    """Ask spreadsheet applications to recalculate formulas on open."""
    root = _xml_part(parts, "xl/workbook.xml")
    calc = root.find(f"{{{_MAIN_NS}}}calcPr")
    if calc is None:
        calc = element_tree.SubElement(root, f"{{{_MAIN_NS}}}calcPr")
    calc.set("calcMode", "auto")
    calc.set("fullCalcOnLoad", "1")
    calc.set("forceFullCalc", "1")
    parts["xl/workbook.xml"] = element_tree.tostring(root, encoding="utf-8", xml_declaration=True)


def _find_row(root: element_tree.Element, row_number: int) -> element_tree.Element | None:
    """Find one worksheet row by its numeric reference."""
    for row in _rows(root):
        if int(row.get("r") or 0) == row_number:
            return row
    return None


def _find_or_create_cell(
    root: element_tree.Element, column: str, row_number: int
) -> element_tree.Element:
    """Find or append a cell while retaining its existing style attributes."""
    row = _find_row(root, row_number)
    if row is None:
        sheet_data = root.find(f"{{{_MAIN_NS}}}sheetData")
        if sheet_data is None:
            raise TemplateToolkitError("The worksheet has no sheetData section.")
        row = element_tree.SubElement(sheet_data, f"{{{_MAIN_NS}}}row", {"r": str(row_number)})
    reference = f"{column}{row_number}"
    for cell in row.findall(f"{{{_MAIN_NS}}}c"):
        if cell.get("r") == reference:
            return cell
    cell = element_tree.SubElement(row, f"{{{_MAIN_NS}}}c", {"r": reference})
    return cell


def _write_cell(root: element_tree.Element, column: str, row_number: int, value: Any) -> None:
    """Write a safe text/number value and refuse to replace a formula cell."""
    cell = _find_or_create_cell(root, column, row_number)
    formula = cell.find(f"{{{_MAIN_NS}}}f")
    if formula is not None:
        raise TemplateToolkitError(f"Refusing to overwrite formula cell {column}{row_number}.")
    for child in list(cell):
        cell.remove(child)
    cell.attrib.pop("t", None)
    if value is None or (isinstance(value, str) and not value.strip()):
        return
    if isinstance(value, bool):
        value = "Yes" if value else "No"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        element_tree.SubElement(cell, f"{{{_MAIN_NS}}}v").text = str(value)
        return
    text = spreadsheet_text(value)
    cell.set("t", "inlineStr")
    inline = element_tree.SubElement(cell, f"{{{_MAIN_NS}}}is")
    text_node = element_tree.SubElement(inline, f"{{{_MAIN_NS}}}t")
    if text[:1].isspace() or text[-1:].isspace():
        text_node.set(_XML_SPACE, "preserve")
    text_node.text = text


def _display_value(row: Mapping[str, Any], field: str) -> Any:
    """Convert a persisted field to the source workbook's cell value."""
    value = row.get(field)
    if isinstance(value, (list, tuple, set)):
        return "\n".join(str(item) for item in value)
    return value


def _write_register_rows(
    root: element_tree.Element,
    shared: Sequence[str],
    spec: ToolkitTemplateSpec,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    """Patch risk/opportunity input rows and retain all calculated columns."""
    header_row, mapping = _header_mapping(root, shared, spec)
    if len(rows) > spec.max_data_rows:
        raise TemplateToolkitError(
            f"{spec.sheet_name} supports {spec.max_data_rows} records; received {len(rows)}."
        )
    slots = list(range(header_row + 1, header_row + 1 + spec.max_data_rows))
    fields = tuple(mapping)
    for index, row_number in enumerate(slots):
        source = rows[index] if index < len(rows) else {}
        for field in fields:
            _write_cell(root, mapping[field], row_number, _display_value(source, field))


def _soa_rows_by_control(
    root: element_tree.Element,
    shared: Sequence[str],
    control_column: str,
    header_row: int,
) -> dict[str, int]:
    """Index existing Annex A rows by their control identifier."""
    result: dict[str, int] = {}
    for row in _rows(root):
        row_number = int(row.get("r") or 0)
        if row_number <= header_row:
            continue
        for cell in row.findall(f"{{{_MAIN_NS}}}c"):
            if cell.get("r") != f"{control_column}{row_number}":
                continue
            match = _CONTROL_PATTERN.match(_cell_value(cell, shared))
            if match:
                result[match.group(1).upper()] = row_number
            break
    return result


def _write_soa_rows(
    root: element_tree.Element,
    shared: Sequence[str],
    spec: ToolkitTemplateSpec,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    """Patch control decisions by control ID, retaining the source row order."""
    header_row, mapping = _header_mapping(root, shared, spec)
    control_column = mapping["control"]
    controls = _soa_rows_by_control(root, shared, control_column, header_row)
    if not controls:
        raise TemplateToolkitError("The SoA template has no Annex A control rows.")
    source_by_control: dict[str, Mapping[str, Any]] = {}
    for source in rows:
        control_id = str(source.get("control_id") or "").strip().upper()
        if not re.fullmatch(r"A\.\d+(?:\.\d+)?", control_id):
            raise TemplateToolkitError(
                f"Invalid Annex A control identifier: {control_id or 'blank'}."
            )
        if control_id in source_by_control:
            raise TemplateToolkitError(f"Duplicate Annex A control identifier: {control_id}.")
        source_by_control[control_id] = source
    unknown = sorted(set(source_by_control) - set(controls))
    if unknown:
        raise TemplateToolkitError(
            "Controls are not present in the selected template: " + ", ".join(unknown)
        )
    for control_id, row_number in controls.items():
        source = source_by_control.get(control_id, {})
        control_name = str(source.get("control_name") or "").strip()
        control_value = f"{control_id} {control_name}".strip() if source else None
        values = {
            "control": control_value,
            "applicability": (
                "Yes"
                if str(source.get("applicability") or "").casefold() == "applicable"
                else "No" if source else None
            ),
            "implementation_status": (
                {
                    "Implemented": "Yes",
                    "Implemented and effective": "Yes",
                    "Implemented but not verified": "Yes",
                    "Partially implemented": "Partial",
                    "Not implemented": "No",
                }.get(str(source.get("implementation_status") or ""), None)
                if source
                else None
            ),
            "justification": (
                (
                    source.get("inclusion_justification")
                    if str(source.get("applicability") or "").casefold() == "applicable"
                    else source.get("exclusion_justification")
                )
                if source
                else None
            ),
            "comments": (
                "\n".join(
                    filter(
                        None,
                        [
                            str(source.get("effectiveness_review") or ""),
                            (
                                f"Assessment result: {source['implementation_status']}"
                                if source.get("implementation_status")
                                else ""
                            ),
                        ],
                    )
                )
                if source
                else None
            ),
        }
        for field, value in values.items():
            # The control label is a source-template identity.  Preserve it
            # when the client has no corresponding SecureScope row so a
            # partially populated export remains an intelligible Annex A list.
            if field == "control" and not source:
                continue
            _write_cell(root, mapping[field], row_number, value)


def _serialize_parts(
    parts: Mapping[str, bytes], modified: Mapping[str, element_tree.Element]
) -> bytes:
    """Create a ZIP while preserving untouched workbook parts exactly."""
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for name, value in parts.items():
            if name in modified:
                value = element_tree.tostring(
                    modified[name], encoding="utf-8", xml_declaration=True
                )
            archive.writestr(name, value)
    return output.getvalue()


def populate_toolkit_template(
    content: bytes,
    kind: str,
    rows: Sequence[Mapping[str, Any]],
    *,
    recalculate: bool = False,
) -> bytes:
    """Populate a supplied toolkit template while retaining its design parts.

    Args:
        content: Original XLSX bytes, supplied by the user or template directory.
        kind: Toolkit document kind.
        rows: Validated SecureScope records to write into input cells.
        recalculate: Run LibreOffice/soffice and reject formula errors before return.
    Returns:
        Populated XLSX bytes.
    Raises:
        TemplateToolkitError: If schema validation, cell mapping or recalculation fails.
    """
    spec = TEMPLATE_SPECS.get(kind)
    if spec is None:
        raise TemplateToolkitError(f"Unsupported toolkit document: {kind}.")
    source_rows: Sequence[Mapping[str, Any]] = rows
    if kind in REGISTER_SCHEMAS:
        try:
            source_rows = normalize_register_rows(kind, [dict(row) for row in rows])
        except (TypeError, ValueError) as exc:
            raise TemplateToolkitError(f"{spec.sheet_name} data failed validation: {exc}") from exc
    parts = _safe_zip_parts(content)
    sheet_part = _sheet_part(parts, spec.sheet_name)
    root = _xml_part(parts, sheet_part)
    shared = _shared_strings(parts)
    if kind == "soa":
        _write_soa_rows(root, shared, spec, source_rows)
    else:
        _write_register_rows(root, shared, spec, source_rows)
    _set_calc_mode(parts)
    output = _serialize_parts(parts, {sheet_part: root})
    if recalculate:
        output = recalculate_with_soffice(output)
    errors = formula_error_count(output)
    if errors:
        raise TemplateToolkitError(f"The populated workbook contains {errors} formula error(s).")
    return output


def template_bytes(kind: str) -> bytes | None:
    """Read a configured source template for a download or preview.

    Args:
        kind: Toolkit document kind.
    Returns:
        Source bytes, or ``None`` when no template is configured.
    Raises:
        TemplateToolkitError: If the source exists but cannot be read.
    """
    path = template_path(kind)
    if path is None:
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise TemplateToolkitError(f"Toolkit template could not be read: {path.name}.") from exc


def import_soa_template(content: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse SoA rows and return row-level validation messages for review.

    Args:
        content: Original or completed SoA workbook bytes.
    Returns:
        Tuple of normalized rows and non-fatal row-level validation errors.
    Raises:
        TemplateToolkitError: If the workbook is malformed or has no controls.
    """
    spec = TEMPLATE_SPECS["soa"]
    parts = _safe_zip_parts(content)
    sheet_part = _sheet_part(parts, spec.sheet_name)
    root = _xml_part(parts, sheet_part)
    shared = _shared_strings(parts)
    header_row, mapping = _header_mapping(root, shared, spec)
    control_rows = _soa_rows_by_control(root, shared, mapping["control"], header_row)
    if not control_rows:
        raise TemplateToolkitError("The SoA template has no Annex A control rows.")
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for control_id, row_number in sorted(control_rows.items(), key=lambda item: item[1]):
        row_element = _find_row(root, row_number)
        row_cells = row_element.findall(f"{{{_MAIN_NS}}}c") if row_element is not None else []
        cells = {
            field: _cell_value(
                next(
                    (cell for cell in row_cells if cell.get("r") == f"{column}{row_number}"),
                    element_tree.Element(f"{{{_MAIN_NS}}}c"),
                ),
                shared,
            )
            for field, column in mapping.items()
        }
        control_match = _CONTROL_PATTERN.match(cells.get("control", ""))
        if not control_match:
            errors.append(f"Row {row_number}: control name is missing or invalid.")
            continue
        applicability_text = cells.get("applicability", "").strip().casefold()
        if applicability_text not in {"yes", "no", ""}:
            errors.append(f"Row {row_number} ({control_id}): applicability must be Yes or No.")
        elif not applicability_text:
            errors.append(f"Row {row_number} ({control_id}): applicability is required.")
        applicability = "Applicable" if applicability_text == "yes" else "Not applicable"
        implementation_text = cells.get("implementation_status", "").strip().casefold()
        implementation = {
            "yes": "Implemented",
            "partial": "Partially implemented",
            "no": "Not implemented",
        }.get(implementation_text, "Not assessed")
        justification = cells.get("justification", "").strip()
        if applicability_text == "yes" and not justification:
            errors.append(f"Row {row_number} ({control_id}): inclusion justification is required.")
        if applicability_text == "no" and not justification:
            errors.append(f"Row {row_number} ({control_id}): exclusion justification is required.")
        if applicability_text == "no":
            errors.append(
                (
                    "Row "
                    f"{row_number}"
                    " ("
                    f"{control_id}"
                    "): Not applicable requires human approval in "
                    "SecureScope."
                )
            )
        rows.append(
            {
                "control_id": control_match.group(1).upper(),
                "control_name": control_match.group(2),
                "necessary_control": applicability == "Applicable",
                "applicability": applicability,
                "inclusion_justification": justification if applicability == "Applicable" else "",
                "exclusion_justification": (
                    justification if applicability == "Not applicable" else ""
                ),
                "implementation_status": implementation,
                "effectiveness_review": cells.get("comments", "").strip(),
                "approved": False,
            }
        )
    return rows, errors


def recalculate_with_soffice(content: bytes) -> bytes:
    """Recalculate a workbook in LibreOffice and reject missing formula output.

    Args:
        content: Populated XLSX bytes.
    Returns:
        Recalculated XLSX bytes.
    Raises:
        TemplateToolkitError: If soffice is unavailable, fails, times out, or
            produces formula errors.
    """
    executable = (
        os.getenv("SECURESCOPE_SOFFICE_PATH")
        or shutil.which("soffice")
        or shutil.which("libreoffice")
    )
    if not executable:
        raise TemplateToolkitError(
            "LibreOffice (soffice) is required to recalculate this toolkit before download."
        )
    with tempfile.TemporaryDirectory(prefix="securescope-toolkit-") as directory:
        root = Path(directory)
        source = root / "source.xlsx"
        output_directory = root / "recalculated"
        output_directory.mkdir()
        source.write_bytes(content)
        profile = root / "profile"
        command = [
            executable,
            "--headless",
            f"-env:UserInstallation={profile.as_uri()}",
            "--convert-to",
            "xlsx",
            "--outdir",
            str(output_directory),
            str(source),
        ]
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=45,
            )
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            UnicodeError,
        ) as exc:
            raise TemplateToolkitError(
                "LibreOffice could not recalculate the toolkit workbook."
            ) from exc
        result = output_directory / "source.xlsx"
        if not result.is_file():
            detail = display_tool_output(completed.stderr or completed.stdout, 400)
            raise TemplateToolkitError(
                f"LibreOffice did not produce a recalculated workbook. {detail}"
            )
        recalculated = result.read_bytes()
    try:
        validate_recalculated_template(content, recalculated)
    except TemplateToolkitError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise TemplateToolkitError(
            "The recalculated workbook contains unverifiable metadata."
        ) from exc
    return recalculated


def _formula_snapshot(parts: Mapping[str, bytes]) -> dict[str, tuple]:
    """Index exact formula definitions, including shared-formula attributes."""
    formulas = {}
    for name in parts:
        if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
            continue
        for cell in _xml_part(parts, name).iter(f"{{{_MAIN_NS}}}c"):
            formula = cell.find(f"{{{_MAIN_NS}}}f")
            if formula is not None:
                formulas[f"{name}!{cell.get('r')}"] = (
                    formula.text or "",
                    tuple(sorted(formula.attrib.items())),
                )
    return formulas


def _object_signature(node: element_tree.Element) -> tuple:
    """Compare object design independently of namespace-prefix spelling."""
    chart_ns = "http://schemas.openxmlformats.org/drawingml/2006/chart"
    cache_tags = {f"{{{chart_ns}}}numCache", f"{{{chart_ns}}}strCache"}
    return (
        node.tag,
        tuple(sorted(node.attrib.items())),
        (node.text or "").strip(),
        tuple(_object_signature(child) for child in node if child.tag not in cache_tags),
    )


def _resolve_part(owner: str, target: str) -> str:
    """Resolve an internal OPC relationship relative to its owning part."""
    name = posixpath.normpath(
        target.lstrip("/")
        if target.startswith("/")
        else posixpath.join(posixpath.dirname(owner), target)
    )
    if name.startswith("../"):
        raise TemplateToolkitError("Workbook relationship escaped the archive.")
    return name


def _relationships(parts: Mapping[str, bytes], owner: str) -> dict[str, str]:
    """Read only internal relationships belonging to one workbook part."""
    name = posixpath.join(
        posixpath.dirname(owner),
        "_rels",
        posixpath.basename(owner) + ".rels",
    )
    if name not in parts:
        return {}
    return {
        item.get("Id"): _resolve_part(owner, item.get("Target", ""))
        for item in _xml_part(parts, name)
        if item.get("TargetMode") != "External"
    }


def _normalized_cache_value(kind: str, value: str | None) -> object:
    """Normalize numeric/blank cache values without changing text semantics."""
    if kind == "m" or value is None or value == "":
        return None
    if kind in {"n", "b"}:
        try:
            number = Decimal(value)
        except InvalidOperation as exc:
            raise TemplateToolkitError("A workbook cache contains an invalid number.") from exc
        if not number.is_finite():
            raise TemplateToolkitError("A workbook cache contains a non-finite number.")
        return number
    return value


def _validate_pivot_caches(parts: Mapping[str, bytes]) -> None:
    """Reject pivot caches whose records differ from their worksheet source.

    Args:
        parts: Recalculated XLSX archive members.
    Returns:
        None after every supported worksheet/table cache matches its inputs.
    Raises:
        TemplateToolkitError: For stale, missing, or unsupported pivot caches.
    """
    shared = _shared_strings(parts)
    sheets = {}
    tables = {}
    workbook = _xml_part(parts, "xl/workbook.xml")
    for sheet in workbook.findall(f"{{{_MAIN_NS}}}sheets/{{{_MAIN_NS}}}sheet"):
        name = sheet.get("name", "")
        path = _sheet_part(parts, name)
        root = _xml_part(parts, path)
        sheets[name] = {
            cell.get("r"): _normalized_cache_value(
                "s" if cell.get("t") in {"s", "str", "inlineStr"} else cell.get("t", "n"),
                _cell_value(cell, shared),
            )
            for cell in root.iter(f"{{{_MAIN_NS}}}c")
        }
        relationships = _relationships(parts, path)
        for table in root.findall(f"{{{_MAIN_NS}}}tableParts/{{{_MAIN_NS}}}tablePart"):
            target = relationships.get(table.get(f"{{{_REL_NS}}}id"))
            definition = _xml_part(parts, target or "missing-table")
            bounds = range_boundaries(definition.get("ref", ""))
            table_info = (
                name,
                bounds,
                int(definition.get("totalsRowCount", "0")),
            )
            for key in ("name", "displayName"):
                tables[definition.get(key)] = table_info
    for name in parts:
        if not name.startswith("xl/pivotCache/pivotCacheDefinition") or not name.endswith(".xml"):
            continue
        definition = _xml_part(parts, name)
        source = definition.find(f"{{{_MAIN_NS}}}cacheSource/{{{_MAIN_NS}}}worksheetSource")
        if source is None:
            raise TemplateToolkitError("A pivot uses an unsupported external source.")
        if source.get("name") in tables:
            sheet_name, bounds, totals = tables[source.get("name")]
        elif source.get("sheet") in sheets and source.get("ref"):
            sheet_name = source.get("sheet")
            bounds, totals = range_boundaries(source.get("ref")), 0
        else:
            raise TemplateToolkitError("A pivot source could not be verified after recalculation.")
        left, top, right, bottom = bounds
        expected = [
            [
                sheets[sheet_name].get(f"{get_column_letter(col)}{row}")
                for col in range(left, right + 1)
            ]
            for row in range(top + 1, bottom + 1 - totals)
        ]
        fields = definition.findall(f"{{{_MAIN_NS}}}cacheFields/{{{_MAIN_NS}}}cacheField")
        shared_items = []
        for field in fields:
            items = field.find(f"{{{_MAIN_NS}}}sharedItems")
            shared_items.append(
                []
                if items is None
                else [
                    _normalized_cache_value(element_tree.QName(item).localname, item.get("v"))
                    for item in items
                ]
            )
        records_path = _relationships(parts, name).get(definition.get(f"{{{_REL_NS}}}id"))
        if not records_path:
            raise TemplateToolkitError("A pivot has no saved records to validate.")
        actual = []
        for record in _xml_part(parts, records_path):
            values = []
            for index, item in enumerate(record):
                kind = element_tree.QName(item).localname
                try:
                    value = (
                        shared_items[index][int(item.get("v"))]
                        if kind == "x"
                        else (_normalized_cache_value(kind, item.get("v")))
                    )
                except (IndexError, TypeError, ValueError) as exc:
                    raise TemplateToolkitError("A pivot cache reference is invalid.") from exc
                values.append(value)
            actual.append(values)
        if expected != actual:
            raise TemplateToolkitError(
                "A pivot dashboard still contains stale values after recalculation. "
                "Use the clean data export until pivot refresh is supported on this host."
            )
    _validate_chart_caches(parts, sheets)


def _validate_chart_caches(
    parts: Mapping[str, bytes],
    sheets: Mapping[str, Mapping[str, object]],
) -> None:
    """Verify cached chart values against the referenced recalculated cells.

    Args:
        parts: Recalculated archive members.
        sheets: Worksheet values indexed by sheet name and cell coordinate.
    Returns:
        None when saved numeric and string series match their source ranges.
    Raises:
        TemplateToolkitError: When a cache is absent, stale, or unverifiable.
    """
    namespace = "http://schemas.openxmlformats.org/drawingml/2006/chart"
    for name in parts:
        if not name.startswith("xl/charts/chart") or not name.endswith(".xml"):
            continue
        root = _xml_part(parts, name)
        for kind in ("num", "str"):
            for reference in root.iter(f"{{{namespace}}}{kind}Ref"):
                formula = reference.find(f"{{{namespace}}}f")
                cache = reference.find(f"{{{namespace}}}{kind}Cache")
                if formula is None or not formula.text or cache is None:
                    raise TemplateToolkitError("A chart has no verifiable saved series.")
                try:
                    sheet_name, (left, top, right, bottom) = range_to_tuple(formula.text)
                    values = sheets[sheet_name]
                    expected = [
                        values.get(f"{get_column_letter(col)}{row}")
                        for row in range(top, bottom + 1)
                        for col in range(left, right + 1)
                    ]
                except (ValueError, KeyError) as exc:
                    raise TemplateToolkitError("A chart source could not be verified.") from exc
                cached = {
                    int(point.get("idx", "-1")): _normalized_cache_value(
                        "n" if kind == "num" else "s",
                        point.findtext(f"{{{namespace}}}v"),
                    )
                    for point in cache.findall(f"{{{namespace}}}pt")
                }
                if kind == "str":
                    expected = [None if value is None else str(value) for value in expected]
                if any(index >= len(expected) or index < 0 for index in cached) or any(
                    cached.get(index) != value for index, value in enumerate(expected)
                ):
                    raise TemplateToolkitError(
                        "A chart still contains stale values after recalculation. "
                        "Use the clean data export until chart refresh passes validation."
                    )


def validate_recalculated_template(original: bytes, recalculated: bytes) -> None:
    """Require preserved design, formula results, and refreshed pivot records.

    Args:
        original: Populated workbook before the external recalculation pass.
        recalculated: Output from the recalculation engine.
    Returns:
        None when all preservation and cache checks pass.
    Raises:
        TemplateToolkitError: If an engine loses objects/formulas or leaves stale data.
    """
    before, after = _safe_zip_parts(original), _safe_zip_parts(recalculated)
    if _formula_snapshot(before) != _formula_snapshot(after):
        raise TemplateToolkitError("Recalculation changed or removed template formulas.")
    prefixes = ("xl/charts/", "xl/drawings/", "xl/pivotTables/")
    protected = {name for name in before if name.startswith(prefixes)}
    if protected != {name for name in after if name.startswith(prefixes)}:
        raise TemplateToolkitError("Recalculation changed the template's chart or pivot objects.")
    for name in protected:
        if before[name] == after[name]:
            continue
        if not name.endswith(".xml") or (
            _object_signature(_xml_part(before, name)) != _object_signature(_xml_part(after, name))
        ):
            raise TemplateToolkitError(
                "Recalculation changed the template's chart or pivot design."
            )
    for name in after:
        if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
            continue
        for cell in _xml_part(after, name).iter(f"{{{_MAIN_NS}}}c"):
            if cell.find(f"{{{_MAIN_NS}}}f") is None:
                continue
            cached = cell.find(f"{{{_MAIN_NS}}}v")
            if cached is None or (cached.text is None and cell.get("t") != "str"):
                raise TemplateToolkitError("Recalculation left formula results unavailable.")
    errors = formula_error_count(recalculated)
    if errors:
        raise TemplateToolkitError(f"LibreOffice produced {errors} formula error(s).")
    _validate_pivot_caches(after)


def formula_error_count(content: bytes) -> int:
    """Count cached spreadsheet formula errors in a workbook.

    Args:
        content: XLSX bytes.
    Returns:
        Number of cells marked as spreadsheet errors, including newer tokens.
    Raises:
        TemplateToolkitError: If the workbook is malformed.
    """
    parts = _safe_zip_parts(content)
    count = 0
    for name, value in parts.items():
        if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
            continue
        root = _xml_part(parts, name)
        count += sum(cell.get("t") == "e" for cell in root.iter(f"{{{_MAIN_NS}}}c"))
    return count


def formula_cells(content: bytes) -> set[str]:
    """Return worksheet formula coordinates for fidelity tests and diagnostics.

    Args:
        content: XLSX bytes.
    Returns:
        Set of ``sheet-part!cell`` identifiers containing formulas.
    Raises:
        TemplateToolkitError: If the workbook is malformed.
    """
    parts = _safe_zip_parts(content)
    values: set[str] = set()
    for name, value in parts.items():
        if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
            continue
        root = _xml_part(parts, name)
        for cell in root.iter(f"{{{_MAIN_NS}}}c"):
            if cell.find(f"{{{_MAIN_NS}}}f") is not None:
                values.add(f"{name}!{cell.get('r')}")
    return values
