"""Offline regression tests for Greenbone runtime-state extraction.

These tests execute only the XML/evidence helpers from openvas_worker_service.py.
They do not connect to PostgreSQL, SSH, gvmd, or a scanner.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from lxml import etree

ROOT = Path(__file__).resolve().parents[1] / "src" / "securescope"
SOURCE = ROOT / "scanners" / "openvas" / "openvas_worker_service.py"
HELPERS = {
    "first_text",
    "_task_text",
    "_task_report_id",
    "_xpath_first_text",
    "_parse_provider_progress",
    "_task_runtime_snapshot",
    "_report_runtime_snapshot",
    "_merge_runtime_evidence",
}


def load_helpers() -> dict[str, Any]:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in HELPERS
    ]
    module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace: dict[str, Any] = {
        "Any": Any,
        "GMP": object,
        "logger": logging.getLogger("runtime-evidence-test"),
    }
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace


H = load_helpers()


class FakeGMP:
    def __init__(self, xml: str):
        self.response = etree.fromstring(xml.encode("utf-8"))
        self.calls: list[dict[str, Any]] = []

    def get_report(self, report_id: str, **kwargs: Any) -> Any:
        self.calls.append({"report_id": report_id, **kwargs})
        return self.response


def task_xml(status: str, progress: int = 0) -> Any:
    return etree.fromstring(
        f"""
        <get_tasks_response status="200" status_text="OK">
          <task id="task-1">
            <name>test</name>
            <status>{status}</status>
            <progress>{progress}</progress>
            <last_report><report id="report-1"/></last_report>
          </task>
        </get_tasks_response>
        """.encode(
            "utf-8"
        )
    )


def report_xml(
    status: str,
    progress: int = 0,
    scan_start: str = "",
    scan_end: str = "",
) -> str:
    return f"""
    <get_reports_response status="200" status_text="OK">
      <report id="report-1" format_id="xml" extension="xml" content_type="text/xml">
        <report id="report-1">
          <scan_run_status>{status}</scan_run_status>
          <task id="task-1"><progress>{progress}</progress></task>
          <scan_start>{scan_start}</scan_start>
          <scan_end>{scan_end}</scan_end>
        </report>
      </report>
    </get_reports_response>
    """


def test_requested_with_scan_start_becomes_running() -> None:
    task = H["_task_runtime_snapshot"](task_xml("Requested", 0))
    gmp = FakeGMP(
        report_xml(
            "Requested",
            progress=0,
            scan_start="2026-07-22T18:00:00Z",
        )
    )
    report = H["_report_runtime_snapshot"](gmp, "report-1")
    merged = H["_merge_runtime_evidence"](task, report)
    assert merged["task_status"] == "Requested"
    assert merged["report_status"] == "Requested"
    assert merged["effective_status"] == "Running"
    assert merged["progress_source"] == "report.scan_start"
    assert gmp.calls[0]["details"] is True
    assert "rows=0" in gmp.calls[0]["filter_string"]


def test_requested_with_progress_becomes_running() -> None:
    task = H["_task_runtime_snapshot"](task_xml("Requested", 0))
    gmp = FakeGMP(report_xml("Requested", progress=17))
    report = H["_report_runtime_snapshot"](gmp, "report-1")
    merged = H["_merge_runtime_evidence"](task, report)
    assert merged["effective_status"] == "Running"
    assert merged["progress"] == 17
    assert merged["progress_source"] == "provider.progress"


def test_genuine_requested_stays_requested() -> None:
    task = H["_task_runtime_snapshot"](task_xml("Requested", 0))
    gmp = FakeGMP(report_xml("Requested", progress=0))
    report = H["_report_runtime_snapshot"](gmp, "report-1")
    merged = H["_merge_runtime_evidence"](task, report)
    assert merged["effective_status"] == "Requested"
    assert merged["progress"] == 0


def test_report_running_overrides_task_requested() -> None:
    task = H["_task_runtime_snapshot"](task_xml("Requested", 0))
    gmp = FakeGMP(report_xml("Running", progress=4))
    report = H["_report_runtime_snapshot"](gmp, "report-1")
    merged = H["_merge_runtime_evidence"](task, report)
    assert merged["effective_status"] == "Running"
    assert merged["progress"] == 4
    assert merged["progress_source"] == "report.scan_run_status"


def test_scan_end_is_done_even_when_report_label_is_requested() -> None:
    task = H["_task_runtime_snapshot"](task_xml("Requested", 0))
    gmp = FakeGMP(
        report_xml(
            "Requested",
            progress=90,
            scan_start="2026-07-22T18:00:00Z",
            scan_end="2026-07-22T18:30:00Z",
        )
    )
    report = H["_report_runtime_snapshot"](gmp, "report-1")
    merged = H["_merge_runtime_evidence"](task, report)
    assert merged["effective_status"] == "Done"
    assert merged["progress"] == 100


if __name__ == "__main__":
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"{len(tests)} runtime-evidence tests passed")
