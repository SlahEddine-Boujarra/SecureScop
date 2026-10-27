"""ISMS implementation tasks and deterministic weekday scheduling rules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

_ISM = "Information Security Manager"
_TM = "Top Management"
_BR = "Business Representatives"
_IT = "IT Management"
PROJECT_TASKS = (
    (1, "Project initiation", "", "Project Manager"),
    (2, "Define proposed scope of ISMS", "4.3", f"{_TM}, {_ISM}"),
    (3, "Document context of the organization", "4", f"{_ISM}, {_TM}"),
    (4, "Perform gap assessment", "4–10, Annex A", f"{_ISM}, {_BR}"),
    (5, "Obtain top management commitment", "5.1", f"{_ISM}, Project Manager, {_TM}"),
    (6, "Select Registered Certification Body (RCB)", "", _TM),
    (7, "Establish ISMS document control", "7.5", f"{_ISM}, Project Manager"),
    (8, "Agree information security objectives", "6.2", f"{_ISM}, {_TM}"),
    (9, "Define roles, responsibilities and authorities", "5.3", f"{_ISM}, {_TM}"),
    (10, "Competence and training needs assessment", "7.2", f"{_ISM}, {_BR}"),
    (11, "Perform risk assessment", "6.1.2, 8.2", f"{_ISM}, {_TM}, {_IT}"),
    (12, "Create risk treatment plan", "6.1.3, 8.3", f"{_ISM}, {_BR}, {_IT}"),
    (13, "Document Statement of Applicability", "6.1.3", _ISM),
    (14, "Define information security policies", "5.2, A.5.1", f"{_ISM}, {_TM}"),
    (15, "Implement required controls", "6.1.3", f"{_ISM}, {_BR}, {_IT}, {_TM}"),
    (16, "Implement applicable organizational controls", "A.5", f"{_ISM}, {_BR}, {_IT}, {_TM}"),
    (17, "Implement applicable people controls", "A.6", "Human Resources, ICT Management"),
    (18, "Implement applicable physical controls", "A.7", "Facilities Management, ICT Management"),
    (19, "Implement applicable technological controls", "A.8", f"{_ISM}, ICT Management"),
    (20, "Additional controls", "6.1.3", _ISM),
    (21, "Document communications procedures", "7.4", f"{_ISM}, {_BR}"),
    (22, "Define monitoring, measurement, analysis and evaluation", "9.1", f"{_ISM}, {_TM}"),
    (23, "Awareness training", "7.3", f"{_ISM}, {_BR}"),
    (24, "Plan how to manage changes to the ISMS", "6.3", f"{_ISM}, {_TM}"),
    (25, "Establish continual improvement process", "10.1, 10.2", f"{_ISM}, {_TM}"),
    (26, "Internal audit", "9.2", f"{_ISM}, {_BR}, {_IT}, Internal Audit Team"),
    (27, "Perform management review", "9.3", f"{_ISM}, {_TM}"),
    (28, "Certification stage one", "", f"{_ISM}, {_TM}, External Auditor"),
    (29, "Certification stage two", "", f"{_ISM}, {_BR}, External Auditor, {_TM}"),
    (30, "Post Project Review", "", f"Project Manager, {_ISM}, {_TM}"),
)
TASK_METADATA = {row[0]: row for row in PROJECT_TASKS}

# Estimates are editable planning assumptions, never ISO-prescribed deadlines.
TASK_DEPENDENCIES = {
    1: (),
    2: (1,),
    3: (1,),
    4: (2, 3),
    5: (4,),
    6: (5,),
    7: (5,),
    8: (5,),
    9: (5,),
    10: (9,),
    11: (4, 8),
    12: (11,),
    13: (12,),
    14: (7, 13),
    16: (14,),
    17: (10, 14),
    18: (14,),
    19: (14,),
    20: (14,),
    21: (9,),
    22: (13,),
    23: (10, 14),
    24: (7,),
    25: (22,),
    26: (16, 17, 18, 19, 20, 23, 25),
    27: (26,),
    28: (6, 27),
    29: (28,),
    30: (29,),
}
TASK_WORK_DAYS = {
    1: 2,
    2: 3,
    3: 3,
    4: 5,
    5: 2,
    6: 3,
    7: 3,
    8: 2,
    9: 2,
    10: 3,
    11: 5,
    12: 4,
    13: 3,
    14: 5,
    16: 15,
    17: 10,
    18: 10,
    19: 20,
    20: 5,
    21: 3,
    22: 4,
    23: 5,
    24: 2,
    25: 3,
    26: 5,
    27: 2,
    28: 3,
    29: 5,
    30: 1,
}


def next_workday(value: date) -> date:
    """Move a date forward to Monday when it falls on a weekend.

    Args:
        value: Calendar date.
    Returns:
        First Monday–Friday date on or after value.
    Raises:
        TypeError: If value is not a date.
    """
    return value + timedelta(days=max(0, 7 - value.weekday()) if value.weekday() > 4 else 0)


def schedule_project(
    records: Sequence[Mapping[str, Any]],
    start: date,
    *,
    only_unscheduled: bool = True,
    duration_scale: float = 1.0,
) -> list[dict[str, Any]]:
    """Suggest dependency dates while preserving work already started.

    Args:
        records: Current task records, optionally with edited durations.
        start: Project start date; weekends roll forward.
        only_unscheduled: Keep all tasks already assigned a start date.
        duration_scale: Multiplier for missing duration estimates, 0.5–3.
    Returns:
        All task rows with calculated finish dates and dependency references.
    Raises:
        ValueError: If dates or duration assumptions are invalid.
    """
    if not 0.5 <= duration_scale <= 3:
        raise ValueError("Duration multiplier must be between 0.5 and 3.")
    planned: dict[int, dict[str, Any]] = {}
    for row in project_task_rows(records):
        ref = row["task_ref"]
        if ref == 15:
            continue
        row = dict(row)
        dependencies = TASK_DEPENDENCIES[ref]
        row["dependencies"] = ", ".join(map(str, dependencies))
        keep = bool(row["completed_days"] or (only_unscheduled and row["start_date"]))
        if not keep:
            finishes = [planned[item]["end_date"] for item in dependencies]
            if any(finish is None for finish in finishes):
                raise ValueError(f"Schedule the predecessors of task {ref} first.")
            earliest = max(
                [
                    next_workday(start),
                    *[next_workday(finish + timedelta(days=1)) for finish in finishes],
                ]
            )
            row["start_date"] = earliest
            row["work_days"] = row["work_days"] or max(
                1, round(TASK_WORK_DAYS[ref] * duration_scale)
            )
            row["end_date"] = workday_end(earliest, row["work_days"])
        planned[ref] = row
    return project_task_rows(list(planned.values()))


@dataclass(frozen=True)
class ProjectTaskUpdate:
    """Validated editable fields for one task.

    Args:
        resource: Responsible people or roles.
        start_date: Planned first weekday, or None while unscheduled.
        work_days: Planned effort, from zero to 3650 weekdays.
        completed_days: Recorded completed effort, capped by work_days.
        notes: Optional working notes.

    Returns:
        Immutable update object.

    Raises:
        ValueError: On validation of incomplete or inconsistent fields.
    """

    resource: str
    start_date: date | None
    work_days: int
    completed_days: int
    notes: str = ""

    def validate(self) -> None:
        """Validate schedule values before a persistence transaction.

        Returns:
            None.

        Raises:
            ValueError: If text, days or the optional weekday are invalid.
        """

        if not self.resource.strip() or len(self.resource) > 1000:
            raise ValueError("Resource is required and must be at most 1000 characters.")
        if len(self.notes) > 5000:
            raise ValueError("Notes must be at most 5000 characters.")
        if type(self.work_days) is not int or not 0 <= self.work_days <= 3650:
            raise ValueError("Work days must be an integer from 0 to 3650.")
        if type(self.completed_days) is not int or not 0 <= self.completed_days <= self.work_days:
            raise ValueError("Completed days must be between zero and planned work days.")
        if self.completed_days and self.start_date is None:
            raise ValueError("Set a start date before recording completed days.")
        if self.start_date is not None:
            if type(self.start_date) is not date or self.start_date.weekday() >= 5:
                raise ValueError("Start date must be a Monday–Friday date.")
            if not date(2000, 1, 1) <= self.start_date <= date(2100, 12, 31):
                raise ValueError("Start date must be between 2000 and 2100.")


def workday_end(start_date: date | None, work_days: int) -> date | None:
    """Calculate the inclusive finish date using Monday–Friday workdays.

    Args:
        start_date: Optional first workday.
        work_days: Nonnegative number of planned workdays.

    Returns:
        Finish date, or None for an unscheduled or zero-duration task.

    Raises:
        ValueError: If duration or the start weekday is invalid.
    """

    if type(work_days) is not int or work_days < 0:
        raise ValueError("Work days must be a nonnegative integer.")
    if start_date is None or work_days == 0:
        return None
    if start_date.weekday() >= 5:
        raise ValueError("Start date must be a weekday.")
    weeks, remaining = divmod(work_days - 1, 5)
    extra_weekend = 2 if start_date.weekday() + remaining >= 5 else 0
    return start_date + timedelta(days=7 * weeks + remaining + extra_weekend)


def project_task_rows(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge saved fields with the template and calculate the control rollup.

    Args:
        records: Saved client task records.

    Returns:
        Thirty display rows. Task 15 summarizes tasks 16–20.

    Raises:
        ValueError: If stored dates or durations are invalid.
    """

    saved = {int(record["task_ref"]): record for record in records}
    rows = []
    for reference, title, iso_ref, resource in PROJECT_TASKS:
        fields = dict(saved.get(reference, {}))
        row = {
            "resource": resource,
            "start_date": None,
            "work_days": 0,
            "completed_days": 0,
            "notes": "",
            "revision": 0,
            **fields,
            "task_ref": reference,
            "task": title,
            "iso_ref": iso_ref,
        }
        row["end_date"] = workday_end(row["start_date"], row["work_days"])
        rows.append(row)
    children = rows[15:20]
    summary = rows[14]
    summary["work_days"] = sum(row["work_days"] for row in children)
    summary["completed_days"] = sum(row["completed_days"] for row in children)
    starts = [row["start_date"] for row in children if row["start_date"]]
    finishes = [row["end_date"] for row in children if row["end_date"]]
    summary["start_date"] = min(starts) if starts else None
    summary["end_date"] = max(finishes) if finishes else None
    for row in rows:
        row["progress"] = (
            100 * row["completed_days"] / row["work_days"] if row["work_days"] else None
        )
    return rows


def project_totals(rows: Sequence[Mapping[str, Any]], today: date) -> dict[str, Any]:
    """Calculate effort-weighted progress without double-counting task 15.

    Args:
        rows: Project task display rows.
        today: Reference date for identifying overdue work.

    Returns:
        Effort, completion, unscheduled and overdue counts.

    Raises:
        KeyError: If required task fields are absent.
    """

    work = [row for row in rows if row["task_ref"] != 15]
    planned = sum(row["work_days"] for row in work)
    completed = sum(row["completed_days"] for row in work)
    return {
        "work_days": planned,
        "completed_days": completed,
        "progress": 100 * completed / planned if planned else None,
        "unscheduled": sum(row["end_date"] is None for row in work),
        "overdue": sum(
            row["end_date"] is not None
            and row["end_date"] < today
            and row["completed_days"] < row["work_days"]
            for row in work
        ),
    }
