"""SecureScope OpenVAS live diagnostic and controlled New-task repair.

Default mode is read-only. The optional --repair-new mode sends start_task only
for exact task UUIDs that Greenbone itself reports as New. It never creates a
new target or task and therefore cannot duplicate a scan attempt.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

from securescope.paths import ENV_FILE

load_dotenv(dotenv_path=ENV_FILE, override=False)

from securescope.persistence.db_service import connect  # noqa: E402
from securescope.persistence.openvas_persistence import (  # noqa: E402
    get_openvas_batch,
    init_openvas_tables,
    load_openvas_batch_jobs,
    record_openvas_job_event,
    update_batch_counters,
    update_openvas_job_by_id,
)
from securescope.scanners.openvas.openvas_worker_service import (  # noqa: E402
    GMP_START_TIMEOUT_SECONDS,
    GVM_PASSWORD,
    GVM_USERNAME,
    LOCAL_TUNNEL_HOST,
    LOCAL_TUNNEL_PORT,
    make_gmp_connection,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _latest_batch_id() -> int | None:
    init_openvas_tables()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT b.id
                FROM securescope_openvas_batches b
                WHERE EXISTS (
                    SELECT 1
                    FROM securescope_openvas_jobs j
                    WHERE j.batch_id = b.id
                      AND j.task_id IS NOT NULL
                      AND j.task_id <> ''
                )
                ORDER BY b.created_at DESC, b.id DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            return int(row[0]) if row else None


def _text(node: Any, path: str, default: str = "") -> str:
    try:
        values = node.xpath(path)
    except Exception:
        return default
    if not values:
        return default
    return str(values[0] or default)


def _exact_task_raw(gmp: GMP, task_id: str) -> tuple[dict[str, Any], str]:
    command = f'<get_tasks task_id="{task_id}" details="0"/>'
    raw = gmp.send_command(command)
    raw_text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    root = etree.fromstring(raw_text.encode("utf-8", errors="replace"))
    response_status = str(root.get("status") or "")
    response_text = str(root.get("status_text") or "")
    nodes = root.xpath("./task") or root.xpath(".//task")
    task = next(
        (node for node in nodes if str(node.get("id") or "").strip() == task_id),
        None,
    )
    result: dict[str, Any] = {
        "response_status": response_status,
        "response_status_text": response_text,
        "found": task is not None,
        "task_id": task_id,
    }
    if task is not None:
        result.update(
            {
                "name": _text(task, "./name/text()"),
                "status": _text(task, "./status/text()", "Unknown"),
                "progress": _text(task, "./progress/text()", "0"),
                "current_report_id": _text(task, "./current_report/report/@id"),
                "last_report_id": _text(task, "./last_report/report/@id"),
                "scanner_id": _text(task, "./scanner/@id"),
                "target_id": _text(task, "./target/@id"),
            }
        )
    return result, raw_text


def _tunnel_check() -> dict[str, Any]:
    result = {
        "host": LOCAL_TUNNEL_HOST,
        "port": LOCAL_TUNNEL_PORT,
        "reachable": False,
        "error": "",
    }
    try:
        with socket.create_connection((LOCAL_TUNNEL_HOST, LOCAL_TUNNEL_PORT), timeout=3):
            result["reachable"] = True
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", type=int)
    parser.add_argument(
        "--repair-new",
        action="store_true",
        help=(
            "Send start_task for exact tasks that Greenbone reports as New. "
            "No target/task is created."
        ),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    batch_id = args.batch_id or _latest_batch_id()
    if batch_id is None:
        print("No OpenVAS batch containing task UUIDs was found.")
        return 2

    batch = get_openvas_batch(batch_id)
    jobs = load_openvas_batch_jobs(batch_id)
    output_path = args.output or Path(
        f"openvas_doctor_batch_{batch_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    report: dict[str, Any] = {
        "generated_at": utc_now().isoformat(),
        "mode": "repair-new" if args.repair_new else "read-only",
        "batch_id": batch_id,
        "batch": batch,
        "tunnel": _tunnel_check(),
        "gmp": {},
        "jobs": [],
        "summary": {},
    }

    if not report["tunnel"]["reachable"]:
        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(json.dumps(report, indent=2, default=str))
        print(f"Saved: {output_path}")
        return 3
    if not GVM_PASSWORD:
        report["gmp"]["error"] = "GVM_PASSWORD is missing."
        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(json.dumps(report, indent=2, default=str))
        return 4

    counts: dict[str, int] = {}
    with GMP(
        connection=make_gmp_connection(
            timeout_seconds=GMP_START_TIMEOUT_SECONDS,
        ),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        version_response = gmp.get_version()
        report["gmp"] = {
            "authenticated": True,
            "username": GVM_USERNAME,
            "version": _text(version_response, ".//version/text()"),
        }

        for db_job in jobs:
            task_id = str(db_job.get("task_id") or "").strip()
            item: dict[str, Any] = {
                "job_id": int(db_job["id"]),
                "asset_ip": str(db_job.get("asset_ip") or ""),
                "database": {
                    "status": db_job.get("status"),
                    "provider_status": db_job.get("provider_status"),
                    "provider_task_status": db_job.get("provider_task_status"),
                    "progress": db_job.get("progress"),
                    "stage": db_job.get("stage"),
                    "task_id": task_id,
                    "report_id": db_job.get("report_id"),
                    "launch_report_id": db_job.get("launch_report_id"),
                    "last_provider_sync_at": db_job.get("last_provider_sync_at"),
                    "error": db_job.get("error"),
                },
                "greenbone": {},
                "repair": {},
            }
            if not task_id:
                item["greenbone"] = {"found": False, "reason": "No task ID in PostgreSQL"}
                report["jobs"].append(item)
                counts["No task ID"] = counts.get("No task ID", 0) + 1
                continue

            try:
                exact, raw_xml = _exact_task_raw(gmp, task_id)
                item["greenbone"] = exact
                item["greenbone"]["raw_xml"] = raw_xml[:12000]
                gb_status = str(exact.get("status") or "Unknown")
                counts[gb_status] = counts.get(gb_status, 0) + 1

                if args.repair_new and gb_status.strip().lower() in {"new", "created"}:
                    started_at = utc_now()
                    try:
                        start_response = gmp.start_task(task_id)
                        response_status = str(start_response.get("status") or "")
                        response_text = str(start_response.get("status_text") or "")
                        report_id = _text(start_response, "./report_id/text()") or _text(
                            start_response, ".//report_id/text()"
                        )
                        item["repair"] = {
                            "attempted": True,
                            "accepted": response_status == "202",
                            "response_status": response_status,
                            "response_status_text": response_text,
                            "report_id": report_id,
                        }
                        update_openvas_job_by_id(
                            int(db_job["id"]),
                            status="Waiting for scanner",
                            ui_status="Waiting for scanner",
                            provider_status="Start submitted",
                            provider_task_status="New",
                            provider_report_status="",
                            provider_progress_source="doctor start_task response",
                            stage="Start submitted by OpenVAS doctor",
                            report_id=report_id or None,
                            launch_report_id=report_id or None,
                            submitted_at=started_at,
                            last_provider_sync_at=None,
                            error="",
                            result_message=(
                                "The stabilization doctor sent start_task for "
                                f"the existing task {task_id}."
                            ),
                        )
                        record_openvas_job_event(
                            int(db_job["id"]),
                            "doctor_start_task",
                            provider_status="Start submitted",
                            ui_status="Waiting for scanner",
                            stage="Start submitted by OpenVAS doctor",
                            progress=0,
                            message=(
                                f"start_task returned {response_status}; "
                                f"report {report_id or 'pending'}."
                            ),
                        )
                        time.sleep(1)
                        after, after_raw = _exact_task_raw(gmp, task_id)
                        item["repair"]["after"] = after
                        item["repair"]["after_raw_xml"] = after_raw[:12000]
                    except Exception as exc:
                        item["repair"] = {
                            "attempted": True,
                            "accepted": False,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
            except Exception as exc:
                item["greenbone"] = {
                    "found": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
                counts["Lookup error"] = counts.get("Lookup error", 0) + 1

            report["jobs"].append(item)

    update_batch_counters(batch_id)
    report["summary"] = {
        "job_count": len(jobs),
        "greenbone_status_counts": counts,
        "repair_attempts": sum(
            1 for item in report["jobs"] if item.get("repair", {}).get("attempted")
        ),
        "repair_accepts": sum(
            1 for item in report["jobs"] if item.get("repair", {}).get("accepted")
        ),
    }

    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2, default=str))
    print(f"Saved full diagnostic: {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
