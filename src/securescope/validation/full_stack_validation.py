"""Read-only validation for the preserved SecureScope application.

The validator never creates or launches an OpenVAS task. It verifies:

- Python runtime and required source files;
- PostgreSQL schema initialization;
- the local GMP tunnel and Greenbone authentication when configured;
- the local Nuclei CLI, templates and worker heartbeat when configured;
- Wazuh API access when configured;
- Wazuh endpoint clock evidence when the Indexer is configured;
- the complete 34-control Annex A.8 assessment engine;
- ISO PDF/evidence-package generation;
- deterministic remediation-plan generation.

Use ``--strict`` after PostgreSQL, OpenVAS and Wazuh are fully configured.
Without ``--strict``, unavailable live integrations are reported as skipped
while local deterministic checks still run.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Callable

from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PACKAGE_ROOT, PROJECT_ROOT, WAZUH_ROOT

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)

Result = dict[str, Any]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _run(name: str, function: Callable[[], Result]) -> Result:
    try:
        result = function()
        result.setdefault("check", name)
        result.setdefault("ok", True)
        result.setdefault("status", "passed" if result["ok"] else "failed")
        return result
    except Exception as exc:
        return {
            "check": name,
            "ok": False,
            "status": "failed",
            "error": _safe_error(exc),
        }


def check_runtime() -> Result:
    required_files = [
        PACKAGE_ROOT / "app.py",
        PACKAGE_ROOT / "scanners" / "openvas" / "openvas_worker_service.py",
        PACKAGE_ROOT / "persistence" / "openvas_persistence.py",
        PACKAGE_ROOT / "scanners" / "nuclei" / "nuclei_client.py",
        PACKAGE_ROOT / "persistence" / "nuclei_persistence.py",
        PACKAGE_ROOT / "scanners" / "nuclei" / "nuclei_worker_service.py",
        PACKAGE_ROOT / "core" / "scanner_engine_service.py",
        PACKAGE_ROOT / "ui" / "dual_engine_ui.py",
        PACKAGE_ROOT / "compliance" / "iso_control_assessment_service.py",
        PACKAGE_ROOT / "integrations" / "ntp_audit_service.py",
        PACKAGE_ROOT / "persistence" / "clock_evidence_persistence.py",
        PACKAGE_ROOT / "integrations" / "vulnerability_intelligence_service.py",
        PACKAGE_ROOT / "compliance" / "remediation_assistant.py",
        PACKAGE_ROOT / "reporting" / "iso_report_service.py",
        WAZUH_ROOT / "README_NTP.md",
        WAZUH_ROOT / "manager" / "validate_manager_clock_rules.sh",
    ]
    missing = [str(path.relative_to(PROJECT_ROOT)) for path in required_files if not path.is_file()]
    major, minor = sys.version_info[:2]
    return {
        "ok": (major, minor) >= (3, 11) and not missing,
        "python": sys.version,
        "application_directory": str(APP_DIR),
        "missing_files": missing,
        "nmap_binary": shutil.which("nmap") or "",
    }


def check_postgresql() -> Result:
    from securescope.compliance.iso_control_assessment_service import init_iso_assessment_tables
    from securescope.integrations.vulnerability_intelligence_service import (
        init_vulnerability_intelligence_tables,
    )
    from securescope.persistence.clock_evidence_persistence import init_clock_evidence_tables
    from securescope.persistence.db_service import connect, init_database
    from securescope.persistence.db_wazuh_service import init_wazuh_tables
    from securescope.persistence.nuclei_persistence import init_nuclei_tables
    from securescope.persistence.openvas_persistence import init_openvas_tables

    init_database()
    init_openvas_tables()
    init_nuclei_tables()
    init_wazuh_tables()
    init_iso_assessment_tables()
    init_clock_evidence_tables()
    init_vulnerability_intelligence_tables()

    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), NOW();")
            database_name, server_time = cursor.fetchone()

    return {
        "ok": True,
        "database": str(database_name),
        "server_time": str(server_time),
        "schema_initialization": "passed",
    }


def check_openvas() -> Result:
    from securescope.scanners.openvas.openvas_diagnostics import (
        check_environment,
        check_gmp,
        check_tunnel,
    )

    check_environment()
    check_tunnel()
    check_gmp()
    return {
        "ok": True,
        "provider": "OpenVAS / Greenbone",
        "write_operations_tested": False,
        "message": "Tunnel, authentication and required resources are valid.",
    }


def check_nuclei() -> Result:
    """Run read-only Nuclei CLI, template and worker checks."""

    from securescope.persistence.nuclei_persistence import get_worker_state, init_nuclei_tables
    from securescope.scanners.nuclei.nuclei_client import NucleiClient

    init_nuclei_tables()
    client = NucleiClient()
    health = client.health()
    worker = get_worker_state()
    worker_age = int(worker.get("heartbeat_age_seconds") or 999999) if worker else 999999
    worker_ok = bool(
        worker and str(worker.get("status") or "").lower() == "running" and worker_age <= 45
    )
    return {
        "ok": bool(health.get("ok")),
        "provider": "ProjectDiscovery Nuclei",
        "integration": "local CLI",
        "binary": health.get("binary"),
        "version": health.get("version"),
        "templates_version": health.get("templates_version"),
        "api_key_required": False,
        "worker_healthy": worker_ok,
        "worker_heartbeat_age_seconds": worker_age,
        "write_operations_tested": False,
        "message": "Read-only Nuclei CLI and template checks passed.",
    }


def check_wazuh_api() -> Result:
    """Test authentication without listing agents from unrelated workspaces."""
    from securescope.integrations.wazuh_service import WazuhClient

    result = WazuhClient().test_connection()
    return dict(
        result,
        telemetry_verified=False,
        message="API authentication tested; bound-asset telemetry requires workspace collection.",
    )


def check_wazuh_clock_evidence() -> Result:
    from securescope.integrations.ntp_audit_service import collect_wazuh_ntp_evidence

    evidence = collect_wazuh_ntp_evidence(limit=5000)
    synchronized = sum(1 for item in evidence if item.get("clock_synchronized") is True)
    return {
        "ok": bool(evidence),
        "status": "passed" if evidence else "warning",
        "evidence_rows": len(evidence),
        "synchronized_rows": synchronized,
        "message": (
            "Clock evidence was collected from Wazuh."
            if evidence
            else ("The Wazuh query succeeded, but no SECURESCOPE_NTP " "event exists yet.")
        ),
        "sample": evidence[:5],
    }


def check_iso_engine() -> Result:
    from securescope.compliance.iso_control_assessment_service import (
        add_maturity,
        assessment_summary,
        evaluate_a8_controls,
    )
    from securescope.reporting.iso_report_service import (
        build_iso_assurance_pdf,
        build_iso_evidence_zip,
    )

    assets = [
        {
            "ip": "192.0.2.10",
            "hostname": "validation-host",
            "operating_system": "Linux",
            "open_ports": [22, 123],
            "clock_evidence_source": "Wazuh endpoint command",
            "clock_sync_status": "Synchronized",
            "clock_source": "time.validation.local",
            "clock_offset_ms": 2.5,
            "manager_agent_delta_ms": 150,
        }
    ]
    history = [
        {
            "asset_ip": "192.0.2.10",
            "final_status": "Completed",
            "report_id": "validation-report",
            "findings": [],
        }
    ]
    wazuh = [
        {
            "asset_ip": "192.0.2.10",
            "monitoring_status": "Monitored",
        }
    ]
    assessments = add_maturity(evaluate_a8_controls(assets, history, wazuh))
    clock = next(item for item in assessments if item["Control"] == "A.8.17")
    summary = assessment_summary(assessments)

    pdf = build_iso_assurance_pdf(
        client_name="Validation",
        assessments=assessments,
        actions=[],
        clock_summary={
            "status": "Synchronized",
            "assets_total": 1,
            "assets_with_endpoint_evidence": 1,
            "synchronized_assets": 1,
            "gap_assets": 0,
            "sources": ["time.validation.local"],
        },
    )
    archive = build_iso_evidence_zip(
        client_name="Validation",
        assessments=assessments,
        actions=[],
        clock_rows=[],
        assets=assets,
        scan_history=history,
    )
    ok = (
        len(assessments) == 34
        and clock.get("Automatic status") == "Likely implemented"
        and pdf.startswith(b"%PDF")
        and archive.startswith(b"PK")
    )
    return {
        "ok": ok,
        "control_count": len(assessments),
        "clock_control": clock,
        "summary": summary,
        "pdf_generation": "passed" if pdf.startswith(b"%PDF") else "failed",
        "evidence_zip_generation": ("passed" if archive.startswith(b"PK") else "failed"),
    }


def check_remediation_assistant() -> Result:
    from securescope.compliance.remediation_assistant import generate_remediation_plan

    plan = generate_remediation_plan(
        {
            "Control": "A.8.17",
            "Control name": "Clock synchronization",
            "Automatic status": "Gap detected",
            "Gaps": ["One endpoint has stale Wazuh clock evidence"],
        },
        {
            "control_id": "A.8.17",
            "priority": "High",
            "title": "Restore current clock evidence",
        },
        use_ai=False,
    )
    return {
        "ok": bool(plan.get("immediate_actions")),
        "source": plan.get("source"),
        "control_id": plan.get("control_id"),
    }


def _configured(*names: str) -> bool:
    return all(str(os.getenv(name) or "").strip() for name in names)


def _enabled_engine(engine: str) -> bool:
    from securescope.core.scanner_engine_service import enabled_engines

    return engine in enabled_engines()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when a configured live integration is unavailable.",
    )
    args = parser.parse_args()

    checks: dict[str, Result] = {}
    checks["runtime"] = _run("runtime", check_runtime)
    checks["postgresql"] = _run("postgresql", check_postgresql)
    checks["iso_engine"] = _run("iso_engine", check_iso_engine)
    checks["remediation"] = _run(
        "remediation",
        check_remediation_assistant,
    )

    if _enabled_engine("OpenVAS") and _configured("GVM_PASSWORD"):
        checks["openvas"] = _run("openvas", check_openvas)
    else:
        checks["openvas"] = {
            "check": "openvas",
            "ok": (not args.strict) or not _enabled_engine("OpenVAS"),
            "status": "skipped",
            "message": (
                "OpenVAS is disabled."
                if not _enabled_engine("OpenVAS")
                else "GVM_PASSWORD is not configured."
            ),
        }

    if _enabled_engine("Nuclei"):
        checks["nuclei"] = _run("nuclei", check_nuclei)
    else:
        checks["nuclei"] = {
            "check": "nuclei",
            "ok": True,
            "status": "skipped",
            "message": "Nuclei is disabled.",
        }

    if _configured(
        "WAZUH_API_URL",
        "WAZUH_API_PASSWORD",
    ):
        checks["wazuh_api"] = _run(
            "wazuh_api",
            check_wazuh_api,
        )
    else:
        checks["wazuh_api"] = {
            "check": "wazuh_api",
            "ok": not args.strict,
            "status": "skipped",
            "message": "Wazuh API credentials are not configured.",
        }

    if _configured(
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USER",
        "WAZUH_INDEXER_PASSWORD",
    ):
        checks["wazuh_clock"] = _run(
            "wazuh_clock",
            check_wazuh_clock_evidence,
        )
        if checks["wazuh_clock"].get("status") == "warning" and not args.strict:
            checks["wazuh_clock"]["ok"] = True
    else:
        checks["wazuh_clock"] = {
            "check": "wazuh_clock",
            "ok": not args.strict,
            "status": "skipped",
            "message": "Wazuh Indexer credentials are not configured.",
        }

    output = {
        "generated_at": _now(),
        "strict": args.strict,
        "checks": checks,
        "ok": all(bool(item.get("ok")) for item in checks.values()),
    }
    output_path = APP_DIR / "logs" / "full_stack_validation.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, indent=2, default=str),
        encoding="utf-8",
    )
    print(json.dumps(output, indent=2, default=str))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
