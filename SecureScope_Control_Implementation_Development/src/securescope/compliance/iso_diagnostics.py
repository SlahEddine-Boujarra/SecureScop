"""Non-destructive diagnostics for SecureScope ISO technical assurance."""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

from securescope.paths import ENV_FILE, PACKAGE_ROOT, PROJECT_ROOT, WAZUH_ROOT

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)

from securescope.compliance.iso_control_assessment_service import (  # noqa: E402
    assessment_summary,
    evaluate_a8_controls,
    init_iso_assessment_tables,
)
from securescope.integrations.ntp_audit_service import (  # noqa: E402
    collect_wazuh_ntp_evidence,
    parse_ntp_evidence_text,
)
from securescope.integrations.vulnerability_intelligence_service import (  # noqa: E402
    extract_cves,
    init_vulnerability_intelligence_tables,
)
from securescope.persistence.clock_evidence_persistence import (  # noqa: E402
    init_clock_evidence_tables,
)
from securescope.persistence.db_service import init_database  # noqa: E402


def check_files() -> dict[str, Any]:
    required = [
        WAZUH_ROOT / "windows" / "securescope_time_sync.ps1",
        WAZUH_ROOT / "linux" / "securescope_time_sync.sh",
        WAZUH_ROOT / "manager" / "agent.conf.example",
        WAZUH_ROOT / "manager" / "local_decoder.xml",
        WAZUH_ROOT / "manager" / "local_rules.xml",
        WAZUH_ROOT / "manager" / "sample_event.txt",
        WAZUH_ROOT / "manager" / "validate_manager_clock_rules.sh",
        PACKAGE_ROOT / "compliance" / "remediation_assistant.py",
    ]
    missing = [str(path.relative_to(PROJECT_ROOT)) for path in required if not path.is_file()]
    return {"ok": not missing, "missing": missing}


def check_clock_parser() -> dict[str, Any]:
    sample = (
        'SECURESCOPE_NTP: {"hostname":"sample","ip":"192.0.2.10",'
        '"synchronized":true,"source":"time.example",'
        '"offset_ms":4.5,"stratum":3,"service":"chrony",'
        '"os":"Linux","epoch_ms":1770000000000}'
    )
    parsed = parse_ntp_evidence_text(
        sample,
        fallback_timestamp="2026-02-02T02:40:00Z",
    )
    return {
        "ok": bool(parsed and parsed.get("clock_synchronized")),
        "parsed": parsed,
    }


def check_engine() -> dict[str, Any]:
    assets = [
        {
            "ip": "192.0.2.10",
            "hostname": "sample",
            "operating_system": "Linux",
            "open_ports": [22, 123],
            "clock_evidence_source": "Wazuh endpoint command",
            "clock_sync_status": "Synchronized",
            "clock_source": "time.example",
            "clock_offset_ms": 4.5,
        }
    ]
    history = [
        {
            "final_status": "Completed",
            "asset_ip": "192.0.2.10",
            "report_id": "diagnostic-report",
            "findings": [],
        }
    ]
    wazuh_rows = [
        {
            "asset_ip": "192.0.2.10",
            "monitoring_status": "Monitored",
        }
    ]
    assessments = evaluate_a8_controls(assets, history, wazuh_rows)
    clock_control = next(row for row in assessments if row.get("control_id") == "A.8.17")
    return {
        "ok": len(assessments) == 34,
        "control_count": len(assessments),
        "clock_control": clock_control,
        "summary": assessment_summary(assessments),
    }


def main() -> int:
    output: dict[str, Any] = {"checks": {}, "warnings": []}
    try:
        init_database()
        init_iso_assessment_tables()
        init_clock_evidence_tables()
        init_vulnerability_intelligence_tables()
        output["checks"]["postgresql"] = {"ok": True}
    except Exception as exc:
        output["checks"]["postgresql"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    output["checks"]["deployment_files"] = check_files()
    output["checks"]["clock_parser"] = check_clock_parser()
    output["checks"]["assessment_engine"] = check_engine()
    output["checks"]["cve_parser"] = {
        "ok": extract_cves("CVE-2024-1234 and cve-2025-12345")
        == ["CVE-2024-1234", "CVE-2025-12345"]
    }

    try:
        from securescope.compliance.remediation_assistant import generate_remediation_plan

        plan = generate_remediation_plan(
            {
                "Control": "A.8.17",
                "Automatic status": "Gap detected",
                "Gaps": ["Validation evidence is stale"],
            },
            use_ai=False,
        )
        output["checks"]["remediation_assistant"] = {
            "ok": bool(plan.get("immediate_actions")),
            "source": plan.get("source"),
        }
    except Exception as exc:
        output["checks"]["remediation_assistant"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    if os.getenv("WAZUH_INDEXER_URL") and os.getenv("WAZUH_INDEXER_PASSWORD"):
        try:
            evidence = collect_wazuh_ntp_evidence(limit=20)
            output["checks"]["wazuh_clock_query"] = {
                "ok": True,
                "evidence_rows": len(evidence),
            }
            if not evidence:
                output["warnings"].append(
                    "Wazuh query succeeded but no SECURESCOPE_NTP event was found."
                )
        except Exception as exc:
            output["checks"]["wazuh_clock_query"] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
            output["warnings"].append(
                (
                    "Wazuh clock evidence is optional during startup; deploy the "
                    "scripts and verify credentials."
                )
            )
    else:
        output["warnings"].append(
            "Wazuh Indexer credentials are not configured; live clock evidence was not tested."
        )

    path = APP_DIR / "logs" / "iso_diagnostics.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")

    required_checks = (
        "postgresql",
        "deployment_files",
        "clock_parser",
        "assessment_engine",
        "cve_parser",
        "remediation_assistant",
    )
    ok = all(output["checks"].get(name, {}).get("ok") for name in required_checks)
    print(json.dumps(output, indent=2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
