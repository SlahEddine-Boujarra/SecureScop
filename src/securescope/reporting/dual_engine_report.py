"""Provider-neutral PDF report discovery and dual-engine consolidation.

This module keeps reporting outside Streamlit. It resolves the stored scan
record for an OpenVAS or Nuclei job, preserves the provider-generated PDF, and
creates a deterministic consolidated OpenVAS + Nuclei PDF when both engines
have completed a scan for the same workspace asset.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from securescope.persistence.db_service import load_scan_history_for_client
from securescope.reporting.openvas_pdf_report import generate_asset_report_pdf

ENGINE_OPENVAS = "OpenVAS"
ENGINE_NUCLEI = "Nuclei"
ENGINE_ORDER = (ENGINE_OPENVAS, ENGINE_NUCLEI)


class DualEngineReportError(RuntimeError):
    """Raised when no usable stored scan record can be resolved."""


def _slug(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "report"))
    return text.strip("._") or "report"


def _engine_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "nuclei" in text or "projectdiscovery" in text:
        return ENGINE_NUCLEI
    if "openvas" in text or "greenbone" in text or "gvm" in text:
        return ENGINE_OPENVAS
    return str(value or "Scanner").strip() or "Scanner"


def record_engine(record: dict[str, Any]) -> str:
    """Return a normalized provider name for a stored scan record."""

    return _engine_name(
        record.get("scanner_engine") or record.get("scanner") or record.get("provider")
    )


def _record_pdf_path(record: dict[str, Any]) -> Path | None:
    for key in ("pdf_report_path", "pdf_path", "report_path"):
        value = str(record.get(key) or "").strip()
        if not value:
            continue
        candidate = Path(value)
        if candidate.is_file():
            return candidate
    return None


def _record_asset_ip(record: dict[str, Any]) -> str:
    asset = record.get("asset") or {}
    return str(record.get("asset_ip") or asset.get("ip") or "").strip()


def _record_datetime(record: dict[str, Any]) -> datetime:
    value = record.get("scanned_at") or record.get("completed_at")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def _job_matches_record(
    record: dict[str, Any],
    *,
    engine: str,
    job: dict[str, Any],
) -> bool:
    if record_engine(record) != _engine_name(engine):
        return False

    job_id = job.get("id")
    if job_id is not None and record.get("job_id") is not None:
        try:
            if int(record.get("job_id")) == int(job_id):
                return True
        except (TypeError, ValueError):
            pass

    job_report_id = str(job.get("report_id") or "").strip()
    record_report_id = str(record.get("report_id") or "").strip()
    if job_report_id and record_report_id and job_report_id == record_report_id:
        return True

    job_uuid = str(job.get("job_uuid") or "").strip()
    if job_uuid and job_uuid == str(record.get("job_uuid") or "").strip():
        return True

    return False


def find_job_scan_record(
    client_name: str,
    engine: str,
    job: dict[str, Any],
    *,
    max_records: int = 300,
) -> dict[str, Any] | None:
    """Find the exact stored scan record for a provider job.

    Exact job ID, report ID, or job UUID matching is preferred. The newest
    same-engine record for the exact asset IP is used only as a fallback.
    """

    history = load_scan_history_for_client(client_name, max_records=max_records)
    for record in history:
        if _job_matches_record(record, engine=engine, job=job):
            return dict(record)

    asset_ip = str(job.get("asset_ip") or "").strip()
    candidates = [
        dict(record)
        for record in history
        if record_engine(record) == _engine_name(engine) and _record_asset_ip(record) == asset_ip
    ]
    candidates.sort(key=_record_datetime, reverse=True)
    return candidates[0] if candidates else None


def latest_engine_records_for_asset(
    client_name: str,
    asset_ip: str,
    *,
    preferred_record: dict[str, Any] | None = None,
    max_records: int = 300,
) -> dict[str, dict[str, Any]]:
    """Return the newest OpenVAS and Nuclei records for one exact asset IP."""

    normalized_ip = str(asset_ip or "").strip()
    history = load_scan_history_for_client(client_name, max_records=max_records)
    records: dict[str, dict[str, Any]] = {}

    if preferred_record and _record_asset_ip(preferred_record) == normalized_ip:
        engine = record_engine(preferred_record)
        if engine in ENGINE_ORDER:
            records[engine] = dict(preferred_record)

    candidates = [
        dict(record)
        for record in history
        if _record_asset_ip(record) == normalized_ip and record_engine(record) in ENGINE_ORDER
    ]
    candidates.sort(key=_record_datetime, reverse=True)
    for record in candidates:
        records.setdefault(record_engine(record), record)
    return records


def _finding_with_engine(
    finding: dict[str, Any],
    engine: str,
) -> dict[str, Any]:
    item = dict(finding)
    item.setdefault("Scanner", engine)
    item.setdefault("scanner_engine", engine)
    item["Scanner Engine"] = engine
    return item


def _latest_asset(records: Iterable[dict[str, Any]], asset_ip: str) -> dict[str, Any]:
    values = sorted((dict(item) for item in records), key=_record_datetime, reverse=True)
    for record in values:
        asset = dict(record.get("asset") or {})
        if asset:
            asset.setdefault("ip", asset_ip)
            return asset
    return {"ip": asset_ip}


def build_consolidated_record(
    client_name: str,
    asset_ip: str,
    records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build one provider-neutral record from one or both scanner engines."""

    if not records:
        raise DualEngineReportError(
            f"No completed OpenVAS or Nuclei scan record exists for {asset_ip}."
        )

    findings: list[dict[str, Any]] = []
    report_ids: list[str] = []
    engine_summaries: list[dict[str, Any]] = []
    for engine in ENGINE_ORDER:
        record = records.get(engine)
        if not record:
            continue
        provider_findings = [
            _finding_with_engine(dict(finding), engine)
            for finding in list(record.get("findings") or [])
            if isinstance(finding, dict)
        ]
        findings.extend(provider_findings)
        report_id = str(record.get("report_id") or "").strip()
        if report_id:
            report_ids.append(report_id)
        engine_summaries.append(
            {
                "engine": engine,
                "report_id": report_id,
                "scanned_at": record.get("scanned_at"),
                "findings_count": len(provider_findings),
                "profile_name": record.get("profile_name") or record.get("scan_profile"),
                "source_format": record.get("source_format")
                or ("JSONL" if engine == ENGINE_NUCLEI else "Greenbone report"),
            }
        )

    ordered_engines = [engine for engine in ENGINE_ORDER if engine in records]
    digest_source = "|".join([client_name, asset_ip, *report_ids, *ordered_engines])
    digest = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:16]
    selected_records = list(records.values())
    scanned_at = max((_record_datetime(item) for item in selected_records)).isoformat()
    engines = [engine for engine in ENGINE_ORDER if engine in records]
    scanner_label = (
        "OpenVAS + ProjectDiscovery Nuclei"
        if len(engines) == 2
        else ("ProjectDiscovery Nuclei" if engines == [ENGINE_NUCLEI] else engines[0])
    )

    return {
        "report_id": f"dual-{digest}",
        "scanner": scanner_label,
        "scanner_engine": "Dual engine" if len(engines) == 2 else engines[0],
        "asset": _latest_asset(selected_records, asset_ip),
        "asset_ip": asset_ip,
        "scanned_at": scanned_at,
        "findings": findings,
        "engine_records": engine_summaries,
        "client_name": client_name,
    }


def _output_path(
    output_root: str | Path,
    client_name: str,
    record: dict[str, Any],
) -> Path:
    engine_records = list(record.get("engine_records") or [])
    engine_token = "dual" if len(engine_records) > 1 else record_engine(record).lower()
    directory = (
        Path(output_root)
        / _slug(client_name)
        / "dual_engine_reports"
        / _slug(record.get("asset_ip") or "unknown")
    )
    directory.mkdir(parents=True, exist_ok=True)
    return directory / (
        f"SecureScope_{engine_token}_{_slug(record.get('asset_ip'))}_"
        f"{_slug(record.get('report_id'))}.pdf"
    )


def ensure_report_bundle(
    client_name: str,
    engine: str,
    job: dict[str, Any],
    *,
    output_root: str | Path = "reports",
) -> dict[str, Any]:
    """Resolve the provider PDF and generate a consolidated report copy.

    The consolidated report contains the clicked scan and, when available, the
    latest completed result from the other engine for the same exact asset IP.
    Existing provider-generated PDFs are never overwritten.
    """

    preferred = find_job_scan_record(client_name, engine, job)
    asset_ip = str(
        job.get("asset_ip")
        or (preferred or {}).get("asset_ip")
        or ((preferred or {}).get("asset") or {}).get("ip")
        or ""
    ).strip()
    if not asset_ip:
        raise DualEngineReportError("The selected scan job has no usable asset IP.")
    if not preferred:
        raise DualEngineReportError(
            "The scan is not finalized in client history yet. Wait for report finalization."
        )

    records = latest_engine_records_for_asset(
        client_name,
        asset_ip,
        preferred_record=preferred,
    )
    consolidated = build_consolidated_record(client_name, asset_ip, records)
    combined_path = _output_path(output_root, client_name, consolidated)
    if not combined_path.is_file():
        combined_path.write_bytes(generate_asset_report_pdf(consolidated, client_name=client_name))

    provider_path = _record_pdf_path(preferred)
    if provider_path is None:
        provider_record = build_consolidated_record(
            client_name,
            asset_ip,
            {record_engine(preferred): preferred},
        )
        provider_path = _output_path(output_root, client_name, provider_record)
        if not provider_path.is_file():
            provider_path.write_bytes(
                generate_asset_report_pdf(provider_record, client_name=client_name)
            )

    return {
        "asset_ip": asset_ip,
        "provider_engine": _engine_name(engine),
        "provider_record": preferred,
        "provider_path": provider_path,
        "combined_record": consolidated,
        "combined_path": combined_path,
        "engines": [item["engine"] for item in consolidated.get("engine_records") or []],
    }
