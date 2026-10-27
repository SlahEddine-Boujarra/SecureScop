"""Parse Nuclei JSONL findings and persist SecureScope evidence bundles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from securescope.reporting.openvas_pdf_report import generate_asset_report_pdf

SEVERITY_ORDER = {
    "info": "Info",
    "unknown": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
SEVERITY_DEFAULT_CVSS = {
    "Critical": 9.5,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 2.5,
    "Info": 0.0,
}


class NucleiReportError(RuntimeError):
    """Raised when Nuclei evidence cannot be parsed or saved."""


def _float(value: Any, default: float = 0.0) -> float:
    """Return a float for arbitrary JSON values."""

    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _list(value: Any) -> list[str]:
    """Normalize a scalar or sequence into non-empty strings."""

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _classification(info: dict[str, Any]) -> dict[str, Any]:
    """Return Nuclei classification data using known key spellings."""

    value = info.get("classification")
    return dict(value) if isinstance(value, dict) else {}


def _severity(info: dict[str, Any]) -> str:
    """Return a SecureScope severity label."""

    raw = str(info.get("severity") or "info").strip().lower()
    return SEVERITY_ORDER.get(raw, raw.title() or "Info")


def _cvss(info: dict[str, Any], severity: str) -> float:
    """Return CVSS from template classification or a cautious fallback."""

    classification = _classification(info)
    for key in ("cvss-score", "cvss_score", "cvss"):
        score = _float(classification.get(key), -1.0)
        if score >= 0:
            return score
    return SEVERITY_DEFAULT_CVSS.get(severity, 0.0)


def _cves(payload: dict[str, Any], info: dict[str, Any]) -> list[str]:
    """Return normalized CVE identifiers from one Nuclei result."""

    classification = _classification(info)
    candidates = [
        *_list(classification.get("cve-id")),
        *_list(classification.get("cve_id")),
        *_list(payload.get("template-id")),
    ]
    result: list[str] = []
    for candidate in candidates:
        for match in re.findall(r"CVE-\d{4}-\d{4,}", candidate, re.I):
            normalized = match.upper()
            if normalized not in result:
                result.append(normalized)
    return result


def _port(payload: dict[str, Any]) -> str:
    """Return a readable port/protocol label from Nuclei output."""

    matched = str(
        payload.get("matched-at") or payload.get("host") or payload.get("url") or ""
    ).strip()
    parsed = urlparse(matched if "://" in matched else f"//{matched}")
    port = parsed.port
    scheme = parsed.scheme or str(payload.get("type") or "network")
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
    return f"{port}/{scheme}" if port else scheme


def _iso_mapping(
    *,
    finding_name: str,
    template_id: str = "",
    description: str,
    tags: list[str],
) -> tuple[str, list[dict[str, str]]]:
    """Return cautious Annex A.8 mappings for one technical match."""

    from securescope.evidence.automated_checks import CONTROL_NAMES, classify_nuclei

    mappings = [
        {
            "id": control,
            "name": CONTROL_NAMES[control],
            "status": "Automated mapping",
            "effect": check.effect,
        }
        for check in classify_nuclei(template_id, tags)
        for control in check.mapped_controls
    ]
    return ", ".join(f"{m['id']} {m['name']}" for m in mappings), mappings


def parse_nuclei_result(
    payload: dict[str, Any],
    *,
    report_id: str,
    default_asset_ip: str,
) -> dict[str, Any]:
    """Normalize one Nuclei JSONL object into a SecureScope finding.

    Args:
        payload: One decoded Nuclei JSONL result.
        report_id: Stable SecureScope report identifier.
        default_asset_ip: Fallback asset address.

    Returns:
        A normalized finding dictionary.
    """

    info_value = payload.get("info")
    info = dict(info_value) if isinstance(info_value, dict) else {}
    severity = _severity(info)
    tags = _list(info.get("tags"))
    finding_name = str(
        info.get("name") or payload.get("template-id") or "Nuclei template match"
    ).strip()
    description = str(
        info.get("description")
        or payload.get("extracted-results")
        or "The Nuclei template matched the target."
    ).strip()
    remediation = str(
        info.get("remediation")
        or info.get("solution")
        or "Validate the match and apply the vendor or configuration remediation."
    ).strip()
    iso_controls, iso_mapping = _iso_mapping(
        finding_name=finding_name,
        template_id=str(payload.get("template-id") or ""),
        description=description,
        tags=tags,
    )
    references = _list(info.get("reference"))
    host = str(payload.get("ip") or payload.get("host") or default_asset_ip).strip()
    template_id = str(payload.get("template-id") or "").strip()

    return {
        "Report ID": report_id,
        "Scanner": "ProjectDiscovery Nuclei",
        "scanner_engine": "Nuclei",
        "Finding": finding_name,
        "Severity": severity,
        "CVSS": _cvss(info, severity),
        "CVE": ", ".join(_cves(payload, info)) or "N/A",
        "Host": host or default_asset_ip,
        "Port": _port(payload),
        "Description": description,
        "Solution": remediation,
        "NVT OID": template_id,
        "QOD": str(payload.get("matcher-name") or "Signed Nuclei template match"),
        "ISO Controls": iso_controls,
        "ISO Mapping": iso_mapping,
        "ISO Mapping Status": "Automated mapping" if iso_mapping else "Unmapped observation",
        "ISMS Clauses": "8.1, 8.2, 8.3, 9.1, 10.1",
        "Treatment Priority": severity,
        "Template ID": template_id,
        "Template Path": str(payload.get("template-path") or ""),
        "Matcher": str(payload.get("matcher-name") or ""),
        "Protocol": str(payload.get("type") or ""),
        "Matched At": str(payload.get("matched-at") or ""),
        "Tags": ", ".join(tags),
        "References": "\n".join(references),
        "Timestamp": str(payload.get("timestamp") or ""),
    }


def parse_nuclei_jsonl(
    source: bytes | str | Path,
    *,
    report_id: str,
    asset_ip: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse Nuclei JSONL evidence into findings and summary metadata.

    Args:
        source: JSONL bytes, text, or path.
        report_id: Stable SecureScope report identifier.
        asset_ip: Asset address used as a fallback.

    Returns:
        A tuple containing normalized findings and severity counts.

    Raises:
        NucleiReportError: If the source type is unsupported.
    """

    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8", errors="replace")
    elif isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    elif isinstance(source, str):
        candidate = Path(source)
        if "\n" not in source and candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace")
        else:
            text = source
    else:
        raise NucleiReportError(f"Unsupported Nuclei source type: {type(source).__name__}.")

    findings: list[dict[str, Any]] = []
    invalid_lines = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if not isinstance(payload, dict):
            invalid_lines += 1
            continue
        # Stats JSON lines do not contain one vulnerability template result.
        if not payload.get("template-id") and not payload.get("info"):
            continue
        findings.append(
            parse_nuclei_result(
                payload,
                report_id=report_id,
                default_asset_ip=asset_ip,
            )
        )

    counts = severity_counts(findings)
    metadata = {
        "findings_count": len(findings),
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "info_count": counts["Info"],
        "invalid_jsonl_lines": invalid_lines,
    }
    return findings, metadata


def severity_counts(
    findings: Iterable[dict[str, Any]],
) -> dict[str, int]:
    """Count normalized findings by SecureScope severity."""

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    for finding in findings:
        severity = str(finding.get("Severity") or "Info")
        counts[severity if severity in counts else "Info"] += 1
    return counts


def count_jsonl_findings(path: str | Path) -> int:
    """Count valid Nuclei finding lines without loading the full report."""

    candidate = Path(path)
    if not candidate.is_file():
        return 0
    count = 0
    with candidate.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"template-id"' in line and '"info"' in line:
                count += 1
    return count


def generate_nuclei_pdf(
    record: dict[str, Any],
    *,
    client_name: str,
) -> bytes:
    """Generate a PDF using SecureScope's provider-neutral report layout."""

    payload = dict(record)
    payload.setdefault("scanner", "ProjectDiscovery Nuclei")
    payload.setdefault("scanner_engine", "Nuclei")
    return generate_asset_report_pdf(payload, client_name=client_name)


def safe_filename(value: Any) -> str:
    """Return a filesystem-safe identifier."""

    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "report"))
    return cleaned.strip("._") or "report"


def save_report_bundle(
    *,
    output_root: str | Path,
    client_name: str,
    asset_ip: str,
    report_id: str,
    source_bytes: bytes,
    pdf_bytes: bytes,
) -> tuple[Path, Path]:
    """Save raw Nuclei JSONL and PDF evidence atomically enough for retries."""

    root = Path(output_root)
    directory = (
        root
        / safe_filename(client_name)
        / "nuclei"
        / safe_filename(asset_ip)
        / safe_filename(report_id)
    )
    directory.mkdir(parents=True, exist_ok=True)
    source_path = directory / f"{safe_filename(report_id)}.jsonl"
    pdf_path = directory / f"{safe_filename(report_id)}.pdf"
    source_path.write_bytes(source_bytes)
    pdf_path.write_bytes(pdf_bytes)
    return source_path, pdf_path
