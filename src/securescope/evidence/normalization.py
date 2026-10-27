"""Bounded, non-executing normalization of imported evidence reports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Any, Iterable, Mapping

from lxml import etree

from securescope.evidence.models import NormalizedEvidence, NormalizedObservation
from securescope.evidence.tool_catalog import get_tool

DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_OBSERVATIONS = 10_000
SENSITIVE_KEY = re.compile(
    r"(?:pass(?:word)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization)",
    re.IGNORECASE,
)
ALLOWED_FORMATS = {
    "json",
    "jsonl",
    "sarif",
    "cyclonedx",
    "csv",
    "xml",
    "xccdf",
    "arf",
    "dat",
    "text",
}


class EvidenceNormalizationError(ValueError):
    """Raised when an evidence report is unsafe, unsupported or malformed."""


def _redact(value: Any, key: str = "") -> Any:
    """Remove common secret fields before data reaches normalized evidence."""

    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def _string(value: Any, limit: int = 4_000) -> str:
    """Return a bounded text representation for imported values."""

    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        rendered = json.dumps(_redact(value), ensure_ascii=False, default=str)
    else:
        rendered = str(value)
    return rendered[:limit]


def _severity(value: Any) -> str:
    """Map heterogeneous source severities to the SecureScope vocabulary."""

    raw = str(value or "").strip().lower()
    aliases = {
        "critical": "Critical",
        "high": "High",
        "error": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "warning": "Medium",
        "low": "Low",
        "note": "Low",
        "info": "Info",
        "informational": "Info",
        "none": "Info",
        "unknown": "Unknown",
        "": "Unknown",
    }
    if raw in aliases:
        return aliases[raw]
    try:
        score = float(raw)
    except ValueError:
        return "Unknown"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _identifier(row: Mapping[str, Any], index: int) -> str:
    """Build a stable observation identifier without trusting source paths."""

    lower = {str(key).lower(): value for key, value in row.items()}
    candidate = next(
        (
            lower.get(key)
            for key in ("id", "ruleid", "check_id", "template-id", "vulnerabilityid", "cve", "qid")
            if lower.get(key)
        ),
        None,
    )
    if candidate:
        return _string(candidate, 256)
    digest = hashlib.sha256(
        json.dumps(_redact(dict(row)), sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return f"observation-{index}-{digest[:16]}"


def _observation(row: Mapping[str, Any], index: int) -> NormalizedObservation:
    """Normalize one generic mapping from a supported report."""

    clean = _redact(dict(row))
    lower = {str(key).lower(): value for key, value in clean.items()}
    title = next(
        (
            lower.get(key)
            for key in ("title", "name", "message", "description", "ruleid", "template-id")
            if lower.get(key)
        ),
        f"Imported observation {index}",
    )
    severity = next(
        (
            lower.get(key)
            for key in ("severity", "level", "risk", "priority", "cvss")
            if lower.get(key) is not None
        ),
        "Unknown",
    )
    asset = next(
        (
            lower.get(key)
            for key in ("asset", "host", "hostname", "ip", "target", "uri", "url", "component")
            if lower.get(key)
        ),
        "",
    )
    description = next(
        (
            lower.get(key)
            for key in ("description", "message", "details", "summary", "evidence")
            if lower.get(key)
        ),
        "",
    )
    refs = lower.get("references") or lower.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    if not isinstance(refs, list):
        refs = []
    excluded = {
        "title",
        "name",
        "message",
        "description",
        "details",
        "summary",
        "evidence",
        "severity",
        "level",
        "risk",
        "priority",
        "cvss",
        "asset",
        "host",
        "hostname",
        "ip",
        "target",
        "uri",
        "url",
        "component",
        "references",
        "reference",
    }
    return NormalizedObservation(
        observation_id=_identifier(clean, index),
        title=_string(title, 1_000),
        severity=_severity(severity),
        asset=_string(asset, 1_000),
        description=_string(description),
        references=tuple(_string(item, 1_000) for item in refs[:50]),
        attributes={str(k): v for k, v in clean.items() if str(k).lower() not in excluded},
    )


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    """Yield likely observation mappings from arbitrary JSON."""

    if isinstance(value, Mapping):
        lower_keys = {str(key).lower() for key in value}
        signals = {
            "severity",
            "level",
            "risk",
            "title",
            "name",
            "message",
            "ruleid",
            "vulnerabilityid",
            "template-id",
        }
        if lower_keys & signals:
            yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _sarif_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Extract SARIF results without retaining driver configuration or secrets."""

    rows: list[dict[str, Any]] = []
    for run in payload.get("runs") or []:
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            locations = result.get("locations") or []
            uri = ""
            if locations and isinstance(locations[0], Mapping):
                uri = _string(
                    locations[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
            message = result.get("message") or {}
            rows.append(
                {
                    "id": result.get("ruleId"),
                    "title": result.get("ruleId") or "SARIF result",
                    "description": message.get("text") if isinstance(message, Mapping) else message,
                    "severity": result.get("level"),
                    "asset": uri,
                }
            )
    return rows


def _json_rows(payload: Any, format_name: str) -> list[Mapping[str, Any]]:
    """Extract observations from JSON, SARIF and CycloneDX documents."""

    if format_name == "sarif" and isinstance(payload, Mapping):
        return _sarif_rows(payload)
    if isinstance(payload, Mapping) and payload.get("bomFormat") == "CycloneDX":
        rows: list[Mapping[str, Any]] = []
        for vulnerability in payload.get("vulnerabilities") or []:
            if isinstance(vulnerability, Mapping):
                ratings = vulnerability.get("ratings") or []
                severity = (
                    ratings[0].get("severity")
                    if ratings and isinstance(ratings[0], Mapping)
                    else "Unknown"
                )
                rows.append(
                    {
                        "id": vulnerability.get("id"),
                        "title": vulnerability.get("id") or "CycloneDX vulnerability",
                        "description": vulnerability.get("description")
                        or vulnerability.get("detail"),
                        "severity": severity,
                        "references": [
                            item.get("url")
                            for item in vulnerability.get("references") or []
                            if isinstance(item, Mapping)
                        ],
                    }
                )
        return rows
    return list(_walk_mappings(payload))


def _xml_rows(content: bytes) -> list[dict[str, Any]]:
    """Extract leaf-oriented XML rows using a hardened parser."""

    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", content, flags=re.IGNORECASE):
        raise EvidenceNormalizationError("XML DTD and entity declarations are forbidden.")
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
        remove_comments=True,
    )
    try:
        root = etree.fromstring(content, parser=parser)
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise EvidenceNormalizationError(f"Invalid or unsafe XML report: {exc}") from exc
    rows: list[dict[str, Any]] = []
    candidate_names = {
        "result",
        "finding",
        "vulnerability",
        "issue",
        "rule-result",
        "item",
        "alertitem",
    }
    for element in root.iter():
        local = etree.QName(element).localname.lower()
        if local not in candidate_names:
            continue
        row = {etree.QName(child).localname: _string(child.text) for child in element if child.text}
        row.update({str(key): _string(value) for key, value in element.attrib.items()})
        if row:
            rows.append(row)
    if not rows:
        rows.append(
            {
                "title": etree.QName(root).localname,
                "description": "Structured XML evidence imported.",
            }
        )
    return rows


def _detect_format(filename: str, content: bytes, requested: str | None) -> str:
    """Detect one supported format from an explicit hint, suffix and content."""

    format_name = (
        requested.strip().lower() if requested else PurePath(filename).suffix.lower().lstrip(".")
    )
    format_name = format_name or "text"
    if format_name == "json" and b'"version"' in content[:4_096] and b'"runs"' in content[:16_384]:
        format_name = "sarif"
    if format_name == "json" and b'"bomFormat"' in content[:4_096]:
        format_name = "cyclonedx"
    aliases = {"jsonlines": "jsonl", "ndjson": "jsonl", "txt": "text", "xccdf.xml": "xccdf"}
    format_name = aliases.get(format_name, format_name)
    if format_name not in ALLOWED_FORMATS:
        raise EvidenceNormalizationError(f"Unsupported evidence format: {format_name}")
    return format_name


def normalize_report(
    tool_id: str,
    filename: str,
    content: bytes,
    *,
    format_hint: str | None = None,
    max_bytes: int = DEFAULT_MAX_REPORT_BYTES,
    max_observations: int = DEFAULT_MAX_OBSERVATIONS,
) -> NormalizedEvidence:
    """Normalize one bounded report without executing source-controlled content."""

    get_tool(tool_id)
    if not filename or PurePath(filename).name != filename or "/" in filename or "\\" in filename:
        raise EvidenceNormalizationError("Evidence filename must not contain a path.")
    if not content:
        raise EvidenceNormalizationError("Evidence report is empty.")
    if len(content) > max_bytes:
        raise EvidenceNormalizationError(f"Evidence report exceeds {max_bytes} bytes.")
    format_name = _detect_format(filename, content, format_hint)
    rows: list[Mapping[str, Any]]
    try:
        if format_name in {"json", "sarif", "cyclonedx"}:
            payload = json.loads(content.decode("utf-8-sig"))
            rows = _json_rows(payload, format_name)
        elif format_name == "jsonl":
            rows = []
            for line in content.decode("utf-8-sig").splitlines():
                if line.strip():
                    item = json.loads(line)
                    if not isinstance(item, Mapping):
                        raise EvidenceNormalizationError("JSONL entries must be objects.")
                    rows.append(item)
        elif format_name == "csv":
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
        elif format_name in {"xml", "xccdf", "arf"}:
            rows = _xml_rows(content)
        elif format_name == "dat":
            rows = []
            for line in content.decode("utf-8", errors="replace").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    rows.append({"title": key.strip(), "description": value.strip()})
        else:
            text = content.decode("utf-8", errors="replace")
            rows = [{"title": "Imported text evidence", "description": text[:20_000]}]
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise EvidenceNormalizationError(f"Malformed {format_name} report: {exc}") from exc
    assurance = {}
    if format_name == "json":
        from securescope.evidence.assurance_facts import normalize_assurance_facts

        envelope = json.loads(content)
        if isinstance(envelope, dict):
            metadata = envelope.get("metadata")
            if isinstance(metadata, dict):
                assurance = normalize_assurance_facts(tool_id, metadata.get("assurance"))
    truncated = len(rows) > max_observations
    observations = tuple(
        _observation(row, index) for index, row in enumerate(rows[:max_observations], 1)
    )
    warnings = (
        (f"Only the first {max_observations} observations were normalized.",) if truncated else ()
    )
    return NormalizedEvidence(
        tool_id=tool_id,
        format_name=format_name,
        source_filename=filename,
        parsed_at=datetime.now(timezone.utc),
        observations=observations,
        metadata={
            "source_row_count": len(rows),
            "normalized_count": len(observations),
            "assurance": assurance,
        },
        parser_warnings=warnings,
    )
