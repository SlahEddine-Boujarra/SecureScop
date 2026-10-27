"""Grounded remediation planning for SecureScope ISO control gaps.

The module always provides a deterministic, evidence-based plan. An optional
OpenAI Responses API call can refine the wording when explicitly enabled. AI
output is advisory only: it never changes a control status or corrective action
without a separate analyst action in the Streamlit UI.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Iterable

import requests

DEFAULT_RESPONSES_URL = "https://api.openai.com/v1/responses"
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
)


class RemediationAssistantError(RuntimeError):
    """Raised when the optional AI remediation call cannot be used safely."""


def _as_list(value: Any) -> list[str]:
    """Normalize arbitrary text/list input to a compact unique list."""
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    output: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if text and text not in output:
            output.append(text[:1200])
    return output


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    """Remove secret-looking keys and bound payload size before cloud use."""
    if depth > 5:
        return "[depth limit]"
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(part in lowered for part in _SECRET_KEY_PARTS):
                continue
            output[key_text[:100]] = _sanitize(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item, depth=depth + 1) for item in list(value)[:30]]
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def _finding_summary(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only remediation-relevant vulnerability fields."""
    rows: list[dict[str, Any]] = []
    for finding in list(findings)[:20]:
        if not isinstance(finding, dict):
            continue
        rows.append(
            {
                "finding": finding.get("Finding") or finding.get("name"),
                "host": finding.get("Host") or finding.get("host"),
                "severity": finding.get("Severity") or finding.get("severity"),
                "cve": finding.get("CVE") or finding.get("cve"),
                "cvss": finding.get("CVSS") or finding.get("cvss"),
                "epss": finding.get("epss"),
                "known_exploited": finding.get("kev"),
                "solution": finding.get("Solution") or finding.get("solution"),
            }
        )
    return rows


def deterministic_remediation_plan(
    assessment: dict[str, Any],
    action: dict[str, Any] | None = None,
    findings: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a transparent remediation plan without any external AI service."""
    action = dict(action or {})
    control_id = str(
        assessment.get("Control")
        or assessment.get("control_id")
        or action.get("control_id")
        or "Unknown control"
    )
    control_name = str(
        assessment.get("Control name")
        or assessment.get("control_name")
        or action.get("title")
        or "Technical control gap"
    )
    gaps = _as_list(assessment.get("Gaps") or assessment.get("gaps"))
    evidence = _as_list(assessment.get("Evidence") or assessment.get("evidence"))
    automatic_status = str(
        assessment.get("Automatic status")
        or assessment.get("automated_status")
        or "Insufficient evidence"
    )
    priority = str(action.get("priority") or "Medium")
    related_findings = _finding_summary(findings)

    immediate_actions = [
        "Confirm the control scope, affected assets and accountable owner.",
        "Validate each detected gap against the organization's approved policy and risk criteria.",
        (
            "Implement or document the missing safeguard without changing "
            "evidence records retroactively."
        ),
    ]
    verification_steps = [
        "Collect fresh evidence from the same authoritative source used by the assessment rule.",
        (
            "Re-run the relevant SecureScope collection or scan and confirm "
            "that the gap no longer reproduces."
        ),
        "Have an authorized analyst review the evidence and record the final control decision.",
    ]
    evidence_required = [
        "Implementation record or approved configuration",
        "Fresh automated evidence after remediation",
        "Analyst validation rationale and review date",
    ]

    if control_id == "A.8.17":
        immediate_actions = [
            (
                "Ensure every in-scope endpoint has an active Wazuh agent and the "
                "SECURESCOPE_NTP probe deployed."
            ),
            (
                "Configure an approved common time source and ensure the "
                "operating-system time service reports synchronized."
            ),
            (
                "Correct endpoints whose source offset or manager/agent delta "
                "exceeds the approved threshold."
            ),
        ]
        verification_steps = [
            "Run the endpoint probe locally and confirm it emits one SECURESCOPE_NTP JSON event.",
            (
                "Use Wazuh logtest and the indexer to confirm rules 100200/100201 "
                "and fresh evidence ingestion."
            ),
            (
                "Collect clock evidence in SecureScope and confirm every Nmap "
                "asset is matched, current and synchronized."
            ),
        ]
        evidence_required = [
            "Approved time-source list or time-synchronization policy",
            "Fresh Wazuh endpoint clock evidence for every in-scope Nmap asset",
            (
                "Source offset, manager/agent delta and evidence freshness within "
                "configured thresholds"
            ),
        ]
    elif control_id == "A.8.8":
        immediate_actions = [
            "Prioritize CISA KEV and high-EPSS vulnerabilities before severity-only items.",
            (
                "Patch, upgrade, remove or isolate affected products according to "
                "vendor guidance and business risk."
            ),
            (
                "Record temporary mitigations and an expiry date when immediate "
                "patching is not possible."
            ),
        ]
        verification_steps = [
            "Run a new OpenVAS attempt against each affected asset after the change window.",
            (
                "Confirm that the original CVE/plugin no longer appears or that an"
                " accepted exception is documented."
            ),
            "Refresh NVD, EPSS and KEV data and re-evaluate remediation priority.",
        ]
        evidence_required = [
            "Patch/change ticket and affected-asset list",
            "Post-remediation OpenVAS report with exact scan/history identity",
            "Risk acceptance and compensating controls for deferred vulnerabilities",
        ]
    elif control_id in {"A.8.15", "A.8.16"}:
        immediate_actions = [
            "Restore Wazuh coverage for all in-scope assets and verify active agent status.",
            "Confirm required security events are collected, decoded, retained and reviewed.",
            "Define escalation and response ownership for relevant alerts.",
        ]
        verification_steps = [
            "Generate a controlled test event on each representative platform.",
            (
                "Confirm the event reaches Wazuh, matches the expected "
                "decoder/rule and is visible in SecureScope evidence."
            ),
            "Review retention, access control and alert-handling records with the control owner.",
        ]
    elif control_id in {"A.8.20", "A.8.21", "A.8.22"}:
        immediate_actions = [
            "Review Nmap and OpenVAS exposure against the approved network/service baseline.",
            (
                "Close unnecessary ports, restrict administrative access and "
                "document required network services."
            ),
            (
                "Validate segmentation and monitoring controls for high-value or "
                "externally reachable assets."
            ),
        ]
        verification_steps = [
            "Run an authorized Nmap discovery and service scan from the relevant network zone.",
            "Run a OpenVAS validation scan and compare the result with the approved baseline.",
            "Record analyst approval for any intentionally exposed service.",
        ]

    if gaps:
        gap_text = "; ".join(gaps[:5])
    else:
        gap_text = "The automated assessment lacks sufficient current evidence."

    finding_text = ""
    if related_findings:
        finding_text = (
            f" {len(related_findings)} related technical finding(s) were supplied "
            "for prioritization."
        )

    return {
        "source": "deterministic",
        "advisory": True,
        "control_id": control_id,
        "control_name": control_name,
        "priority": priority,
        "risk_statement": (
            f"{control_id} is currently assessed as {automatic_status}. "
            f"Primary gap: {gap_text}.{finding_text}"
        ),
        "immediate_actions": immediate_actions,
        "verification_steps": verification_steps,
        "evidence_required": evidence_required,
        "owner_suggestion": (
            action.get("owner") or "Control owner with system/platform administrator support"
        ),
        "related_findings": related_findings,
        "existing_evidence": evidence[:10],
        "limitations": [
            "This plan is advisory and does not prove implementation or certification.",
            "Final applicability and control status require authorized analyst validation.",
        ],
    }


def _extract_response_text(payload: dict[str, Any]) -> str:
    """Extract assistant text from a raw Responses API payload."""
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    fragments: list[str] = []
    for item in payload.get("output") or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content") or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text")
            if isinstance(text, str) and text.strip():
                fragments.append(text.strip())
    return "\n".join(fragments)


def _parse_json_text(text: str) -> dict[str, Any]:
    """Parse a JSON object even when surrounded by Markdown fences."""
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if not match:
            raise RemediationAssistantError("The AI response did not contain a JSON object.")
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise RemediationAssistantError("The AI response was not a JSON object.")
    return value


def _normalize_ai_plan(
    value: dict[str, Any],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    """Constrain external output to the local remediation-plan schema."""
    plan = dict(fallback)
    plan.update(
        {
            "source": "openai",
            "advisory": True,
            "risk_statement": str(value.get("risk_statement") or fallback["risk_statement"])[:3000],
            "immediate_actions": _as_list(
                value.get("immediate_actions") or fallback["immediate_actions"]
            )[:10],
            "verification_steps": _as_list(
                value.get("verification_steps") or fallback["verification_steps"]
            )[:10],
            "evidence_required": _as_list(
                value.get("evidence_required") or fallback["evidence_required"]
            )[:10],
            "owner_suggestion": str(value.get("owner_suggestion") or fallback["owner_suggestion"])[
                :500
            ],
            "limitations": _as_list(value.get("limitations") or fallback["limitations"])[:10],
        }
    )
    return plan


def generate_remediation_plan(
    assessment: dict[str, Any],
    action: dict[str, Any] | None = None,
    findings: Iterable[dict[str, Any]] = (),
    *,
    use_ai: bool | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Generate a deterministic plan and optionally refine it with OpenAI.

    The function always returns a usable deterministic plan when AI is disabled,
    unconfigured, unavailable or malformed. No secret-looking fields are sent.
    """
    fallback = deterministic_remediation_plan(assessment, action, findings)
    enabled = (
        os.getenv("AI_REMEDIATION_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        if use_ai is None
        else bool(use_ai)
    )
    if not enabled:
        fallback["ai_status"] = "disabled"
        return fallback

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    model = os.getenv("OPENAI_MODEL", "").strip()
    if not api_key or not model:
        fallback["ai_status"] = "not configured"
        return fallback

    endpoint = os.getenv(
        "OPENAI_RESPONSES_URL",
        DEFAULT_RESPONSES_URL,
    ).strip()
    timeout = max(5, int(os.getenv("AI_REMEDIATION_TIMEOUT_SECONDS", "45")))
    client = session or requests.Session()
    context = _sanitize(
        {
            "assessment": assessment,
            "corrective_action": action or {},
            "related_findings": _finding_summary(findings),
            "deterministic_plan": fallback,
        }
    )
    instructions = (
        "You are a cautious ISO/IEC 27001:2022 technical-control remediation "
        "assistant. Use only the supplied evidence. Do not claim certification, "
        "implementation, exploitability or successful remediation unless the "
        "evidence proves it. Return one JSON object with exactly these keys: "
        "risk_statement, immediate_actions, verification_steps, "
        "evidence_required, owner_suggestion, limitations. List values must be "
        "arrays of concise strings. Preserve the supplied control ID and scope."
    )

    try:
        response = client.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "instructions": instructions,
                "input": json.dumps(context, ensure_ascii=False),
                "store": False,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        response_payload = response.json()
        text = _extract_response_text(response_payload)
        if not text:
            raise RemediationAssistantError("The Responses API returned no output text.")
        plan = _normalize_ai_plan(_parse_json_text(text), fallback)
        plan["ai_status"] = "completed"
        return plan
    except Exception as exc:
        fallback["ai_status"] = "fallback"
        fallback["ai_error"] = f"{type(exc).__name__}: {exc}"[:1000]
        return fallback


def remediation_plan_markdown(plan: dict[str, Any]) -> str:
    """Render a plan as analyst-editable Markdown."""
    lines = [
        f"## {plan.get('control_id', 'Control')} — Remediation plan",
        "",
        f"**Priority:** {plan.get('priority', 'Medium')}",
        f"**Suggested owner:** {plan.get('owner_suggestion', '')}",
        f"**Plan source:** {plan.get('source', 'deterministic')} (advisory)",
        "",
        "### Risk statement",
        str(plan.get("risk_statement") or ""),
        "",
        "### Immediate actions",
    ]
    lines.extend(f"- {item}" for item in _as_list(plan.get("immediate_actions")))
    lines.extend(["", "### Verification steps"])
    lines.extend(f"- {item}" for item in _as_list(plan.get("verification_steps")))
    lines.extend(["", "### Evidence required"])
    lines.extend(f"- {item}" for item in _as_list(plan.get("evidence_required")))
    lines.extend(["", "### Limitations"])
    lines.extend(f"- {item}" for item in _as_list(plan.get("limitations")))
    return "\n".join(lines).strip() + "\n"
