from __future__ import annotations

import json

from securescope.compliance.remediation_assistant import (
    deterministic_remediation_plan,
    generate_remediation_plan,
    remediation_plan_markdown,
)


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeSession:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.request_json: dict | None = None
        self.headers: dict | None = None

    def post(self, _url: str, **kwargs):
        self.request_json = kwargs.get("json")
        self.headers = kwargs.get("headers")
        return _FakeResponse(self.payload)


def test_deterministic_ntp_remediation() -> None:
    plan = deterministic_remediation_plan(
        {
            "Control": "A.8.17",
            "Control name": "Clock synchronization",
            "Automatic status": "Gap detected",
            "Gaps": ["No current Wazuh evidence for one Nmap asset"],
        },
        {"priority": "High", "control_id": "A.8.17"},
    )
    assert plan["source"] == "deterministic"
    assert plan["control_id"] == "A.8.17"
    assert any("Wazuh" in item for item in plan["immediate_actions"])
    assert "advisory" in remediation_plan_markdown(plan).lower()


def test_disabled_ai_returns_deterministic_plan() -> None:
    plan = generate_remediation_plan(
        {"Control": "A.8.8", "Gaps": ["Critical CVE"]},
        {"priority": "Critical"},
        use_ai=False,
    )
    assert plan["source"] == "deterministic"
    assert plan["ai_status"] == "disabled"


def test_optional_ai_output_is_constrained(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    generated = {
        "risk_statement": "Evidence-backed risk",
        "immediate_actions": ["Patch the affected service"],
        "verification_steps": ["Re-scan the exact asset"],
        "evidence_required": ["Change ticket"],
        "owner_suggestion": "Infrastructure owner",
        "limitations": ["Analyst validation required"],
    }
    session = _FakeSession(
        {
            "output": [
                {
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(generated),
                        }
                    ]
                }
            ]
        }
    )
    plan = generate_remediation_plan(
        {
            "Control": "A.8.8",
            "Gaps": ["CVE remains present"],
            "api_token": "must-not-leak",
        },
        use_ai=True,
        session=session,
    )
    assert plan["source"] == "openai"
    assert plan["ai_status"] == "completed"
    assert session.request_json is not None
    assert "must-not-leak" not in session.request_json["input"]
    assert session.headers["Authorization"] == "Bearer test-key"


def test_ai_failure_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")

    class BrokenSession:
        def post(self, *_args, **_kwargs):
            raise TimeoutError("network unavailable")

    plan = generate_remediation_plan(
        {"Control": "A.8.20", "Gaps": ["Unexpected exposure"]},
        use_ai=True,
        session=BrokenSession(),
    )
    assert plan["source"] == "deterministic"
    assert plan["ai_status"] == "fallback"
    assert "TimeoutError" in plan["ai_error"]
