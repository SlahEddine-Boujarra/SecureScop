"""CISO Assistant API client for SecureScope scanner integrations.

The client keeps CISO objects idempotent: a later scan updates the same asset,
vulnerability and risk scenario rather than creating duplicates.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

import requests
import urllib3


class CisoApiError(RuntimeError):
    """Raised when CISO Assistant returns an unsuccessful API response."""


@dataclass(frozen=True)
class CisoConfig:
    """Configuration loaded from environment variables."""

    base_url: str
    token: str
    verify_tls: bool
    timeout_seconds: int
    scope_folder_name: str
    perimeter_name: str
    perimeter_status: str
    risk_assessment_name: str
    risk_assessment_ref_id: str
    risk_matrix_id: str


def load_ciso_config() -> CisoConfig:
    """Load and validate CISO Assistant settings from environment variables."""
    base_url = os.getenv("CISO_BASE_URL", "").strip().rstrip("/")
    token = os.getenv("CISO_API_TOKEN", "").strip()
    verify_tls = os.getenv("CISO_VERIFY_TLS", "false").strip().lower() in {
        "true",
        "1",
        "yes",
    }

    if not base_url:
        raise CisoApiError("Missing CISO_BASE_URL in .env.")
    if not token:
        raise CisoApiError("Missing CISO_API_TOKEN in .env.")

    return CisoConfig(
        base_url=base_url,
        token=token,
        verify_tls=verify_tls,
        timeout_seconds=int(os.getenv("CISO_TIMEOUT_SECONDS", "30")),
        scope_folder_name=os.getenv(
            "CISO_SCOPE_FOLDER_NAME",
            os.getenv("CISO_DOMAIN_NAME", "Vulnerability Scanning Lab"),
        ).strip(),
        perimeter_name=os.getenv(
            "CISO_PERIMETER_NAME",
            "Internal Network 192.168.100.0-24",
        ).strip(),
        perimeter_status=os.getenv("CISO_PERIMETER_STATUS", "in_prod").strip(),
        risk_assessment_name=os.getenv(
            "CISO_RISK_ASSESSMENT_NAME",
            "SecureScope Technical Risk Assessment",
        ).strip(),
        risk_assessment_ref_id=os.getenv(
            "CISO_RISK_ASSESSMENT_REF_ID",
            "openvas-technical-risk-assessment",
        ).strip(),
        risk_matrix_id=os.getenv("CISO_RISK_MATRIX_ID", "").strip(),
    )


class CisoAssistantClient:
    """Small REST client for CISO Assistant."""

    def __init__(self, config: CisoConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {config.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        if not config.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        try:
            response = self.session.request(
                method=method,
                url=self._url(path),
                params=params,
                json=payload,
                timeout=self.config.timeout_seconds,
                verify=self.config.verify_tls,
            )
        except requests.RequestException as exc:
            raise CisoApiError(f"Could not reach CISO Assistant: {exc}") from exc

        if not response.ok:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text[:1000]
            raise CisoApiError(f"{method} {path} failed with HTTP {response.status_code}: {detail}")

        if response.status_code == 204 or not response.content:
            return None

        try:
            return response.json()
        except ValueError:
            return response.text

    @staticmethod
    def _results(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            results = payload.get("results", [])
            return results if isinstance(results, list) else []
        return payload if isinstance(payload, list) else []

    @staticmethod
    def _relation_id(value: Any) -> str | None:
        if isinstance(value, dict):
            identifier = value.get("id")
            return str(identifier) if identifier else None
        if isinstance(value, str):
            return value
        return None

    @staticmethod
    def _short_ref(prefix: str, *parts: str) -> str:
        """Create a stable CISO ref_id shorter than the API 100-char limit."""
        raw = "|".join(str(part) for part in parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}-{digest}"

    def current_user(self) -> dict[str, Any]:
        payload = self._request("GET", "/api/iam/current-user/")
        return payload if isinstance(payload, dict) else {}

    def list_objects(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"limit": 100}
        if params:
            query.update(params)
        return self._results(self._request("GET", endpoint, params=query))

    def _find_by_ref_id(
        self,
        endpoint: str,
        ref_id: str,
    ) -> dict[str, Any] | None:
        """Find an object by its stable integration reference ID."""
        candidates = self.list_objects(endpoint, params={"ref_id": ref_id})
        for item in candidates:
            if item.get("ref_id") == ref_id:
                return item
        return None

    def _find_by_name(
        self,
        endpoint: str,
        name: str,
        *,
        folder_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Find an object by exact name, with an optional folder check."""
        candidates = self.list_objects(endpoint, params={"name": name})
        for item in candidates:
            if item.get("name") != name:
                continue
            if folder_id is None:
                return item
            if self._relation_id(item.get("folder")) == folder_id:
                return item
        return None

    def _upsert(
        self,
        endpoint: str,
        *,
        ref_id: str,
        create_payload: dict[str, Any],
        update_payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Create an object once, then PATCH it on later synchronization."""
        existing = self._find_by_ref_id(endpoint, ref_id)
        if not existing:
            created = self._request("POST", endpoint, payload=create_payload)
            if not isinstance(created, dict):
                raise CisoApiError(f"CISO did not return an object for POST {endpoint}.")
            return created, True

        object_id = existing.get("id")
        if not object_id:
            raise CisoApiError(f"Existing CISO object at {endpoint} has no ID.")

        if update_payload is None:
            return existing, False

        updated = self._request(
            "PATCH",
            f"{endpoint}{object_id}/",
            payload=update_payload,
        )
        if not isinstance(updated, dict):
            raise CisoApiError(f"CISO did not return an object for PATCH {endpoint}.")
        return updated, False

    def get_or_create_scope_folder(self) -> dict[str, Any]:
        existing = self._find_by_name(
            "/api/folders/",
            self.config.scope_folder_name,
        )
        if existing:
            return existing
        created = self._request(
            "POST",
            "/api/folders/",
            payload={
                "name": self.config.scope_folder_name,
                "description": (
                    "Automatically created by SecureScope asset discovery and CISO "
                    "Assistant integration."
                ),
                "parent_folder": None,
                "create_iam_groups": False,
                "is_published": True,
            },
        )
        return created

    def get_or_create_perimeter(self, folder_id: str) -> dict[str, Any]:
        existing = self._find_by_name(
            "/api/perimeters/",
            self.config.perimeter_name,
            folder_id=folder_id,
        )
        if existing:
            return existing

        payload = {
            "name": self.config.perimeter_name,
            "description": (
                "Authorized internal lab perimeter used for Nmap discovery "
                "and vulnerability scanning evidence."
            ),
            "folder": folder_id,
            "lc_status": self.config.perimeter_status,
            "default_assignee": [],
            "is_published": True,
        }
        try:
            created = self._request("POST", "/api/perimeters/", payload=payload)
            return created
        except CisoApiError as exc:
            # A previous process may have created the perimeter between GET/POST.
            if "already used in this scope" not in str(exc):
                raise
            for perimeter in self.list_objects("/api/perimeters/"):
                if perimeter.get("name") == self.config.perimeter_name:
                    return perimeter
            raise

    def bootstrap_scope(self) -> tuple[dict[str, Any], dict[str, Any]]:
        folder = self.get_or_create_scope_folder()
        folder_id = folder.get("id")
        if not folder_id:
            raise CisoApiError("CISO Assistant did not return a folder ID.")
        perimeter = self.get_or_create_perimeter(str(folder_id))
        return folder, perimeter

    def sync_asset(
        self,
        *,
        folder_id: str,
        name: str,
        description: str,
        ref_id: str,
        asset_type: str = "SP",
    ) -> tuple[dict[str, Any], bool]:
        payload = {
            "name": name[:200],
            "description": description,
            "type": asset_type,
            "folder": folder_id,
            "ref_id": ref_id[:100],
            "is_published": True,
        }
        return self._upsert(
            "/api/assets/",
            ref_id=ref_id[:100],
            create_payload=payload,
            update_payload=payload,
        )

    def get_or_create_findings_assessment(
        self,
        *,
        folder_id: str,
        perimeter_id: str,
        report_id: str,
        target_ip: str,
    ) -> tuple[dict[str, Any], bool]:
        ref_id = self._short_ref("openvas-report", report_id)
        payload = {
            "name": f"SecureScope scan {target_ip} {report_id[:8]}"[:200],
            "description": (
                "Vulnerability scan imported automatically by the "
                "Vulnerability Management Platform."
            ),
            "ref_id": ref_id,
            "category": "pentest",
            "status": "done",
            "folder": folder_id,
            "perimeter": perimeter_id,
            "is_published": True,
        }
        return self._upsert(
            "/api/findings-assessments/",
            ref_id=ref_id,
            create_payload=payload,
            update_payload=None,
        )

    def get_enabled_risk_matrix(self) -> dict[str, Any]:
        matrices = self.list_objects("/api/risk-matrices/")

        if self.config.risk_matrix_id:
            for matrix in matrices:
                if matrix.get("id") == self.config.risk_matrix_id:
                    return matrix
            raise CisoApiError(
                "CISO_RISK_MATRIX_ID does not match a risk matrix accessible " "to this API token."
            )

        enabled = [matrix for matrix in matrices if matrix.get("is_enabled") is not False]
        if enabled:
            return enabled[0]

        raise CisoApiError(
            "No enabled CISO risk matrix is available. Add a risk matrix in "
            "CISO Assistant, then restart the synchronization."
        )

    def get_or_create_risk_assessment(
        self,
        *,
        folder_id: str,
        perimeter_id: str,
    ) -> tuple[dict[str, Any], bool]:
        ref_id = self.config.risk_assessment_ref_id[:100]
        existing = self._find_by_ref_id("/api/risk-assessments/", ref_id)
        if existing:
            return existing, False

        matrix = self.get_enabled_risk_matrix()
        matrix_id = matrix.get("id")
        if not matrix_id:
            raise CisoApiError("The selected CISO risk matrix did not return an ID.")

        payload = {
            "name": self.config.risk_assessment_name[:200],
            "description": (
                "Risk assessment automatically maintained from SecureScope "
                "vulnerability findings."
            ),
            "ref_id": ref_id,
            "status": "in_progress",
            "folder": folder_id,
            "perimeter": perimeter_id,
            "risk_matrix": matrix_id,
            "auto_sync": False,
            "is_published": True,
        }
        created = self._request("POST", "/api/risk-assessments/", payload=payload)
        if not isinstance(created, dict):
            raise CisoApiError("CISO did not return the created risk assessment.")
        return created, True

    def sync_vulnerability(
        self,
        *,
        finding: dict[str, Any],
        folder_id: str,
        asset_id: str,
        detected_on: str,
    ) -> tuple[dict[str, Any], bool]:
        ref_id = str(finding["vulnerability_ref_id"])[:100]
        payload = {
            "name": str(finding["Finding"])[:200],
            "description": build_openvas_description(finding),
            "ref_id": ref_id,
            "status": "potential",
            "severity": cvss_to_ciso_severity(float(finding["CVSS"])),
            "detected_at": detected_on,
            "folder": folder_id,
            "assets": [asset_id],
            "is_published": True,
        }
        return self._upsert(
            "/api/vulnerabilities/",
            ref_id=ref_id,
            create_payload=payload,
            update_payload=payload,
        )

    def sync_finding(
        self,
        *,
        finding: dict[str, Any],
        findings_assessment_id: str,
        vulnerability_id: str,
    ) -> tuple[dict[str, Any], bool]:
        ref_id = str(finding["finding_ref_id"])[:100]
        payload = {
            "name": str(finding["Finding"])[:200],
            "description": build_openvas_description(finding),
            "ref_id": ref_id,
            "priority": cvss_to_priority(float(finding["CVSS"])),
            "severity": cvss_to_ciso_severity(float(finding["CVSS"])),
            "status": "confirmed",
            "findings_assessment": findings_assessment_id,
            "vulnerabilities": [vulnerability_id],
            "is_published": True,
        }
        return self._upsert(
            "/api/findings/",
            ref_id=ref_id,
            create_payload=payload,
            update_payload=payload,
        )

    def sync_risk_scenario(
        self,
        *,
        finding: dict[str, Any],
        risk_assessment_id: str,
        asset_id: str,
        vulnerability_id: str,
    ) -> tuple[dict[str, Any], bool]:
        ref_id = str(finding["risk_ref_id"])[:100]
        create_payload = {
            "name": f"Scanner risk: {finding['Finding']}"[:200],
            "description": build_openvas_risk_description(finding),
            "ref_id": ref_id,
            "risk_assessment": risk_assessment_id,
            "assets": [asset_id],
            "vulnerabilities": [vulnerability_id],
            "treatment": "open",
            "justification": (
                "Automatically created from a SecureScope scanner finding. The scanner "
                "result requires analyst validation before treatment approval."
            ),
            "is_published": True,
        }
        # Do not replace the treatment chosen later by a CISO user.
        update_payload = {
            "description": build_openvas_risk_description(finding),
            "assets": [asset_id],
            "vulnerabilities": [vulnerability_id],
        }
        return self._upsert(
            "/api/risk-scenarios/",
            ref_id=ref_id,
            create_payload=create_payload,
            update_payload=update_payload,
        )

    def sync_openvas_findings(
        self,
        *,
        findings: list[dict[str, Any]],
        folder_id: str,
        perimeter_id: str,
        asset_id: str,
        report_id: str,
        target_ip: str,
        risk_min_cvss: float,
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Synchronize one normalized scanner report without duplicates."""
        if not report_id:
            raise CisoApiError("The scanner did not return a report ID to synchronize.")

        def progress(message: str) -> None:
            if progress_callback:
                progress_callback(message)

        findings_assessment, assessment_created = self.get_or_create_findings_assessment(
            folder_id=folder_id,
            perimeter_id=perimeter_id,
            report_id=report_id,
            target_ip=target_ip,
        )
        findings_assessment_id = findings_assessment.get("id")
        if not findings_assessment_id:
            raise CisoApiError("CISO did not return an ID for the findings assessment.")

        result: dict[str, Any] = {
            "findings_assessment_id": findings_assessment_id,
            "findings_assessment_created": assessment_created,
            "processed": 0,
            "skipped_info": 0,
            "vulnerabilities_created": 0,
            "vulnerabilities_updated": 0,
            "findings_created": 0,
            "findings_updated": 0,
            "risks_created": 0,
            "risks_updated": 0,
            "errors": [],
            "risk_assessment_id": None,
        }

        risk_assessment_id: str | None = None
        requires_risk = any(float(item.get("CVSS", 0)) >= risk_min_cvss for item in findings)
        if requires_risk:
            try:
                risk_assessment, _created = self.get_or_create_risk_assessment(
                    folder_id=folder_id,
                    perimeter_id=perimeter_id,
                )
                risk_assessment_id = str(risk_assessment.get("id") or "") or None
                result["risk_assessment_id"] = risk_assessment_id
                if not risk_assessment_id:
                    result["errors"].append("CISO risk assessment did not return an ID.")
            except CisoApiError as exc:
                result["errors"].append(f"Risk scenarios skipped: {exc}")

        today = date.today().isoformat()
        total = len(findings)
        for index, finding in enumerate(findings, start=1):
            cvss = float(finding.get("CVSS", 0))
            if cvss <= 0:
                result["skipped_info"] += 1
                continue

            result["processed"] += 1
            progress(f"Synchronizing CISO finding {index}/{total}: {finding['Finding'][:60]}")
            try:
                vulnerability, vulnerability_created = self.sync_vulnerability(
                    finding=finding,
                    folder_id=folder_id,
                    asset_id=asset_id,
                    detected_on=today,
                )
                vulnerability_id = vulnerability.get("id")
                if not vulnerability_id:
                    raise CisoApiError("CISO vulnerability did not return an ID.")

                if vulnerability_created:
                    result["vulnerabilities_created"] += 1
                else:
                    result["vulnerabilities_updated"] += 1

                _finding, finding_created = self.sync_finding(
                    finding=finding,
                    findings_assessment_id=str(findings_assessment_id),
                    vulnerability_id=str(vulnerability_id),
                )
                if finding_created:
                    result["findings_created"] += 1
                else:
                    result["findings_updated"] += 1

                if risk_assessment_id and cvss >= risk_min_cvss:
                    _risk, risk_created = self.sync_risk_scenario(
                        finding=finding,
                        risk_assessment_id=risk_assessment_id,
                        asset_id=asset_id,
                        vulnerability_id=str(vulnerability_id),
                    )
                    if risk_created:
                        result["risks_created"] += 1
                    else:
                        result["risks_updated"] += 1

            except CisoApiError as exc:
                result["errors"].append(f"{finding['Finding'][:80]}: {exc}")

        return result

    def sync_scanner_findings(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Synchronize normalized findings from any scanner provider."""
        return self.sync_openvas_findings(**kwargs)


def cvss_to_ciso_severity(cvss: float) -> int:
    """Map CVSS scores to CISO severity enum values (0 through 4)."""
    if cvss >= 9:
        return 4
    if cvss >= 7:
        return 3
    if cvss >= 4:
        return 2
    if cvss > 0:
        return 1
    return 0


def cvss_to_priority(cvss: float) -> int:
    """Map CVSS scores to CISO priority values, where P1 is highest."""
    if cvss >= 9:
        return 1
    if cvss >= 7:
        return 2
    if cvss >= 4:
        return 3
    return 4


def build_openvas_description(finding: dict[str, Any]) -> str:
    """Turn a normalized scanner finding into a readable CISO description."""
    source_label = (
        finding.get("Scanner") or finding.get("scanner") or "SecureScope vulnerability scanner"
    )
    mapping_status = finding.get("ISO Mapping Status", "Suggested — analyst validation required")
    details = [
        f"Source: {source_label}",
        f"Report ID: {finding.get('Report ID', 'Unknown')}",
        f"Host: {finding.get('Host', 'Unknown')}",
        f"Port: {finding.get('Port', 'Unknown')}",
        f"CVSS: {finding.get('CVSS', 0)}",
        f"CVE: {finding.get('CVE', 'N/A')}",
        f"NVT OID: {finding.get('NVT OID', 'Unknown')}",
        f"Quality of detection: {finding.get('QOD', 'Unknown')}",
        f"Suggested ISO/IEC 27001:2022 controls: {finding.get('ISO Controls', 'Not mapped')}",
        f"Related ISMS clauses: {finding.get('ISMS Clauses', 'Not mapped')}",
        f"Mapping status: {mapping_status}",
        "",
        "Description:",
        str(finding.get("Description", "No description provided by the scanner.")),
        "",
        "Recommended remediation:",
        str(finding.get("Solution", "No remediation provided by the scanner.")),
    ]
    return "\n".join(details)


def build_openvas_risk_description(finding: dict[str, Any]) -> str:
    """Build the risk statement stored in CISO Assistant."""
    return (
        f"A vulnerability detected by a SecureScope scanner may affect host "
        f"{finding.get('Host', 'Unknown')} on {finding.get('Port', 'Unknown')}. "
        f"The reported CVSS score is {finding.get('CVSS', 0)}. "
        f"CVE references: {finding.get('CVE', 'N/A')}.\n\n"
        f"Recommended remediation: {finding.get('Solution', 'No remediation provided.')}\n\n"
        f"Suggested ISO/IEC 27001:2022 controls: {finding.get('ISO Controls', 'Not mapped')}\n"
        f"Related ISMS clauses: {finding.get('ISMS Clauses', 'Not mapped')}\n"
        "This is an automated technical input. Validate exploitability, "
        "business impact and treatment before approving the risk."
    )


def format_nmap_asset_description(asset: dict[str, Any]) -> str:
    """Create a readable CISO asset description from Nmap discovery data."""
    fields = [
        ("Asset tag", asset.get("asset_tag")),
        ("IP address", asset.get("ip")),
        ("Hostname", asset.get("hostname")),
        ("MAC address", asset.get("mac_address")),
        ("Manufacturer", asset.get("manufacturer")),
        ("Lifecycle", asset.get("status")),
        ("Criticality", asset.get("criticality")),
        ("Owner", asset.get("owner")),
        ("Location", asset.get("location")),
        ("VLAN ID", asset.get("vlan_id")),
        ("VLAN name", asset.get("vlan_name")),
        ("Device type", asset.get("device_type")),
        ("Operating system", asset.get("operating_system")),
        ("Detected products", asset.get("products")),
        ("Open ports", asset.get("open_ports")),
        ("Discovery source", asset.get("source") or "Nmap"),
        ("Discovery confirmation", asset.get("confirmation")),
        ("Last seen", asset.get("last_seen")),
        ("Last inspection", asset.get("last_inspected")),
    ]
    return "\n".join(
        f"{label}: {value}"
        for label, value in fields
        if value and value not in {"Unknown", "Not inspected"}
    )
