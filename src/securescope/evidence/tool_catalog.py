"""Approved SecureScope open-source evidence-source catalog.

The catalog is deliberately declarative. It prevents a presentation layer from
constructing arbitrary commands and makes the import-only boundary for
offensive and credential-testing tools enforceable in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from securescope.grc.control_catalog import TECHNICAL_SOURCES

EXPECTED_TOOL_COUNT = 31


class IntegrationMode(str, Enum):
    """Supported connector implementation modes."""

    EXISTING = "Existing SecureScope integration"
    LOCAL_CLI = "Defensive local CLI"
    API_OR_IMPORT = "Authenticated API or report import"
    IMPORT_ONLY = "Report import only"


class ExecutionPolicy(str, Enum):
    """Execution permissions enforced independently of UI labels."""

    EXISTING_WORKER = "existing_worker"
    DEFENSIVE_ONLY = "defensive_only"
    API_COLLECTION = "api_collection"
    DISABLED = "disabled"


@dataclass(frozen=True)
class ToolDefinition:
    """Describe one approved evidence source.

    Args:
        tool_id: Stable lowercase source identifier.
        name: Product name displayed in the Evidence Hub.
        category: Functional catalog group.
        purpose: Concise evidence purpose.
        integration_mode: Supported integration route.
        execution_policy: Enforced execution boundary.
        executable_names: Candidate local executable names.
        report_formats: Accepted machine-readable formats.
        license_name: Community/source license label.
        homepage: Authoritative project or documentation URL.
        platform_note: Optional installation/platform limitation.

    Returns:
        Immutable connector metadata.

    Raises:
        ValueError: If mandatory metadata is missing or execution policy is unsafe.
    """

    tool_id: str
    name: str
    category: str
    purpose: str
    integration_mode: IntegrationMode
    execution_policy: ExecutionPolicy
    executable_names: tuple[str, ...]
    report_formats: tuple[str, ...]
    license_name: str
    homepage: str
    platform_note: str = ""

    def __post_init__(self) -> None:
        """Validate source metadata and the import-only safety boundary.

        Returns:
            None.

        Raises:
            ValueError: If the metadata or execution policy is invalid.
        """

        if not all((self.tool_id, self.name, self.category, self.purpose)):
            raise ValueError("Tool definitions require identity and purpose metadata.")
        if (
            self.integration_mode is IntegrationMode.IMPORT_ONLY
            and self.execution_policy is not ExecutionPolicy.DISABLED
        ):
            raise ValueError(f"Import-only source cannot be executable: {self.tool_id}")

    @property
    def iso_control_ids(self) -> tuple[str, ...]:
        """Return ISO controls for which this source can provide support.

        Returns:
            Sorted control identifiers from the conservative mapping catalog.

        Raises:
            ValueError: Never raised.
        """

        return tuple(
            sorted(
                control_id
                for control_id, sources in TECHNICAL_SOURCES.items()
                if self.tool_id in sources
            )
        )

    @property
    def can_execute(self) -> bool:
        """Return whether SecureScope may invoke this connector.

        Returns:
            ``True`` only for existing workers and defensive collectors.

        Raises:
            ValueError: Never raised.
        """

        return self.execution_policy in {
            ExecutionPolicy.EXISTING_WORKER,
            ExecutionPolicy.DEFENSIVE_ONLY,
            ExecutionPolicy.API_COLLECTION,
        }


def _tool(
    tool_id: str,
    name: str,
    category: str,
    purpose: str,
    integration_mode: IntegrationMode,
    execution_policy: ExecutionPolicy,
    executable_names: tuple[str, ...],
    report_formats: tuple[str, ...],
    license_name: str,
    homepage: str,
    platform_note: str = "",
) -> ToolDefinition:
    """Build one tool definition without exposing positional construction to UI code.

    Args:
        tool_id: Stable source identifier.
        name: Display name.
        category: Functional group.
        purpose: Evidence purpose.
        integration_mode: Connector route.
        execution_policy: Execution boundary.
        executable_names: Candidate local commands.
        report_formats: Import formats.
        license_name: License label.
        homepage: Authoritative URL.
        platform_note: Optional platform limitation.

    Returns:
        Validated tool definition.

    Raises:
        ValueError: Propagated when metadata violates safety invariants.
    """

    return ToolDefinition(
        tool_id=tool_id,
        name=name,
        category=category,
        purpose=purpose,
        integration_mode=integration_mode,
        execution_policy=execution_policy,
        executable_names=executable_names,
        report_formats=report_formats,
        license_name=license_name,
        homepage=homepage,
        platform_note=platform_note,
    )


TOOLS: tuple[ToolDefinition, ...] = (
    _tool(
        "nmap",
        "Nmap",
        "Network and discovery",
        "Asset discovery, service inventory and exposure evidence.",
        IntegrationMode.EXISTING,
        ExecutionPolicy.EXISTING_WORKER,
        ("nmap", "nmap.exe"),
        ("xml",),
        "Nmap Public Source License",
        "https://nmap.org/",
    ),
    _tool(
        "openvas",
        "OpenVAS / Greenbone",
        "Vulnerability management",
        "Infrastructure vulnerability observations and remediation evidence.",
        IntegrationMode.EXISTING,
        ExecutionPolicy.EXISTING_WORKER,
        (),
        ("xml", "json", "csv"),
        "AGPL-3.0",
        "https://greenbone.github.io/docs/",
    ),
    _tool(
        "nuclei",
        "Nuclei",
        "Vulnerability management",
        "Template-based vulnerability and configuration evidence.",
        IntegrationMode.EXISTING,
        ExecutionPolicy.EXISTING_WORKER,
        ("nuclei", "nuclei.exe"),
        ("jsonl", "json", "sarif"),
        "MIT",
        "https://docs.projectdiscovery.io/tools/nuclei/overview",
    ),
    _tool(
        "zap",
        "OWASP ZAP",
        "Web application security",
        "Authorized passive and active web-application testing evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("zap.sh", "zap.bat", "zap.exe"),
        ("json", "xml", "sarif"),
        "Apache-2.0",
        "https://www.zaproxy.org/docs/automate/automation-framework/",
    ),
    _tool(
        "wazuh",
        "Wazuh",
        "Endpoint, SIEM and response",
        "Endpoint coverage, alerts, monitoring and incident records.",
        IntegrationMode.EXISTING,
        ExecutionPolicy.API_COLLECTION,
        (),
        ("json", "jsonl", "csv"),
        "GPL-2.0",
        "https://documentation.wazuh.com/",
    ),
    _tool(
        "ciso-assistant",
        "CISO Assistant Community",
        "GRC integration",
        "Governance, risk, assessment and control synchronization.",
        IntegrationMode.EXISTING,
        ExecutionPolicy.API_COLLECTION,
        (),
        ("json", "csv"),
        "AGPL-3.0 Community Edition",
        "https://github.com/intuitem/ciso-assistant-community",
    ),
    _tool(
        "amass",
        "OWASP Amass",
        "Network and discovery",
        "Authorized external asset and domain discovery.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("amass", "amass.exe"),
        ("json", "jsonl", "text"),
        "Apache-2.0",
        "https://owasp.org/www-project-amass/",
    ),
    _tool(
        "theharvester",
        "theHarvester",
        "Network and discovery",
        "OSINT-derived domains, hosts, email addresses and exposure context.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("theHarvester", "theHarvester.exe"),
        ("json", "xml"),
        "GPL-2.0",
        "https://github.com/laramies/theHarvester",
    ),
    _tool(
        "dnsrecon",
        "DNSRecon",
        "Network and discovery",
        "DNS enumeration and external attack-surface evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("dnsrecon", "dnsrecon.exe"),
        ("json", "csv", "xml"),
        "GPL-2.0",
        "https://github.com/darkoperator/dnsrecon",
    ),
    _tool(
        "nikto",
        "Nikto",
        "Web application security",
        "Web-server configuration and known-risk evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("nikto", "nikto.pl"),
        ("json", "xml", "csv", "text"),
        "GPL-2.0",
        "https://github.com/sullo/nikto",
    ),
    _tool(
        "wapiti",
        "Wapiti",
        "Web application security",
        "Authorized black-box web vulnerability evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("wapiti", "wapiti.exe"),
        ("json", "xml", "csv", "text"),
        "GPL-2.0",
        "https://wapiti-scanner.github.io/",
    ),
    _tool(
        "droopescan",
        "Droopescan",
        "Web application security",
        "Open-source CMS and WordPress exposure evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("droopescan", "droopescan.exe"),
        ("json", "text"),
        "GPL",
        "https://github.com/SamJoan/droopescan",
        "Replaces WPScan, whose commercial integration requires a paid license.",
    ),
    _tool(
        "lynis",
        "Lynis",
        "System compliance",
        "Host hardening and system-audit evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("lynis",),
        ("dat", "text"),
        "GPL-3.0",
        "https://cisofy.com/documentation/lynis/",
        "Automatic execution is Linux-only; Windows accepts imported reports.",
    ),
    _tool(
        "openscap",
        "OpenSCAP",
        "System compliance",
        "XCCDF/OVAL configuration and benchmark evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("oscap",),
        ("xccdf", "arf", "xml"),
        "LGPL-2.1",
        "https://www.open-scap.org/",
        "Automatic execution normally runs on Linux; Windows accepts imported ARF/XCCDF.",
    ),
    _tool(
        "trivy",
        "Trivy",
        "Container and cloud",
        "Container, filesystem, dependency and misconfiguration evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("trivy", "trivy.exe"),
        ("json", "sarif", "cyclonedx", "spdx"),
        "Apache-2.0",
        "https://trivy.dev/",
    ),
    _tool(
        "grype",
        "Grype",
        "Container and cloud",
        "Container image, filesystem and SBOM vulnerability evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("grype", "grype.exe"),
        ("json", "sarif", "cyclonedx"),
        "Apache-2.0",
        "https://oss.anchore.com/docs/",
    ),
    _tool(
        "prowler",
        "Prowler",
        "Container and cloud",
        "Cloud posture and benchmark evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("prowler", "prowler.exe"),
        ("csv", "json-ocsf", "json-asff", "sarif"),
        "Apache-2.0",
        "https://docs.prowler.com/",
    ),
    _tool(
        "scoutsuite",
        "ScoutSuite",
        "Container and cloud",
        "Multi-cloud configuration and exposure evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("scout", "scout.exe"),
        ("json", "html"),
        "GPL-2.0",
        "https://github.com/nccgroup/ScoutSuite",
    ),
    _tool(
        "osv-scanner",
        "OSV-Scanner",
        "Source-code security",
        "Open-source dependency vulnerability evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("osv-scanner", "osv-scanner.exe"),
        ("json", "sarif"),
        "Apache-2.0",
        "https://google.github.io/osv-scanner/",
    ),
    _tool(
        "semgrep-ce",
        "Semgrep Community Edition",
        "Source-code security",
        "Static application security findings and secure-coding evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("semgrep", "semgrep.exe"),
        ("json", "sarif"),
        "LGPL-2.1 Community engine",
        "https://semgrep.dev/docs/",
    ),
    _tool(
        "bandit",
        "Bandit",
        "Source-code security",
        "Python security issue and secure-coding evidence.",
        IntegrationMode.LOCAL_CLI,
        ExecutionPolicy.DEFENSIVE_ONLY,
        ("bandit", "bandit.exe"),
        ("json", "sarif", "csv", "xml"),
        "Apache-2.0",
        "https://bandit.readthedocs.io/",
    ),
    _tool(
        "sonarqube-community",
        "SonarQube Community Build",
        "Source-code security",
        "Code quality and security issue evidence collected through its Web API.",
        IntegrationMode.API_OR_IMPORT,
        ExecutionPolicy.API_COLLECTION,
        (),
        ("json", "sarif", "csv"),
        "LGPL-3.0 Community Build",
        "https://docs.sonarsource.com/sonarqube-community-build/",
    ),
    _tool(
        "metasploit",
        "Metasploit Framework",
        "Controlled security-test imports",
        "Authorized exploitation-test results imported as validation evidence.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("xml", "json", "text"),
        "BSD-3-Clause",
        "https://github.com/rapid7/metasploit-framework",
    ),
    _tool(
        "hydra",
        "THC Hydra",
        "Controlled security-test imports",
        "Authorized credential-audit results imported without execution.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("json", "text"),
        "AGPL-3.0",
        "https://github.com/vanhauser-thc/thc-hydra",
    ),
    _tool(
        "medusa",
        "Medusa",
        "Controlled security-test imports",
        "Authorized credential-audit results imported without execution.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("text", "csv"),
        "GPL-2.0",
        "https://github.com/jmk-foofus/medusa",
    ),
    _tool(
        "ncrack",
        "Ncrack",
        "Controlled security-test imports",
        "Authorized authentication-audit results imported without execution.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("xml", "text"),
        "Nmap Public Source License",
        "https://nmap.org/ncrack/",
    ),
    _tool(
        "beef",
        "BeEF",
        "Controlled security-test imports",
        "Authorized browser-security test results imported without execution.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("json", "text"),
        "GPL-2.0",
        "https://github.com/beefproject/beef",
    ),
    _tool(
        "atomic-red-team",
        "Atomic Red Team",
        "Controlled security-test imports",
        "Approved adversary-simulation results imported without execution.",
        IntegrationMode.IMPORT_ONLY,
        ExecutionPolicy.DISABLED,
        (),
        ("json", "csv", "text"),
        "MIT",
        "https://github.com/redcanaryco/atomic-red-team",
    ),
    _tool(
        "redmine",
        "Redmine",
        "Ticketing and remediation",
        "Open-source remediation ticket and closure evidence.",
        IntegrationMode.API_OR_IMPORT,
        ExecutionPolicy.API_COLLECTION,
        (),
        ("json", "csv"),
        "GPL-2.0",
        "https://www.redmine.org/projects/redmine/wiki/Rest_api",
    ),
    _tool(
        "glpi",
        "GLPI",
        "Ticketing and remediation",
        "Open-source ITSM ticket, asset and remediation evidence.",
        IntegrationMode.API_OR_IMPORT,
        ExecutionPolicy.API_COLLECTION,
        (),
        ("json", "csv"),
        "GPL-3.0",
        "https://github.com/glpi-project/glpi",
    ),
    _tool(
        "gitlab-ce",
        "GitLab Community Edition",
        "Ticketing and remediation",
        "Issue, merge-request and change-control evidence.",
        IntegrationMode.API_OR_IMPORT,
        ExecutionPolicy.API_COLLECTION,
        ("glab", "glab.exe"),
        ("json", "sarif", "csv"),
        "MIT Community Edition",
        "https://docs.gitlab.com/api/",
    ),
)


TOOL_CATALOG: dict[str, ToolDefinition] = {item.tool_id: item for item in TOOLS}
IMPORT_ONLY_TOOL_IDS = frozenset(
    item.tool_id for item in TOOLS if item.integration_mode is IntegrationMode.IMPORT_ONLY
)


def get_tool(tool_id: str) -> ToolDefinition:
    """Return a catalog source by stable identifier.

    Args:
        tool_id: Stable source identifier.

    Returns:
        Matching tool definition.

    Raises:
        KeyError: If the source is not approved.
    """

    normalized = str(tool_id or "").strip().lower()
    if normalized not in TOOL_CATALOG:
        raise KeyError(f"Unsupported evidence source: {tool_id}")
    return TOOL_CATALOG[normalized]


def tools_by_category() -> dict[str, list[ToolDefinition]]:
    """Group catalog entries for Evidence Hub presentation.

    Returns:
        Category names mapped to sorted tool definitions.

    Raises:
        ValueError: Never raised.
    """

    result: dict[str, list[ToolDefinition]] = {}
    for item in TOOLS:
        result.setdefault(item.category, []).append(item)
    for items in result.values():
        items.sort(key=lambda value: value.name.casefold())
    return result


def validate_tool_catalog() -> None:
    """Validate source count, identities and execution restrictions.

    Returns:
        None.

    Raises:
        ValueError: If catalog invariants are broken.
    """

    if len(TOOLS) != EXPECTED_TOOL_COUNT:
        raise ValueError(f"Expected {EXPECTED_TOOL_COUNT} sources, found {len(TOOLS)}.")
    if len(TOOL_CATALOG) != len(TOOLS):
        raise ValueError("Evidence source identifiers must be unique.")
    expected_import_only = {
        "metasploit",
        "hydra",
        "medusa",
        "ncrack",
        "beef",
        "atomic-red-team",
    }
    if IMPORT_ONLY_TOOL_IDS != expected_import_only:
        raise ValueError("Import-only execution boundary changed unexpectedly.")
    for item in TOOLS:
        if item.tool_id in expected_import_only and item.can_execute:
            raise ValueError(f"Offensive source must never execute: {item.tool_id}")


validate_tool_catalog()
