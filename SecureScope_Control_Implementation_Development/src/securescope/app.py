"""SecureScope: asset discovery, vulnerability management and ISO assurance.

Architecture:
- Windows runs this Streamlit application.
- Nmap discovers and classifies client-isolated assets.
- OpenVAS/GVM remains the preserved vulnerability-scanning provider.
- Wazuh supplies endpoint monitoring and clock-synchronization evidence.
- PostgreSQL stores workspaces, scan identity, evidence and analyst decisions.
- CISO Assistant receives assets, findings, vulnerabilities and technical risks.

SecureScope v5.4.3 keeps the evidence-driven ISO/IEC 27001:2022 workflows and
scanner workers intact while moving top-level presentation to modern Streamlit
page routing, fragment-scoped reruns, Stitch-aligned components, and pooled
PostgreSQL repository access.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Optional

import nmap
import pandas as pd
import streamlit as st

from securescope.core.output_sanitizer import display_tool_output
from securescope.core.presentation import safe_text
from securescope.core.runtime_noise_filter import install_windows_asyncio_cleanup_filter
from securescope.paths import ENV_FILE, PROJECT_ROOT, WAZUH_ROOT
from securescope.reporting.openvas_pdf_report import (
    build_reports_zip,
    save_asset_report_pdf,
)
from securescope.ui.calendar_workspace import render_calendar_page
from securescope.ui.components import (
    StitchMetric,
    render_attention_panel,
    render_coverage_gaps,
    render_severity_bars,
    render_stitch_metrics,
)
from securescope.ui.components.navigation import module_tabs
from securescope.ui.components.primitives import (
    metric_card,
    panel_heading,
    readable_table,
)
from securescope.ui.evidence_hub_ui import render_iso_evidence_hub
from securescope.ui.grc_workspace_ui import render_grc_workspace
from securescope.ui.navigation import (
    active_navigation_key,
    build_page_registry,
    run_hidden_navigation,
)
from securescope.ui.navigation_runtime import (
    configure_page_registry,
    navigate_to,
)
from securescope.ui.pages.command_center import render_iso_command_center
from securescope.ui.risk_workspace import render_risk_page
from securescope.ui.securescope_sidebar import render_sidebar_menu
from securescope.ui.securescope_ui_theme import (
    apply_securescope_ui_theme,
    criticality_display,
    lifecycle_display,
    render_asset_legends,
    severity_display,
)

install_windows_asyncio_cleanup_filter()
from dotenv import load_dotenv
from gvm import connections as gvm_connections
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from securescope.compliance.iso_control_assessment_service import (
    APPLICABILITY_OPTIONS,
    ISO_A8_CONTROLS,
    VALIDATED_STATUSES,
    IsoAssessmentDatabaseError,
    add_maturity,
    assessment_summary,
    evaluate_a8_controls,
    latest_iso_assessment_snapshot,
    list_corrective_actions,
    load_iso_control_reviews,
    merge_reviews,
    save_iso_assessment_snapshot,
    save_iso_control_review,
    synchronize_corrective_actions,
)
from securescope.core.finding_domain import ACTIVE_FINDING_STATUSES
from securescope.core.scanner_engine_service import (
    ENGINE_NUCLEI,
    ENGINE_OPENVAS,
    default_engine,
    enabled_engines,
    persist_engine_selection,
)
from securescope.integrations.ciso_assistant_service import (
    CisoApiError,
    CisoAssistantClient,
    format_nmap_asset_description,
    load_ciso_config,
)
from securescope.integrations.ntp_audit_service import (
    DEFAULT_EVIDENCE_MAX_AGE_MINUTES,
    DEFAULT_MANAGER_DELTA_TOLERANCE_MS,
    DEFAULT_TOLERANCE_MS,
    NtpAuditError,
    apply_clock_status,
    audit_ntp_servers,
    clock_evidence_table,
    collect_wazuh_ntp_evidence,
    fleet_clock_summary,
    match_clock_evidence_to_assets,
)
from securescope.persistence.clock_evidence_persistence import (
    ClockEvidenceDatabaseError,
    load_latest_clock_evidence,
    save_clock_evidence,
)
from securescope.persistence.db_service import (
    DatabaseConfigurationError,
    DatabaseError,
)
from securescope.persistence.db_service import ensure_client as db_ensure_client
from securescope.persistence.db_service import (
    init_database,
    list_client_names,
    load_all_assets,
    load_all_scan_history,
    load_assets_for_client,
    load_scan_history_for_client,
    save_assets_for_client,
    save_scan_history_for_client,
)
from securescope.persistence.exposure_repository import (
    ExposureRepositoryError,
    list_audit_events,
    list_findings,
    synchronize_findings_from_history,
    workspace_dashboard_metrics,
    workspace_finding_analysis,
)
from securescope.persistence.nuclei_persistence import NucleiDatabaseError, init_nuclei_tables
from securescope.persistence.openvas_persistence import (
    abandon_openvas_job,
    activate_openvas_batch_dispatch,
    cancel_queued_openvas_job,
    create_openvas_batch,
    create_or_update_openvas_job,
    get_active_openvas_batch,
    get_openvas_batch,
    get_openvas_queue_snapshot,
    get_worker_state,
    init_openvas_tables,
    list_openvas_attempts,
    list_openvas_batches,
    list_openvas_job_events,
    load_openvas_batch_jobs,
    request_openvas_job_action,
    requeue_ambiguous_openvas_start_failures,
    update_batch_counters,
)
from securescope.reporting.iso_report_service import build_iso_assurance_pdf
from securescope.scanners.openvas.openvas_embedded_worker import start_embedded_openvas_worker
from securescope.scanners.openvas.openvas_worker_service import (
    diagnose_openvas_submission_path,
    prepare_and_start_openvas_batch_parallel,
    prepare_openvas_tasks_for_batch,
    probe_gmp_tunnel,
    recover_recent_securescope_tasks,
    retry_openvas_jobs,
    start_openvas_batch_parallel,
    stop_other_securescope_tasks,
    trigger_openvas_fast_status_cycle,
    trigger_openvas_queue_start_cycle,
)
from securescope.ui.dual_engine_ui import (
    render_button_choice,
    render_nuclei_connection_panel,
    render_nuclei_scan_center,
    render_report_downloads,
    report_action_value,
    scanner_fabric_metrics,
)
from securescope.ui.exposure_management_ui import (
    render_gap_assessment_page,
    render_remediation_page,
    render_vulnerabilities_page,
)

try:
    from securescope.integrations.wazuh_service import (
        WazuhClient,
        build_iso_evidence_from_wazuh,
    )
    from securescope.persistence.db_wazuh_service import (
        WazuhDatabaseError,
        load_latest_wazuh_status,
    )

    WAZUH_INTEGRATION_AVAILABLE = True
    WAZUH_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # Wazuh remains optional until configured.
    WAZUH_INTEGRATION_AVAILABLE = False
    WAZUH_IMPORT_ERROR = exc


try:
    from securescope.ui.nmap_custom_ui import (
        render_nmap_custom_scan_page as render_nmap_custom_scan_page,
    )

    NMAP_CUSTOM_BUILDER_AVAILABLE = callable(render_nmap_custom_scan_page)
    NMAP_CUSTOM_IMPORT_ERROR: Exception | None = None
except Exception as exc:
    NMAP_CUSTOM_BUILDER_AVAILABLE = False
    NMAP_CUSTOM_IMPORT_ERROR = exc


load_dotenv(dotenv_path=ENV_FILE, override=False)

st.set_page_config(
    page_title="SecureScope — ISO 27001 Assurance",
    page_icon="🛡️",
    layout="wide",
)


ENABLED_SCAN_ENGINES = enabled_engines()
OPENVAS_ENGINE_ENABLED = ENGINE_OPENVAS in ENABLED_SCAN_ENGINES
NUCLEI_ENGINE_ENABLED = ENGINE_NUCLEI in ENABLED_SCAN_ENGINES


class _DisabledOpenVASRuntime:
    """No-op runtime used when OpenVAS is disabled or not configured."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def start(self) -> "_DisabledOpenVASRuntime":
        return self

    def wake(self, batch_id: int | None = None) -> None:
        del batch_id

    def watch_batch(self, batch_id: int) -> None:
        del batch_id

    def snapshot(self) -> dict[str, Any]:
        return {
            "started": False,
            "alive": False,
            "starter_alive": False,
            "deep_alive": False,
            "priority_alive": False,
            "owns_lock": False,
            "message": self.reason,
            "error": self.reason,
            "starter_error": "",
            "deep_error": "",
            "priority_error": "",
            "priority_inflight": [],
        }


@st.cache_resource(show_spinner=False)
def _bootstrap_persistent_openvas_worker() -> Any:
    """Return the process-wide OpenVAS worker runtime when configured."""
    if not OPENVAS_ENGINE_ENABLED:
        return _DisabledOpenVASRuntime("OpenVAS is disabled in .env.")
    if not os.getenv("GVM_PASSWORD", "").strip():
        return _DisabledOpenVASRuntime("GVM_PASSWORD is missing; OpenVAS is unavailable.")
    runtime_ready = (
        os.getenv(
            "SECURESCOPE_OPENVAS_RUNTIME_READY",
            "true",
        )
        .strip()
        .lower()
    )
    if runtime_ready in {"0", "false", "no", "off"}:
        return _DisabledOpenVASRuntime("OpenVAS tunnel diagnostics did not pass during startup.")
    return start_embedded_openvas_worker()


OPENVAS_WORKER_BOOTSTRAP = _bootstrap_persistent_openvas_worker()
# Calling start on every rerun is harmless while the cached runtime is healthy.
OPENVAS_WORKER_BOOTSTRAP.start()


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# OpenVAS/GVM configuration.
GVM_USERNAME = os.getenv("GVM_USERNAME", "admin")
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "")
LOCAL_TUNNEL_HOST = os.getenv("LOCAL_TUNNEL_HOST", "127.0.0.1")
LOCAL_TUNNEL_PORT = int(os.getenv("LOCAL_TUNNEL_PORT", "19390"))

# Nmap and local asset inventory configuration.
DEFAULT_NETWORK = os.getenv("DEFAULT_NETWORK", "192.168.100.0/24")
NMAP_SECOND_PASS_DEFAULT_BATCH = max(
    1,
    int(os.getenv("NMAP_SECOND_PASS_DEFAULT_BATCH", "5")),
)
NMAP_CONFIRM_HOST_TIMEOUT = os.getenv("NMAP_CONFIRM_HOST_TIMEOUT", "300s")
NMAP_CONFIRM_MAX_RETRIES = max(
    0,
    int(os.getenv("NMAP_CONFIRM_MAX_RETRIES", "1")),
)
NMAP_DETAIL_HOST_TIMEOUT = os.getenv("NMAP_DETAIL_HOST_TIMEOUT", "900s")
NMAP_DETAIL_PORTS = os.getenv("NMAP_DETAIL_PORTS", "-p-").strip() or "-p-"

# CISO Assistant configuration.
CISO_FOLDER_ID = os.getenv("CISO_FOLDER_ID", "").strip()
CISO_PERIMETER_ID = os.getenv("CISO_PERIMETER_ID", "").strip()
CISO_MIN_CVSS_FOR_RISK = float(os.getenv("CISO_MIN_CVSS_FOR_RISK", "4.0"))

APP_DIR = PROJECT_ROOT
DATA_DIR = APP_DIR / "data"  # Used only by the optional JSON migration script.
MAX_SCAN_HISTORY = int(os.getenv("MAX_SCAN_HISTORY", "30"))
DEFAULT_CLIENT_NAME = (
    os.getenv("SECURESCOPE_DEFAULT_CLIENT", "Default Client").strip() or "Default Client"
)
CLASSIFICATION_LABELS = {
    0: "Public",
    1: "Internal Use",
    2: "Confidential",
    3: "Restricted",
}
INFORMATION_CLASSIFICATION_OPTIONS = [
    "Public",
    "Internal Use",
    "Confidential",
    "Restricted",
]
CIA_SCORE_LABELS = {
    0: "None / negligible",
    1: "Low",
    2: "Medium",
    3: "High",
}
CLASSIFICATION_OPTIONS = [0, 1, 2, 3]
CIA_GUIDANCE = {
    "confidentiality": {
        0: "Public information; unauthorized disclosure has no meaningful impact.",
        1: "Low: disclosure has negligible impact and can be shared internally.",
        2: "Medium: disclosure can affect operations, customers or obligations.",
        3: "High: disclosure can cause financial, legal, contractual or reputational damage.",
    },
    "integrity": {
        0: "Public/reference data; unauthorized modification has no meaningful impact.",
        1: "Low: unauthorized modification has little or no operational impact.",
        2: (
            "Medium: modification can affect processes, reporting or decisions"
            " and needs correction."
        ),
        3: (
            "High: modification can seriously compromise operations, "
            "compliance, safety or decisions."
        ),
    },
    "availability": {
        0: "No protection requirement for availability.",
        1: "Low: temporary unavailability has little or no operational impact.",
        2: (
            "Medium: unavailability disrupts operations for a limited period "
            "and needs timely restoration."
        ),
        3: "High: unavailability critically affects continuity, customer services or obligations.",
    },
}

# GVM scanner configuration.
SCAN_CONFIG_NAME = os.getenv("SCAN_CONFIG_NAME", "Full and fast")
PORT_LIST_NAME = os.getenv(
    "PORT_LIST_NAME",
    "All IANA assigned TCP",
)
SCANNER_NAME = os.getenv("SCANNER_NAME", "OpenVAS Default")

# Timeouts and polling.
GMP_TIMEOUT_SECONDS = int(os.getenv("GMP_TIMEOUT_SECONDS", "600"))
TASK_POLL_SECONDS = int(os.getenv("TASK_POLL_SECONDS", "10"))
REPORT_MAX_ROWS = int(os.getenv("REPORT_MAX_ROWS", "200"))
OPENVAS_CONNECTION_RETRIES = max(
    0,
    int(os.getenv("OPENVAS_CONNECTION_RETRIES", "2")),
)
OPENVAS_RECONNECT_DELAY_SECONDS = max(
    1,
    int(os.getenv("OPENVAS_RECONNECT_DELAY_SECONDS", "5")),
)
OPENVAS_BETWEEN_ASSET_DELAY_SECONDS = max(
    0,
    int(os.getenv("OPENVAS_BETWEEN_ASSET_DELAY_SECONDS", "2")),
)
OPENVAS_BATCH_SUBMIT_RETRIES = max(
    0,
    int(os.getenv("OPENVAS_BATCH_SUBMIT_RETRIES", "2")),
)
OPENVAS_BATCH_POLL_SECONDS = max(
    2,
    int(os.getenv("OPENVAS_BATCH_POLL_SECONDS", str(TASK_POLL_SECONDS))),
)
OPENVAS_REQUESTED_WARNING_SECONDS = max(
    10,
    int(os.getenv("OPENVAS_REQUESTED_WARNING_SECONDS", "60")),
)
OPENVAS_SCANNER_DIAGNOSTIC_INTERVAL_SECONDS = max(
    30,
    int(os.getenv("OPENVAS_SCANNER_DIAGNOSTIC_INTERVAL_SECONDS", "90")),
)
OPENVAS_MAX_CONCURRENT_SCANS = max(
    1,
    int(os.getenv("OPENVAS_MAX_CONCURRENT_SCANS", "8")),
)
OPENVAS_LIVE_STALE_SECONDS = max(
    20,
    int(os.getenv("OPENVAS_LIVE_STALE_SECONDS", "45")),
)
OPENVAS_ACTIVE_SLOT_FRESH_SECONDS = max(
    60,
    int(os.getenv("OPENVAS_ACTIVE_SLOT_FRESH_SECONDS", "180")),
)

try:
    init_database(DEFAULT_CLIENT_NAME)
    init_openvas_tables()
    init_nuclei_tables()
except (DatabaseConfigurationError, DatabaseError, NucleiDatabaseError) as exc:
    st.error(f"PostgreSQL is not ready: {exc}")
    st.stop()


class PlainSocketConnection:
    """Plain TCP connection used through the local Windows SSH tunnel."""

    def __init__(
        self,
        hostname: str = "127.0.0.1",
        port: int = 19390,
        timeout: int = GMP_TIMEOUT_SECONDS,
    ) -> None:
        self.hostname = hostname
        self.port = int(port)
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._file: Optional[BinaryIO] = None

    def connect(self) -> None:
        """Connect to the local SSH tunnel."""
        if self.sock is not None:
            return

        self.sock = socket.create_connection(
            (self.hostname, self.port),
            timeout=self.timeout,
        )
        self.sock.settimeout(self.timeout)

    def disconnect(self) -> None:
        """Disconnect from the local SSH tunnel."""
        self.close()

    def close(self) -> None:
        """Close socket and file resources."""
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                logger.debug("Could not close tunnel file object.", exc_info=True)
            self._file = None

        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            try:
                self.sock.close()
            except OSError:
                logger.debug("Could not close tunnel socket.", exc_info=True)

        self.sock = None

    def send(self, data: bytes) -> None:
        """Send GMP XML bytes through the tunnel."""
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        self.sock.sendall(data)

    def write(self, data: bytes) -> None:
        """Write bytes to the tunnel."""
        self.send(data)

    def recv(self, size: int = 4096) -> bytes:
        """Receive bytes from gvmd."""
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")
        return self.sock.recv(size)

    def receive(self, size: int = 4096) -> bytes:
        """Receive bytes from gvmd."""
        return self.recv(size)

    def read(self, size: int = -1) -> bytes:
        """Read bytes from gvmd."""
        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")

        if size is None or size < 0:
            return self.sock.recv(4096)

        chunks: list[bytes] = []
        remaining = size

        while remaining > 0:
            chunk = self.sock.recv(min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def makefile(
        self,
        mode: str = "rwb",
        buffering: int = 0,
    ) -> BinaryIO:
        """Return a file-like wrapper for the tunnel socket."""
        if self._file is not None:
            return self._file

        if self.sock is None:
            self.connect()

        if self.sock is None:
            raise ConnectionError("GVM connection is not open.")

        self._file = self.sock.makefile(mode, buffering=buffering)
        return self._file

    def fileno(self) -> int:
        """Return the socket file descriptor."""
        return self.sock.fileno() if self.sock is not None else -1

    def settimeout(self, timeout: float) -> None:
        """Set the socket timeout."""
        self.timeout = timeout
        if self.sock is not None:
            self.sock.settimeout(timeout)

    def flush(self) -> None:
        """Flush the file object when it exists."""
        if self._file is not None:
            self._file.flush()

    def __enter__(self) -> "PlainSocketConnection":
        """Open the connection for context-manager usage."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[BaseException],
        traceback: Optional[Any],
    ) -> None:
        """Close the connection after context-manager usage."""
        self.disconnect()


SocketConnection = getattr(gvm_connections, "SocketConnection", None)
DebugConnection = getattr(gvm_connections, "DebugConnection", None)

if SocketConnection is None:
    SocketConnection = PlainSocketConnection


def make_gmp_connection() -> Any:
    """Create a GMP connection through the Windows SSH tunnel."""
    connection = SocketConnection(
        hostname=LOCAL_TUNNEL_HOST,
        port=LOCAL_TUNNEL_PORT,
        timeout=GMP_TIMEOUT_SECONDS,
    )

    if DebugConnection is not None and os.getenv("DEBUG_GVM") == "1":
        connection = DebugConnection(connection)

    return connection


def find_first_id(resource_ids: list[str], resource_name: str) -> str:
    """Return the first GVM resource ID or raise a meaningful error."""
    if not resource_ids:
        raise GvmError(f"{resource_name} was not found on the GVM server.")
    return resource_ids[0]


def test_gvm_tunnel() -> str:
    """Request GVM version information through the local tunnel."""
    transform = EtreeCheckCommandTransform()

    with GMP(
        connection=make_gmp_connection(),
        transform=transform,
    ) as gmp:
        response = gmp.get_version()

    version_nodes = response.xpath("version/text()")
    return version_nodes[0] if version_nodes else "Unknown"


def test_ciso_connection() -> str:
    """Authenticate with CISO Assistant and return the current user identity."""
    client = CisoAssistantClient(load_ciso_config())
    user = client.current_user()

    return user.get("email") or user.get("username") or user.get("id") or "Authenticated user"


def get_first_text(nodes: list[str], default: str = "Unknown") -> str:
    """Return the first non-empty value from an XPath/text list."""
    for node in nodes:
        value = str(node).strip()
        if value:
            return value
    return default


def _utc_now() -> str:
    """Return a UTC timestamp suitable for the local evidence store."""
    return datetime.now(timezone.utc).isoformat()


def _ip_sort_key(ip_address: str) -> tuple[int, int, int, int]:
    """Sort IPv4 addresses numerically instead of alphabetically."""
    try:
        values = tuple(int(part) for part in str(ip_address).split("."))
        return values if len(values) == 4 else (999, 999, 999, 999)
    except ValueError:
        return (999, 999, 999, 999)


def _unknown(value: Any) -> bool:
    """Return whether a scanner value should not replace useful inventory data."""
    return value in {None, "", "Unknown", "Not inspected", "N/A"}


def _next_asset_tag(existing_assets: list[dict[str, Any]]) -> str:
    """Create a human-friendly permanent tag inspired by asset registers."""
    highest = 0
    for asset in existing_assets:
        match = re.fullmatch(r"AST-(\d+)", str(asset.get("asset_tag", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"AST-{highest + 1:05d}"


def _clean_client_name(value: Any) -> str:
    """Return a safe client/workspace name for local history separation."""
    cleaned = re.sub(r"\s+", " ", str(value or "").strip())
    return cleaned or DEFAULT_CLIENT_NAME


def load_clients() -> list[str]:
    """Load known client workspaces from PostgreSQL."""
    return sorted(list_client_names(DEFAULT_CLIENT_NAME), key=str.lower)


def save_clients(clients: list[str]) -> None:
    """Persist client workspace names in PostgreSQL."""
    for client in clients:
        db_ensure_client(_clean_client_name(client))


def ensure_client_exists(client_name: str) -> str:
    """Create the PostgreSQL client workspace if it does not already exist."""
    clean_name = _clean_client_name(client_name)
    return db_ensure_client(clean_name)


def get_active_client_name() -> str:
    """Return the client workspace currently selected in the sidebar."""
    try:
        return _clean_client_name(st.session_state.get("active_client_name"))
    except Exception:
        return DEFAULT_CLIENT_NAME


def _active_client(value: Any | None = None) -> str:
    """Return an explicit client name or the active workspace."""
    return _clean_client_name(value) if value else get_active_client_name()


def switch_client_workspace(client_name: str) -> None:
    """Switch local asset and scan-history context to another client."""
    clean_name = ensure_client_exists(client_name)
    st.session_state.active_client_name = clean_name
    st.session_state.assets = load_asset_inventory(clean_name)
    st.session_state.scan_history = load_scan_history(clean_name)
    st.session_state.selected_ip = None
    st.session_state.last_discovery_ips = []
    st.session_state.last_ciso_asset_id = None
    st.session_state.last_openvas_report_id = None
    st.session_state.last_findings = []

    # Live execution selections are always workspace-local. Removing them here
    # prevents a batch/job from the previous client remaining selected.
    for key in (
        "selected_persistent_openvas_batch_id",
        "persistent_openvas_batch_id_selector",
        "persistent_openvas_batch_selector",
        "openvas_live_selected_job_id",
        "openvas_live_filter",
        "openvas_live_search",
        "openvas_job_action_selector",
        "openvas_parallel_pending_launch",
        "openvas_selected_parallel_assets",
    ):
        st.session_state.pop(key, None)
    dynamic_prefixes = (
        "openvas_live_selected_job_id_",
        "openvas_live_filter_",
        "openvas_live_search_",
        "retry_reason_",
        "confirm_rescan_",
    )
    for key in list(st.session_state.keys()):
        if str(key).startswith(dynamic_prefixes):
            st.session_state.pop(key, None)


def _score_value(value: Any) -> int:
    """Normalize CIA scores to the allowed 0–3 range."""
    try:
        score = int(value)
    except (TypeError, ValueError):
        score = 1
    return max(0, min(3, score))


def classify_information(confidentiality: Any, integrity: Any, availability: Any) -> str:
    """Use the highest CIA score to calculate the final information label."""
    highest = max(
        _score_value(confidentiality),
        _score_value(integrity),
        _score_value(availability),
    )
    return CLASSIFICATION_LABELS[highest]


def format_cia_option(score: int) -> str:
    """Display one independent CIA impact score."""
    return f"{score} — {CIA_SCORE_LABELS[score]}"


def cia_summary(asset: dict[str, Any]) -> str:
    """Return a compact CIA score summary."""
    item = normalize_asset(asset)
    return (
        f"C{item['confidentiality_score']} / "
        f"I{item['integrity_score']} / "
        f"A{item['availability_score']}"
    )


def normalize_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Ensure a local asset record contains all management and Nmap fields."""
    defaults: dict[str, Any] = {
        "client_name": get_active_client_name(),
        "asset_tag": "",
        "ip": "Unknown",
        "hostname": "Unknown",
        "mac_address": "Unknown",
        "manufacturer": "Unknown",
        "device_type": "Not inspected",
        "operating_system": "Not inspected",
        "os_confidence": "Not inspected",
        "products": "Not inspected",
        "open_ports": "Not inspected",
        "status": "Discovered",
        "criticality": "Medium",
        "confidentiality_score": 1,
        "integrity_score": 1,
        "availability_score": 1,
        "information_classification": "Internal Use",
        "ntp_server_detected": False,
        "ntp_role": "Unknown",
        "ntp_server_stratum": None,
        "ntp_server_refid": "",
        "ntp_server_offset_ms": None,
        "ntp_server_delay_ms": None,
        "ntp_server_version": None,
        "ntp_server_last_checked": "",
        "ntp_server_error": "",
        "clock_sync_status": "Unknown",
        "clock_source": "",
        "clock_synchronized": None,
        "clock_offset_ms": None,
        "clock_stratum": None,
        "clock_service": "",
        "clock_epoch_ms": None,
        "wazuh_received_epoch_ms": None,
        "manager_agent_delta_ms": None,
        "wazuh_agent_id": "",
        "clock_evidence_source": "",
        "clock_last_checked": "",
        "owner": "Unassigned",
        "location": "Unassigned",
        "vlan_id": "",
        "vlan_name": "",
        "notes": "",
        "source": "Nmap",
        "confirmation": "Not confirmed",
        "first_seen": "",
        "last_seen": "",
        "last_inspected": "",
        "last_scan": "",
        "ciso_asset_id": "",
        "ciso_last_synced": "",
        "inspection_note": "",
    }
    normalized = {**defaults, **asset}
    normalized["client_name"] = _clean_client_name(normalized.get("client_name"))
    normalized["ip"] = str(normalized.get("ip") or "Unknown")
    normalized["asset_tag"] = str(normalized.get("asset_tag") or "")
    normalized["confidentiality_score"] = _score_value(normalized.get("confidentiality_score"))
    normalized["integrity_score"] = _score_value(normalized.get("integrity_score"))
    normalized["availability_score"] = _score_value(normalized.get("availability_score"))
    explicit_classification = str(normalized.get("information_classification") or "").strip()
    if explicit_classification not in INFORMATION_CLASSIFICATION_OPTIONS:
        # Legacy records are migrated from the previous highest-CIA rule.
        explicit_classification = classify_information(
            normalized["confidentiality_score"],
            normalized["integrity_score"],
            normalized["availability_score"],
        )
    normalized["information_classification"] = explicit_classification
    normalized["ntp_server_detected"] = bool(normalized.get("ntp_server_detected"))
    normalized["clock_sync_status"] = str(normalized.get("clock_sync_status") or "Unknown")
    return normalized


def _load_all_asset_records_raw() -> list[dict[str, Any]]:
    """Load all client asset records from PostgreSQL."""
    return load_all_assets()


def load_asset_inventory(client_name: str | None = None) -> list[dict[str, Any]]:
    """Load the persistent PostgreSQL asset register for one client workspace."""
    client = _active_client(client_name)
    assets = []
    for item in load_assets_for_client(client):
        if not isinstance(item, dict):
            continue
        asset = normalize_asset(item)
        asset["client_name"] = client
        assets.append(asset)
    return sorted(assets, key=lambda item: _ip_sort_key(item["ip"]))


def save_asset_inventory(assets: list[dict[str, Any]], client_name: str | None = None) -> None:
    """Persist the current client's asset register in PostgreSQL."""
    client = _active_client(client_name)
    normalized = []
    for asset in assets:
        item = normalize_asset(asset)
        item["client_name"] = client
        normalized.append(item)
    ordered = sorted(normalized, key=lambda item: _ip_sort_key(item["ip"]))
    save_assets_for_client(client, ordered)


def set_asset_inventory(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Update Streamlit state and PostgreSQL inventory for the active client."""
    client = get_active_client_name()
    normalized = []
    for asset in assets:
        item = normalize_asset(asset)
        item["client_name"] = client
        normalized.append(item)
    normalized = sorted(normalized, key=lambda item: _ip_sort_key(item["ip"]))
    st.session_state.assets = normalized
    save_asset_inventory(normalized, client)
    return normalized


def get_nmap_hostname(host_data: Any) -> str:
    """Extract the best hostname from a python-nmap host payload."""
    hostnames = host_data.get("hostnames", [])
    if isinstance(hostnames, list):
        for hostname in hostnames:
            if isinstance(hostname, dict) and hostname.get("name"):
                return str(hostname["name"])
    return "Unknown"


def get_nmap_mac_and_vendor(host_data: Any) -> tuple[str, str]:
    """Extract a local-L2 MAC address and vendor name when Nmap provides one."""
    addresses = host_data.get("addresses", {})
    mac_address = str(addresses.get("mac", "Unknown")) if isinstance(addresses, dict) else "Unknown"
    vendor_data = host_data.get("vendor", {})
    manufacturer = "Unknown"
    if isinstance(vendor_data, dict) and mac_address in vendor_data:
        manufacturer = str(vendor_data[mac_address])
    return mac_address, manufacturer


def get_os_details(host_data: Any) -> tuple[str, str, str]:
    """Return OS guess, device type and confidence from a detailed scan."""
    os_matches = host_data.get("osmatch", [])
    if not isinstance(os_matches, list) or not os_matches:
        return "Unknown", "Unknown", "Unknown"
    first_match = os_matches[0]
    if not isinstance(first_match, dict):
        return "Unknown", "Unknown", "Unknown"
    os_name = str(first_match.get("name", "Unknown"))
    accuracy = str(first_match.get("accuracy", "Unknown"))
    device_types: list[str] = []
    for os_class in first_match.get("osclass", []):
        if isinstance(os_class, dict) and os_class.get("type"):
            device_type = str(os_class["type"])
            if device_type not in device_types:
                device_types.append(device_type)
    return os_name, ", ".join(device_types) or "Unknown", accuracy


def get_services(host_data: Any) -> tuple[str, str]:
    """Return product labels and open-port descriptions from an Nmap record."""
    ports: list[str] = []
    products: list[str] = []
    for protocol in ("tcp", "udp"):
        protocol_data = host_data.get(protocol, {})
        if not isinstance(protocol_data, dict):
            continue
        for port_number in sorted(protocol_data):
            service = protocol_data[port_number]
            if not isinstance(service, dict) or service.get("state") != "open":
                continue
            service_name = str(service.get("name", "unknown"))
            product_parts = [
                str(service.get(key, "")).strip() for key in ("product", "version", "extrainfo")
            ]
            product_text = " ".join(part for part in product_parts if part).strip()
            port_text = f"{port_number}/{protocol} {service_name}"
            if product_text:
                port_text = f"{port_text} ({product_text})"
                if product_text not in products:
                    products.append(product_text)
            ports.append(port_text)
    return "; ".join(products) or "Unknown", "; ".join(ports) or "No open ports detected"


def make_discovery_asset(host: str, host_data: Any) -> dict[str, Any]:
    """Create a lightweight host record from the fast Nmap -sn pass."""
    mac_address, manufacturer = get_nmap_mac_and_vendor(host_data)
    now = _utc_now()
    return normalize_asset(
        {
            "ip": host,
            "hostname": get_nmap_hostname(host_data),
            "mac_address": mac_address,
            "manufacturer": manufacturer,
            "status": "Discovered",
            "source": "Nmap -sn discovery",
            "confirmation": "Confirmed by host discovery",
            "first_seen": now,
            "last_seen": now,
            "inspection_note": (
                "Discovered by Nmap -sn. Select this asset to inspect OS, "
                "device type, services, products and all TCP ports."
            ),
        }
    )


def _prefer_existing_unless_empty(existing_value: Any, incoming_value: Any) -> Any:
    """Protect existing inventory values and only fill empty/unknown cells.

    This preserves the asset inventory table after the first scan. Later scans only
    complete missing values such as Unknown/Not inspected/empty fields.
    """
    if _unknown(existing_value) and not _unknown(incoming_value):
        return incoming_value
    return existing_value


def merge_asset_records(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge scanner data by filling only empty cells.

    Rule:
    - If the asset already exists, do not overwrite existing useful values.
    - Only update fields that are empty/Unknown/Not inspected/N/A.
    - Always refresh last_seen because it is scan evidence, not manual context.
    - Preserve manual/business fields such as owner, VLAN, location, CIA scores.
    """
    current = normalize_asset(existing)
    discovered = normalize_asset(incoming)

    protected_fields = {
        "client_name",
        "asset_tag",
        "criticality",
        "owner",
        "location",
        "vlan_id",
        "vlan_name",
        "notes",
        "ciso_asset_id",
        "ciso_last_synced",
        "last_scan",
        "confidentiality_score",
        "integrity_score",
        "availability_score",
        "information_classification",
    }

    for key, incoming_value in discovered.items():
        if key in protected_fields:
            continue
        current[key] = _prefer_existing_unless_empty(current.get(key), incoming_value)

    current["asset_tag"] = current.get("asset_tag") or discovered.get("asset_tag")
    current["first_seen"] = current.get("first_seen") or discovered.get("first_seen")
    current["last_seen"] = discovered.get("last_seen") or current.get("last_seen")

    # If a later scan provides an inspection timestamp and the existing field is empty, keep it.
    if _unknown(current.get("last_inspected")) and not _unknown(discovered.get("last_inspected")):
        current["last_inspected"] = discovered.get("last_inspected")

    return normalize_asset(current)


def upsert_assets(incoming_assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge discovered assets into the persistent register by IP address."""
    current = [normalize_asset(asset) for asset in st.session_state.assets]
    by_ip = {asset["ip"]: asset for asset in current}
    for incoming in incoming_assets:
        candidate = normalize_asset(incoming)
        existing = by_ip.get(candidate["ip"])
        if existing:
            by_ip[candidate["ip"]] = merge_asset_records(existing, candidate)
        else:
            candidate["asset_tag"] = _next_asset_tag(list(by_ip.values()))
            by_ip[candidate["ip"]] = candidate
    return set_asset_inventory(list(by_ip.values()))


def discover_assets(network: str) -> list[dict[str, Any]]:
    """Fast first-pass discovery across the whole authorized subnet.

    The command is intentionally restricted to ``-sn -n``. It discovers live
    hosts but performs no port, OS or service scan across a large CIDR.
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments="-sn -n")
    discovered: list[dict[str, Any]] = []
    for host in scanner.all_hosts():
        host_data = scanner[host]
        if host_data.state() == "up":
            discovered.append(make_discovery_asset(host, host_data))
    return sorted(discovered, key=lambda item: _ip_sort_key(item["ip"]))


def parse_candidate_ips(raw_value: str) -> tuple[list[str], list[str]]:
    """Parse trusted IPv4 candidates pasted from DHCP, AD, ARP or firewall data."""
    import ipaddress

    valid: list[str] = []
    invalid: list[str] = []
    for value in re.split(r"[\s,;]+", raw_value.strip()):
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 4:
                invalid.append(value)
                continue
            parsed = str(ip)
            if parsed not in valid:
                valid.append(parsed)
        except ValueError:
            invalid.append(value)
    return valid, invalid


def confirm_missed_candidates(
    candidate_ips: list[str],
    known_ips: set[str],
    batch_limit: int,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Confirm trusted missed hosts with -Pn and all TCP ports.

    A candidate is stored only if at least one TCP port replies ``open`` or
    ``closed``. A result where all ports are filtered remains unconfirmed.
    """
    to_scan = [ip for ip in candidate_ips if ip not in known_ips][:batch_limit]
    result: dict[str, Any] = {
        "requested": len(candidate_ips),
        "already_known": [ip for ip in candidate_ips if ip in known_ips],
        "scanned": to_scan,
        "confirmed": [],
        "unconfirmed": [],
    }

    for index, ip in enumerate(to_scan, start=1):
        if progress_callback:
            progress_callback(f"Confirming candidate {index}/{len(to_scan)}: {ip}")
        scanner = nmap.PortScanner()
        arguments = (
            "-n -Pn -sT -p- --reason "
            f"--max-retries {NMAP_CONFIRM_MAX_RETRIES} "
            f"--host-timeout {NMAP_CONFIRM_HOST_TIMEOUT} -T3"
        )
        try:
            scanner.scan(hosts=ip, arguments=arguments)
        except nmap.PortScannerError as exc:
            result["unconfirmed"].append({"ip": ip, "reason": str(exc)})
            continue

        if ip not in scanner.all_hosts():
            result["unconfirmed"].append({"ip": ip, "reason": "No Nmap response"})
            continue

        host_data = scanner[ip]
        tcp_data = host_data.get("tcp", {})
        responsive: list[str] = []
        open_ports: list[str] = []
        if isinstance(tcp_data, dict):
            for port, details in tcp_data.items():
                state = str(details.get("state", "")) if isinstance(details, dict) else ""
                if state in {"open", "closed"}:
                    responsive.append(f"{port}/tcp {state}")
                if state == "open":
                    service = (
                        str(details.get("name", "unknown"))
                        if isinstance(details, dict)
                        else "unknown"
                    )
                    open_ports.append(f"{port}/tcp {service}")

        if not responsive:
            result["unconfirmed"].append(
                {
                    "ip": ip,
                    "reason": "All tested TCP ports were filtered or no TCP response was received",
                }
            )
            continue

        mac_address, manufacturer = get_nmap_mac_and_vendor(host_data)
        now = _utc_now()
        result["confirmed"].append(
            normalize_asset(
                {
                    "ip": ip,
                    "hostname": get_nmap_hostname(host_data),
                    "mac_address": mac_address,
                    "manufacturer": manufacturer,
                    "status": "Discovered",
                    "source": "Trusted candidate confirmation (-Pn, all TCP ports)",
                    "confirmation": f"Confirmed by TCP response: {responsive[0]}",
                    "first_seen": now,
                    "last_seen": now,
                    "open_ports": "; ".join(open_ports) or "No open ports detected",
                    "inspection_note": (
                        "Candidate confirmed with -Pn and all TCP ports. "
                        "Run selected-asset inspection for OS, device type and service versions."
                    ),
                }
            )
        )

    return result


def inspect_asset(host: str) -> dict[str, Any]:
    """Inspect one explicitly selected host with -Pn and all TCP ports."""
    scanner = nmap.PortScanner()
    inspection_note = "Detailed all-TCP-port Nmap inspection completed."
    try:
        scanner.scan(
            hosts=host,
            arguments=(
                f"-n -Pn -sS {NMAP_DETAIL_PORTS} -sV --version-light "
                f"-O --osscan-guess --reason --host-timeout {NMAP_DETAIL_HOST_TIMEOUT} -T3"
            ),
        )
    except nmap.PortScannerError:
        scanner.scan(
            hosts=host,
            arguments=(
                f"-n -Pn -sT {NMAP_DETAIL_PORTS} -sV --version-light "
                f"--reason --host-timeout {NMAP_DETAIL_HOST_TIMEOUT} -T3"
            ),
        )
        inspection_note = (
            "Detailed all-TCP-port service scan completed. OS/device type was not "
            "detected; run Streamlit as Administrator with Npcap to enable OS detection."
        )

    if host not in scanner.all_hosts():
        raise RuntimeError("Nmap did not return the selected host after inspection.")

    host_data = scanner[host]
    mac_address, manufacturer = get_nmap_mac_and_vendor(host_data)
    operating_system, device_type, os_confidence = get_os_details(host_data)
    products, open_ports = get_services(host_data)
    now = _utc_now()
    return normalize_asset(
        {
            "ip": host,
            "hostname": get_nmap_hostname(host_data),
            "status": "Discovered",
            "mac_address": mac_address,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "operating_system": operating_system,
            "os_confidence": os_confidence,
            "products": products,
            "open_ports": open_ports,
            "last_seen": now,
            "last_inspected": now,
            "source": "Selected asset Nmap inspection (-Pn, all TCP ports)",
            "confirmation": "Confirmed by selected host inspection",
            "inspection_note": inspection_note,
        }
    )


def merge_asset(
    assets: list[dict[str, Any]], updated_asset: dict[str, Any]
) -> list[dict[str, Any]]:
    """Merge detailed Nmap data into one asset and persist the register."""
    by_ip = {normalize_asset(asset)["ip"]: normalize_asset(asset) for asset in assets}
    existing = by_ip.get(updated_asset["ip"], {})
    merged = merge_asset_records(existing, updated_asset)
    if not merged.get("asset_tag"):
        merged["asset_tag"] = _next_asset_tag(list(by_ip.values()))
    by_ip[merged["ip"]] = merged
    return set_asset_inventory(list(by_ip.values()))


def resolve_ciso_scope_ids() -> tuple[str, str]:
    """Validate configured CISO IDs and auto-bootstrap stale/missing scope IDs."""
    client = CisoAssistantClient(load_ciso_config())
    folder_id = str(CISO_FOLDER_ID or "").strip()
    perimeter_id = str(CISO_PERIMETER_ID or "").strip()

    if folder_id:
        try:
            client._request("GET", f"/api/folders/{folder_id}/")
        except CisoApiError:
            folder_id = ""
            perimeter_id = ""

    if not folder_id:
        folder, perimeter = client.bootstrap_scope()
        folder_id = str(folder.get("id") or "")
        perimeter_id = str(perimeter.get("id") or "")
        if not folder_id or not perimeter_id:
            raise CisoApiError("CISO scope bootstrap did not return valid IDs.")
        return folder_id, perimeter_id

    if perimeter_id:
        try:
            client._request("GET", f"/api/perimeters/{perimeter_id}/")
            return folder_id, perimeter_id
        except CisoApiError:
            perimeter_id = ""

    perimeter = client.get_or_create_perimeter(folder_id)
    perimeter_id = str(perimeter.get("id") or "")
    if not perimeter_id:
        raise CisoApiError("CISO perimeter resolution failed.")
    return folder_id, perimeter_id


def sync_asset_to_ciso(asset: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Create or update a validated local asset in CISO Assistant."""
    folder_id, _perimeter_id = resolve_ciso_scope_ids()

    asset_tag = str(asset.get("asset_tag") or f"HOST-{asset['ip']}")
    hostname = str(asset.get("hostname") or "Unknown")
    ref_id = str(asset.get("ciso_ref_id") or f"securescope:{asset_tag}")
    client = CisoAssistantClient(load_ciso_config())
    ciso_asset, created = client.sync_asset(
        folder_id=folder_id,
        name=f"{asset_tag} — {hostname if hostname != 'Unknown' else asset['ip']}",
        ref_id=ref_id,
        description=format_nmap_asset_description(asset),
        asset_type="SP",
    )
    asset["ciso_ref_id"] = ref_id
    asset["ciso_asset_id"] = str(ciso_asset.get("id") or "")
    asset["ciso_last_synced"] = _utc_now()
    if "assets" in st.session_state and asset.get("asset_tag"):
        saved_assets = [normalize_asset(item) for item in st.session_state.assets]
        for saved_asset in saved_assets:
            if saved_asset.get("asset_tag") == asset.get("asset_tag"):
                saved_asset.update(asset)
                break
        set_asset_inventory(saved_assets)
    return ciso_asset, created


def _is_retryable_gvm_connection_error(exc: BaseException) -> bool:
    """Return True for transient tunnel/GMP connection failures.

    Windows error 10054 means the local GMP socket was reset by the remote side.
    It normally concerns the management connection through the SSH tunnel, not
    necessarily the scanned target itself.
    """
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, EOFError)):
        return True

    if isinstance(exc, socket.timeout):
        return True

    if isinstance(exc, OSError):
        winerror = getattr(exc, "winerror", None)
        errno_value = getattr(exc, "errno", None)
        if winerror in {10053, 10054, 10057, 10060, 10061}:
            return True
        if errno_value in {32, 54, 104, 110, 111}:
            return True

    message = str(exc).lower()
    return any(
        token in message
        for token in (
            "forcibly closed",
            "connection reset",
            "broken pipe",
            "connection aborted",
            "unexpected eof",
            "timed out",
        )
    )


def run_openvas_scan(
    target_ip: str,
    status_placeholder: Any,
    status_callback: Optional[Any] = None,
) -> tuple[str, list[Any], str]:
    """Create, execute, monitor, and fetch one OpenVAS report.

    The task ID is retained after creation. If the GMP socket or SSH tunnel
    channel is reset (including WinError 10054), the app reconnects,
    re-authenticates, and resumes monitoring the same OpenVAS task instead of
    immediately failing the asset.
    """
    transform = EtreeCheckCommandTransform()
    timestamp = int(time.time())

    task_id = ""
    report_id = ""
    final_status = "Unknown"
    retry_count = 0
    last_progress = "0"

    def publish(
        phase: str,
        message: str,
        progress: Optional[str] = None,
        attempt: Optional[int] = None,
    ) -> None:
        status_placeholder.info(message)
        if status_callback is not None:
            try:
                status_callback(
                    {
                        "phase": phase,
                        "message": message,
                        "progress": progress,
                        "attempt": attempt,
                        "task_id": task_id,
                        "report_id": report_id,
                    }
                )
            except Exception:
                logger.debug("OpenVAS status callback failed.", exc_info=True)

    while True:
        try:
            publish(
                "Connecting",
                f"{target_ip} — connecting to gvmd through the Windows SSH tunnel…",
                last_progress,
                retry_count + 1,
            )

            with GMP(
                connection=make_gmp_connection(),
                transform=transform,
            ) as gmp:
                publish(
                    "Authenticating",
                    f"{target_ip} — authenticating with GVM…",
                    last_progress,
                    retry_count + 1,
                )
                gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)

                # Create/start the task only once. After a connection reset,
                # reuse task_id and continue polling the same OpenVAS task.
                if not task_id:
                    publish(
                        "Preparing",
                        f"{target_ip} — resolving OpenVAS scan resources…",
                        "0",
                        retry_count + 1,
                    )

                    configs = gmp.get_scan_configs()
                    config_id = find_first_id(
                        configs.xpath(f"config[name='{SCAN_CONFIG_NAME}']/@id"),
                        f"Scan config '{SCAN_CONFIG_NAME}'",
                    )

                    port_lists = gmp.get_port_lists()
                    port_list_id = find_first_id(
                        port_lists.xpath(f"port_list[name='{PORT_LIST_NAME}']/@id"),
                        f"Port list '{PORT_LIST_NAME}'",
                    )

                    scanners = gmp.get_scanners()
                    scanner_id = find_first_id(
                        scanners.xpath(f"scanner[name='{SCANNER_NAME}']/@id"),
                        f"Scanner '{SCANNER_NAME}'",
                    )

                    target_response = gmp.create_target(
                        name=f"target-{target_ip}-{timestamp}",
                        hosts=[target_ip],
                        port_list_id=port_list_id,
                    )
                    target_id = target_response.get("id")

                    if not target_id:
                        raise GvmError("GVM did not return an ID for the created target.")

                    task_response = gmp.create_task(
                        name=f"scan-{target_ip}-{timestamp}",
                        config_id=config_id,
                        target_id=target_id,
                        scanner_id=scanner_id,
                    )
                    task_id = task_response.get("id") or ""

                    if not task_id:
                        raise GvmError("GVM did not return an ID for the created task.")

                    gmp.start_task(task_id)
                    publish(
                        "Started",
                        f"{target_ip} — OpenVAS task started.",
                        "0",
                        retry_count + 1,
                    )

                task: Optional[Any] = None

                while True:
                    task = gmp.get_task(task_id)

                    status_nodes = task.xpath("task/status/text()")
                    progress_nodes = task.xpath("task/progress/text()")

                    task_status = get_first_text(status_nodes)
                    last_progress = get_first_text(progress_nodes, default=last_progress or "0")

                    publish(
                        "Scanning",
                        f"{target_ip} — {task_status} ({last_progress}%)",
                        last_progress,
                        retry_count + 1,
                    )

                    if task_status in {"Done", "Stopped", "Interrupted"}:
                        final_status = task_status
                        report_id = get_first_text(
                            task.xpath("task/last_report/report/@id"),
                            default="",
                        )
                        break

                    time.sleep(TASK_POLL_SECONDS)

                if task is None:
                    raise GvmError("GVM scan task could not be retrieved.")

                if not report_id:
                    publish(
                        final_status,
                        f"{target_ip} — scan ended with no report ID.",
                        last_progress,
                        retry_count + 1,
                    )
                    return final_status, [], ""

                publish(
                    "Fetching report",
                    f"{target_ip} — fetching OpenVAS report {report_id}…",
                    "100" if final_status == "Done" else last_progress,
                    retry_count + 1,
                )

                report = gmp.get_report(
                    report_id,
                    filter_string=f"rows={REPORT_MAX_ROWS} min_qod=0",
                    details=True,
                    ignore_pagination=False,
                )

                results = report.xpath("report/report/results/result")
                publish(
                    "Completed" if final_status == "Done" else final_status,
                    f"{target_ip} — OpenVAS scan {final_status.lower()}.",
                    "100" if final_status == "Done" else last_progress,
                    retry_count + 1,
                )
                return final_status, results, report_id

        except Exception as exc:
            if _is_retryable_gvm_connection_error(exc) and retry_count < OPENVAS_CONNECTION_RETRIES:
                retry_count += 1
                publish(
                    "Reconnecting",
                    (
                        f"{target_ip} — GMP connection was reset ({exc}). "
                        f"Reconnecting in {OPENVAS_RECONNECT_DELAY_SECONDS}s "
                        f"({retry_count}/{OPENVAS_CONNECTION_RETRIES})…"
                    ),
                    last_progress,
                    retry_count + 1,
                )
                time.sleep(OPENVAS_RECONNECT_DELAY_SECONDS)
                continue

            if status_callback is not None:
                try:
                    status_callback(
                        {
                            "phase": "Failed",
                            "message": str(exc),
                            "progress": last_progress,
                            "attempt": retry_count + 1,
                            "task_id": task_id,
                            "report_id": report_id,
                        }
                    )
                except Exception:
                    logger.debug("OpenVAS failure callback failed.", exc_info=True)

            raise


def get_severity_badge(severity: float) -> str:
    """Return a display badge for a CVSS severity score."""
    if severity >= 9:
        return "Critical"
    if severity >= 7:
        return "High"
    if severity >= 4:
        return "Medium"
    if severity > 0:
        return "Low"
    return "Info"


def parse_severity(severity_values: list[str]) -> float:
    """Parse a GVM severity value safely."""
    try:
        return float(severity_values[0]) if severity_values else 0.0
    except (TypeError, ValueError):
        return 0.0


def get_integration_ref(prefix: str, *parts: str) -> str:
    """Return a stable, API-safe reference ID for CISO synchronization."""
    raw = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


ISO_CONTROL_CATALOG: dict[str, dict[str, str]] = {
    "A.5.7": {
        "name": "Threat intelligence",
        "evidence": "CVE/NVT references and scanner vulnerability intelligence.",
    },
    "A.5.9": {
        "name": "Inventory of information and other associated assets",
        "evidence": "Nmap inventory: IP, hostname, MAC, vendor, OS and services.",
    },
    "A.5.28": {
        "name": "Collection of evidence",
        "evidence": "Report ID, timestamp, CVE/NVT evidence and remediation output.",
    },
    "A.5.37": {
        "name": "Documented operating procedures",
        "evidence": "Discovery, scan, risk, treatment and re-test workflow.",
    },
    "A.8.2": {
        "name": "Privileged access rights",
        "evidence": "Review of exposed administrative and remote-access services.",
    },
    "A.8.3": {
        "name": "Information access restriction",
        "evidence": "Review of exposed services and unnecessary reachability.",
    },
    "A.8.5": {
        "name": "Secure authentication",
        "evidence": "Authentication findings and hardening recommendations.",
    },
    "A.8.7": {
        "name": "Protection against malware",
        "evidence": "Malware-related findings and mitigation actions.",
    },
    "A.8.8": {
        "name": "Management of technical vulnerabilities",
        "evidence": "OpenVAS/Nuclei scan, CVSS/CVE analysis, remediation and re-test evidence.",
    },
    "A.8.9": {
        "name": "Configuration management",
        "evidence": "Configuration findings and hardening recommendations.",
    },
    "A.8.13": {
        "name": "Information backup",
        "evidence": "Backup-related findings and remediation recommendations.",
    },
    "A.8.15": {
        "name": "Logging",
        "evidence": "Stored report IDs, timestamps, scan history and synchronization results.",
    },
    "A.8.16": {
        "name": "Monitoring activities",
        "evidence": "Repeated scans, findings dashboard and severity monitoring.",
    },
    "A.8.19": {
        "name": "Installation of software on operational systems",
        "evidence": "Patch and obsolete-software findings.",
    },
    "A.8.20": {
        "name": "Networks security",
        "evidence": "Open-port discovery and network-hardening recommendations.",
    },
    "A.8.21": {
        "name": "Security of network services",
        "evidence": "Network services, products, versions and exposure information.",
    },
    "A.8.22": {
        "name": "Segregation of networks",
        "evidence": "Network-exposure evidence and segmentation recommendations.",
    },
    "A.8.24": {
        "name": "Use of cryptography",
        "evidence": "TLS, SSL, certificate and cipher findings.",
    },
    "A.8.25": {
        "name": "Secure development life cycle",
        "evidence": "Application vulnerability evidence can feed secure development.",
    },
    "A.8.26": {
        "name": "Application security requirements",
        "evidence": "Web and API findings inform application security requirements.",
    },
    "A.8.29": {
        "name": "Security testing in development and acceptance",
        "evidence": "Repeatable vulnerability testing and documented test results.",
    },
}

BASE_ISMS_CLAUSES = (
    "6.1.2 Risk assessment; 6.1.3 Risk treatment; "
    "8.2 Operational risk assessment; 8.3 Operational risk treatment; "
    "9.1 Monitoring, measurement, analysis and evaluation"
)


def _finding_text(finding_name: str, description: str, solution: str) -> str:
    """Build normalized text used by ISO mapping rules."""
    return " ".join((finding_name, description, solution)).lower()


def _port_number(port: str) -> int | None:
    """Extract the numeric port from an OpenVAS port field."""
    match = re.match(r"\\s*(\\d+)", str(port or ""))
    return int(match.group(1)) if match else None


def _add_iso_control(
    controls: list[dict[str, str]],
    control_id: str,
    rationale: str,
) -> None:
    """Add one suggested control once."""
    if any(item["id"] == control_id for item in controls):
        return

    catalog = ISO_CONTROL_CATALOG[control_id]
    controls.append(
        {
            "id": control_id,
            "name": catalog["name"],
            "rationale": rationale,
            "evidence": catalog["evidence"],
        }
    )


def suggest_iso_controls(
    *,
    finding_name: str,
    description: str,
    solution: str,
    port: str,
    cve: str,
    cvss: float,
) -> list[dict[str, str]]:
    """Suggest relevant ISO/IEC 27001:2022 controls for a technical finding.

    This is a technical evidence mapping. It does not automatically establish
    that a control is applicable, implemented or effective.
    """
    text = _finding_text(finding_name, description, solution)
    parsed_port = _port_number(port)
    controls: list[dict[str, str]] = []

    _add_iso_control(
        controls,
        "A.8.8",
        "A vulnerability scanner identifies a technical vulnerability, supports exposure "
        "evaluation and records a proposed remediation.",
    )
    _add_iso_control(
        controls,
        "A.5.28",
        "The report retains host, port, CVE/NVT and remediation evidence.",
    )
    _add_iso_control(
        controls,
        "A.8.15",
        "Scan report identifiers, timestamps and sync results form an audit trail.",
    )
    _add_iso_control(
        controls,
        "A.8.16",
        "The finding is monitored through the dashboard and future scans.",
    )

    if cve and str(cve).upper() not in {"N/A", "NONE", "UNKNOWN"}:
        _add_iso_control(
            controls,
            "A.5.7",
            "CVE data is vulnerability intelligence used to prioritize exposure.",
        )

    if any(word in text for word in ("configuration", "misconfiguration", "default", "hardening")):
        _add_iso_control(
            controls,
            "A.8.9",
            "The result indicates that a configuration baseline or hardening "
            "measure should be reviewed.",
        )

    if any(
        word in text
        for word in ("unsupported", "end of life", "obsolete", "outdated", "patch", "update")
    ):
        _add_iso_control(
            controls,
            "A.8.19",
            "The treatment concerns secure installation, patching or removal "
            "of obsolete operational software.",
        )

    remote_access_ports = {22, 23, 3389, 5900, 5985, 5986}
    remote_access_words = (
        "ssh",
        "telnet",
        "rdp",
        "remote desktop",
        "vnc",
        "winrm",
        "default credential",
        "weak password",
        "brute force",
    )
    if parsed_port in remote_access_ports or any(word in text for word in remote_access_words):
        _add_iso_control(
            controls,
            "A.8.2",
            "The exposed service may provide privileged or remote administrative access.",
        )
        _add_iso_control(
            controls,
            "A.8.3",
            "The exposed service requires access restriction to approved users and paths.",
        )
        _add_iso_control(
            controls,
            "A.8.5",
            "Authentication controls should be reviewed for this exposure.",
        )

    web_ports = {80, 443, 8000, 8080, 8081, 8443, 8888}
    web_words = (
        "http",
        "https",
        "web",
        "apache",
        "nginx",
        "tomcat",
        "iis",
        "xss",
        "cross-site",
        "sql injection",
        "directory traversal",
        "csrf",
        "web application",
    )
    if parsed_port in web_ports or any(word in text for word in web_words):
        _add_iso_control(
            controls,
            "A.8.20",
            "The result concerns network exposure of a web or API interface.",
        )
        _add_iso_control(
            controls,
            "A.8.21",
            "Security mechanisms and requirements of the detected network service need review.",
        )
        _add_iso_control(
            controls,
            "A.8.26",
            "The result can inform application security requirements.",
        )
        _add_iso_control(
            controls,
            "A.8.29",
            "The scanner output is evidence from repeatable security testing.",
        )

    database_ports = {1433, 1521, 3306, 5432, 6379, 27017}
    database_words = ("mysql", "postgres", "mssql", "oracle", "mongodb", "database")
    if parsed_port in database_ports or any(word in text for word in database_words):
        _add_iso_control(
            controls,
            "A.8.3",
            "Database exposure requires access restriction to approved users and systems.",
        )
        _add_iso_control(
            controls,
            "A.8.5",
            "Database authentication settings require review.",
        )
        _add_iso_control(
            controls,
            "A.8.9",
            "Database configuration should be baselined, reviewed and hardened.",
        )

    if parsed_port in {139, 445} or any(word in text for word in ("smb", "netbios", "share")):
        _add_iso_control(
            controls,
            "A.8.20",
            "SMB or NetBIOS exposure should be secured using network controls.",
        )
        _add_iso_control(
            controls,
            "A.8.21",
            "File-sharing service requirements and mechanisms need review.",
        )
        _add_iso_control(
            controls,
            "A.8.9",
            "SMB service configuration and hardening should be reviewed.",
        )

    if any(
        word in text
        for word in ("tls", "ssl", "certificate", "cipher", "cryptograph", "encryption")
    ):
        _add_iso_control(
            controls,
            "A.8.24",
            "The result concerns TLS, certificates, ciphers or cryptographic configuration.",
        )

    if "malware" in text or "virus" in text:
        _add_iso_control(
            controls,
            "A.8.7",
            "The finding relates to malware protection or anti-malware measures.",
        )

    if "backup" in text or "restore" in text:
        _add_iso_control(
            controls,
            "A.8.13",
            "The finding concerns backup protection, recoverability or backup testing.",
        )

    if cvss >= 7:
        _add_iso_control(
            controls,
            "A.5.37",
            "High-severity remediation should follow a documented operating procedure.",
        )

    return controls


def enrich_finding_with_iso_mapping(finding: dict[str, Any]) -> dict[str, Any]:
    """Add analyst-review ISO mapping data to an OpenVAS finding."""
    enriched = dict(finding)
    mapping = suggest_iso_controls(
        finding_name=str(enriched.get("Finding", "")),
        description=str(enriched.get("Description", "")),
        solution=str(enriched.get("Solution", "")),
        port=str(enriched.get("Port", "")),
        cve=str(enriched.get("CVE", "")),
        cvss=float(enriched.get("CVSS", 0) or 0),
    )
    enriched["ISO Mapping"] = mapping
    enriched["ISO Controls"] = "; ".join(f"{item['id']} {item['name']}" for item in mapping)
    enriched["ISMS Clauses"] = BASE_ISMS_CLAUSES
    enriched["ISO Rationale"] = " | ".join(item["rationale"] for item in mapping[:3])
    cvss = float(enriched.get("CVSS", 0) or 0)
    enriched["Treatment Priority"] = (
        "Immediate" if cvss >= 9 else "High" if cvss >= 7 else "Planned" if cvss >= 4 else "Routine"
    )
    enriched["ISO Mapping Status"] = "Suggested — analyst validation required"
    return enriched


def ensure_iso_mapping(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add mapping data to older locally stored findings when it is absent."""
    return [
        (
            item
            if item.get("ISO Mapping") and item.get("ISO Controls")
            else enrich_finding_with_iso_mapping(item)
        )
        for item in findings
    ]


def parse_openvas_results(
    results: list[Any],
    report_id: str,
) -> list[dict[str, Any]]:
    """Normalize GVM XML into dashboard, ISO-mapping and CISO rows."""
    findings: list[dict[str, Any]] = []

    for result in results:
        severity = parse_severity(result.xpath("severity/text()"))
        cves = get_first_text(result.xpath("nvt/cve/text()"), default="N/A")
        port = get_first_text(result.xpath("port/text()"), default="N/A")
        host = get_first_text(result.xpath("host/text()"), default="N/A")
        nvt_oid = get_first_text(result.xpath("nvt/@oid"), default="Unknown")
        qod = get_first_text(result.xpath("qod/value/text()"), default="Unknown")
        solution = get_first_text(
            result.xpath("nvt/solution/text()"),
            default="No remediation provided by the scanner.",
        )
        description = get_first_text(
            result.xpath("description/text()"),
            default="No description provided by the scanner.",
        )
        finding_name = get_first_text(
            result.xpath("name/text()"),
            default="Unnamed finding",
        )
        source_key = f"{host}|{port}|{nvt_oid}|{finding_name}"

        base_finding = {
            "Severity": get_severity_badge(severity),
            "CVSS": round(severity, 1),
            "Finding": finding_name,
            "CVE": cves,
            "Host": host,
            "Port": port,
            "NVT OID": nvt_oid,
            "QOD": qod,
            "Report ID": report_id,
            "Solution": solution,
            "Description": description,
            "finding_ref_id": get_integration_ref(
                "openvas-finding",
                report_id,
                source_key,
            ),
            "vulnerability_ref_id": get_integration_ref(
                "openvas-vuln",
                source_key,
            ),
            "risk_ref_id": get_integration_ref(
                "openvas-risk",
                source_key,
            ),
        }
        findings.append(enrich_finding_with_iso_mapping(base_finding))

    return sorted(findings, key=lambda item: item["CVSS"], reverse=True)


def update_asset_management_fields(
    asset_tag: str,
    *,
    status: str,
    criticality: str,
    information_classification: str,
    confidentiality_score: int,
    integrity_score: int,
    availability_score: int,
    owner: str,
    location: str,
    vlan_id: str,
    vlan_name: str,
    notes: str,
) -> dict[str, Any] | None:
    """Save analyst-managed lifecycle and ownership fields for one asset."""
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    updated: dict[str, Any] | None = None
    for asset in assets:
        if asset.get("asset_tag") != asset_tag:
            continue
        asset.update(
            {
                "status": status,
                "criticality": criticality,
                "information_classification": (
                    information_classification
                    if information_classification in INFORMATION_CLASSIFICATION_OPTIONS
                    else "Internal Use"
                ),
                "confidentiality_score": _score_value(confidentiality_score),
                "integrity_score": _score_value(integrity_score),
                "availability_score": _score_value(availability_score),
                "owner": owner.strip() or "Unassigned",
                "location": location.strip() or "Unassigned",
                "vlan_id": vlan_id.strip(),
                "vlan_name": vlan_name.strip(),
                "notes": notes.strip(),
            }
        )
        updated = normalize_asset(asset)
        break
    if updated is not None:
        set_asset_inventory(assets)
    return updated


def _clock_offset_label(value: Any) -> str:
    if value in {None, ""}:
        return "Not measured"
    try:
        return f"{float(value):.3f} ms"
    except (TypeError, ValueError):
        return str(value)


def _ntp_status_label(asset: dict[str, Any]) -> str:
    item = normalize_asset(asset)
    clock_status = str(item.get("clock_sync_status") or "Unknown")
    if clock_status not in {"", "Unknown", "No evidence"}:
        return clock_status
    if item.get("ntp_server_detected"):
        return "NTP server detected"
    if item.get("ntp_server_error"):
        return "No NTP response"
    return "Not checked"


def _apply_ntp_server_results(
    results: list[dict[str, Any]],
) -> int:
    by_ip = {str(result.get("ip") or ""): result for result in results}
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    changed = 0

    for asset in assets:
        result = by_ip.get(str(asset.get("ip") or ""))
        if not result:
            continue

        for key in (
            "ntp_server_detected",
            "ntp_role",
            "ntp_server_stratum",
            "ntp_server_refid",
            "ntp_server_offset_ms",
            "ntp_server_delay_ms",
            "ntp_server_version",
            "ntp_server_last_checked",
            "ntp_server_error",
        ):
            if key in result:
                asset[key] = result.get(key)

        changed += 1

    if changed:
        set_asset_inventory(assets)
    return changed


def _match_clock_evidence(
    asset: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    asset_ip = str(asset.get("ip") or "").strip().lower()
    asset_hostname = str(asset.get("hostname") or "").strip().lower()
    evidence_ip = str(evidence.get("asset_ip") or "").strip().lower()
    evidence_hostname = str(evidence.get("asset_hostname") or "").strip().lower()

    if asset_ip and evidence_ip and asset_ip == evidence_ip:
        return True
    if (
        asset_hostname
        and asset_hostname not in {"unknown", "not detected"}
        and evidence_hostname
        and (
            asset_hostname == evidence_hostname
            or asset_hostname in evidence_hostname
            or evidence_hostname in asset_hostname
        )
    ):
        return True
    return False


def _apply_wazuh_clock_evidence(
    evidence_rows: list[dict[str, Any]],
    *,
    tolerance_ms: float,
) -> int:
    """Match, persist and apply Wazuh endpoint clock evidence.

    Nmap inventory identity remains the source of asset scope. Matching uses
    asset IP first, hostname second and the persisted Wazuh agent correlation
    as a final fallback. Missing evidence remains visible and is never treated
    as compliant.
    """
    client_name = get_active_client_name()
    assets = [normalize_asset(asset) for asset in st.session_state.assets]

    try:
        agent_rows = load_latest_wazuh_status(client_name)
    except Exception:
        agent_rows = []

    merged_assets = match_clock_evidence_to_assets(
        assets,
        evidence_rows,
        agent_rows=agent_rows,
    )

    evidence_to_store: list[dict[str, Any]] = []
    changed = 0
    for asset in merged_assets:
        if asset.get("clock_evidence_source"):
            asset["clock_sync_status"] = apply_clock_status(
                asset,
                tolerance_ms=tolerance_ms,
            )
            evidence_to_store.append(dict(asset))
            changed += 1

    if evidence_to_store:
        save_clock_evidence(client_name, evidence_to_store)

    if merged_assets:
        set_asset_inventory(merged_assets)

    return changed


def _ntp_inventory_rows(
    assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the combined network and endpoint clock-assurance table."""
    rows: list[dict[str, Any]] = []

    for asset in assets:
        item = normalize_asset(asset)
        rows.append(
            {
                "Asset": item.get("asset_tag"),
                "IP address": item.get("ip"),
                "Hostname": item.get("hostname"),
                "NTP server": ("Detected" if item.get("ntp_server_detected") else "Not detected"),
                "Server role": item.get("ntp_role") or "Unknown",
                "Server stratum": item.get("ntp_server_stratum"),
                "Server reference": (item.get("ntp_server_refid") or "Not available"),
                "Server offset": _clock_offset_label(item.get("ntp_server_offset_ms")),
                "Endpoint sync": _ntp_status_label(item),
                "Endpoint source": (item.get("clock_source") or "No endpoint evidence"),
                "Endpoint stratum": item.get("clock_stratum"),
                "Endpoint offset": _clock_offset_label(item.get("clock_offset_ms")),
                "Manager/agent delta": _clock_offset_label(item.get("manager_agent_delta_ms")),
                "Wazuh agent": item.get("wazuh_agent_id") or "",
                "Evidence": (
                    item.get("clock_evidence_source")
                    or ("Network NTP response" if item.get("ntp_server_detected") else "None")
                ),
                "Last checked": (
                    str(
                        item.get("clock_last_checked") or item.get("ntp_server_last_checked") or ""
                    ).replace("T", " ")[:19]
                    or "Never"
                ),
            }
        )

    return rows


def render_ntp_clock_synchronization_panel(
    selected_asset: dict[str, Any],
) -> None:
    """Render NTP discovery and Wazuh endpoint clock assurance.

    UDP/123 discovery identifies time servers. ISO A.8.17 assurance uses the
    endpoint time-service state, reported offset and a supporting comparison
    between the endpoint epoch embedded in the event and the Wazuh manager
    receipt timestamp.
    """
    section_heading(
        "Clock synchronization",
        (
            "Discover NTP servers on UDP/123 and verify every inventoried "
            "endpoint through Wazuh clock evidence."
        ),
    )
    st.caption(
        "An NTP response proves that an asset provides time service; it does "
        "not prove that the asset itself is synchronized. Endpoint evidence "
        "from Wazuh is required for the ISO A.8.17 conclusion."
    )

    threshold_cols = st.columns(3)
    with threshold_cols[0]:
        tolerance_ms = st.number_input(
            "Allowed source offset (ms)",
            min_value=1.0,
            max_value=60000.0,
            value=float(DEFAULT_TOLERANCE_MS),
            step=100.0,
            key="ntp_offset_tolerance_ms",
        )
    with threshold_cols[1]:
        manager_delta_ms = st.number_input(
            "Allowed manager/agent delta (ms)",
            min_value=100.0,
            max_value=300000.0,
            value=float(DEFAULT_MANAGER_DELTA_TOLERANCE_MS),
            step=500.0,
            key="ntp_manager_delta_tolerance_ms",
            help=(
                "This supporting comparison includes transport and indexing "
                "delay, so it uses a wider threshold than the NTP source offset."
            ),
        )
    with threshold_cols[2]:
        max_age_minutes = st.number_input(
            "Evidence maximum age (minutes)",
            min_value=1.0,
            max_value=10080.0,
            value=float(DEFAULT_EVIDENCE_MAX_AGE_MINUTES),
            step=15.0,
            key="ntp_evidence_max_age_minutes",
        )

    network_tab, endpoint_tab, fleet_tab = module_tabs(
        [
            "NTP server discovery",
            "Endpoint synchronization",
            "Fleet status",
        ]
    )

    with network_tab:
        scope = st.radio(
            "Network audit scope",
            ["Selected asset", "All assets"],
            horizontal=True,
            key="ntp_network_audit_scope",
        )
        timeout = st.number_input(
            "NTP response timeout (seconds)",
            min_value=0.5,
            max_value=15.0,
            value=2.5,
            step=0.5,
            key="ntp_query_timeout",
        )
        if st.button(
            "Run NTP server discovery",
            icon=":material/schedule:",
            type="primary",
            key="run_ntp_server_discovery",
        ):
            targets = (
                [selected_asset] if scope == "Selected asset" else list(st.session_state.assets)
            )
            with st.spinner(f"Checking UDP/123 on {len(targets)} asset(s)…"):
                results = audit_ntp_servers(
                    targets,
                    timeout=float(timeout),
                )
                changed = _apply_ntp_server_results(results)

            detected = sum(1 for result in results if result.get("ntp_server_detected"))
            st.success(
                f"NTP audit saved for {changed} asset(s); "
                f"{detected} server response(s) detected."
            )
            st.dataframe(
                pd.DataFrame(results),
                width="stretch",
                hide_index=True,
            )
            st.rerun()

        st.info(
            "Use this result to identify internal NTP servers. Client-only "
            "devices normally do not listen on UDP/123."
        )

    with endpoint_tab:
        indexer_ready = bool(
            os.getenv("WAZUH_INDEXER_URL")
            and os.getenv("WAZUH_INDEXER_USER")
            and os.getenv("WAZUH_INDEXER_PASSWORD")
        )

        if not indexer_ready:
            st.warning(
                "Wazuh Indexer credentials are not configured. Add "
                "WAZUH_INDEXER_URL, WAZUH_INDEXER_USER and "
                "WAZUH_INDEXER_PASSWORD to .env."
            )

        action_cols = st.columns(2)
        with action_cols[0]:
            collect_clicked = st.button(
                "Collect endpoint clock evidence from Wazuh",
                icon=":material/sync:",
                type="primary",
                disabled=not indexer_ready,
                key="collect_wazuh_ntp_evidence",
                width="stretch",
            )
        with action_cols[1]:
            guide_path = WAZUH_ROOT / "README_NTP.md"
            if guide_path.exists():
                st.download_button(
                    "Download Wazuh deployment guide",
                    data=guide_path.read_bytes(),
                    file_name="SecureScope_Wazuh_Clock_Deployment.md",
                    mime="text/markdown",
                    width="stretch",
                )
            else:
                st.button(
                    "Deployment guide unavailable",
                    disabled=True,
                    width="stretch",
                )

        if collect_clicked:
            try:
                with st.spinner("Reading latest SECURESCOPE_NTP evidence from Wazuh…"):
                    evidence = collect_wazuh_ntp_evidence(limit=5000)
                    changed = _apply_wazuh_clock_evidence(
                        evidence,
                        tolerance_ms=float(tolerance_ms),
                    )
                    from securescope.evidence.wazuh_bridge import ingest_wazuh_evidence
                    from securescope.ui.evidence_collection_context import (
                        current_collection_context,
                    )
                    from securescope.ui.grc_workspace.context import current_actor

                    client = get_active_client_name()
                    ingest_wazuh_evidence(
                        client, current_actor(), current_collection_context(client)
                    )
                st.success(
                    f"Collected {len(evidence)} endpoint record(s); "
                    f"matched and persisted {changed} SecureScope asset(s)."
                )
                if evidence:
                    display = pd.DataFrame(evidence).drop(
                        columns=["clock_raw"],
                        errors="ignore",
                    )
                    st.dataframe(
                        display,
                        width="stretch",
                        hide_index=True,
                    )
                st.rerun()
            except (
                NtpAuditError,
                ClockEvidenceDatabaseError,
            ) as exc:
                st.error(f"Wazuh clock evidence collection failed: {exc}")
            except Exception as exc:
                st.error(f"Wazuh clock evidence collection failed: " f"{type(exc).__name__}: {exc}")

        st.markdown(
            """
            **Endpoint evidence expected**

            - Windows: source, synchronization state and offset from `w32tm`
            - Linux: source, synchronization state and offset from `chronyc`,
              `ntpq` or `timedatectl`
            - The probe includes the endpoint UTC epoch in one
              `SECURESCOPE_NTP` JSON line
            - Wazuh's event timestamp is used as the manager receipt time
            """
        )

        with st.expander("Deployment files and exact locations"):
            st.code(
                "Windows probe: integrations/wazuh/windows/securescope_time_sync.ps1\n"
                "Linux probe: integrations/wazuh/linux/securescope_time_sync.sh\n"
                "Central configuration: integrations/wazuh/manager/agent.conf.example\n"
                "Decoder: integrations/wazuh/manager/local_decoder.xml\n"
                "Rules: integrations/wazuh/manager/local_rules.xml\n"
                "Validation: integrations/wazuh/manager/validate_manager_clock_rules.sh",
                language="text",
            )

    with fleet_tab:
        assets = [normalize_asset(asset) for asset in st.session_state.assets]

        try:
            persisted = load_latest_clock_evidence(get_active_client_name())
        except ClockEvidenceDatabaseError as exc:
            persisted = []
            st.warning(f"Clock evidence persistence is unavailable: {exc}")

        if persisted:
            try:
                agent_rows = load_latest_wazuh_status(get_active_client_name())
            except Exception:
                agent_rows = []
            assets = match_clock_evidence_to_assets(
                assets,
                persisted,
                agent_rows=agent_rows,
            )

        for asset in assets:
            if asset.get("clock_evidence_source"):
                asset["clock_sync_status"] = apply_clock_status(
                    asset,
                    tolerance_ms=float(tolerance_ms),
                    manager_delta_tolerance_ms=float(manager_delta_ms),
                    max_age_minutes=float(max_age_minutes),
                )

        summary = fleet_clock_summary(
            assets,
            tolerance_ms=float(tolerance_ms),
        )

        metric_cols = st.columns(5)
        with metric_cols[0]:
            dashboard_metric_card(
                "Fleet status",
                summary["status"],
                (
                    f"{summary['assets_with_endpoint_evidence']}/"
                    f"{summary['assets_total']} with endpoint evidence"
                ),
                ("healthy" if summary["status"] == "Synchronized" else "risk"),
            )
        with metric_cols[1]:
            dashboard_metric_card(
                "Synchronized",
                summary["synchronized_assets"],
                f"Source tolerance ±{float(tolerance_ms):.0f} ms",
                "neutral",
            )
        with metric_cols[2]:
            dashboard_metric_card(
                "Clock gaps",
                summary["gap_assets"],
                "Unsynchronized, stale or out of tolerance",
                "risk" if summary["gap_assets"] else "neutral",
            )
        with metric_cols[3]:
            max_offset = summary["max_absolute_offset_ms"]
            dashboard_metric_card(
                "Maximum source offset",
                (f"{max_offset:.3f} ms" if max_offset is not None else "Unknown"),
                "Largest endpoint-reported offset",
                "neutral",
            )
        with metric_cols[4]:
            max_delta = summary.get("max_manager_agent_delta_ms")
            dashboard_metric_card(
                "Maximum manager delta",
                (f"{max_delta:.0f} ms" if max_delta is not None else "Unknown"),
                "Includes transport and indexing delay",
                "neutral",
            )

        if summary["status"] == "Synchronized":
            st.success(
                "All inventoried assets have fresh endpoint evidence and are "
                "within the configured clock thresholds."
            )
        elif summary["status"] == "Partial evidence":
            st.warning(
                "Not every Nmap asset has Wazuh endpoint clock evidence. "
                "Fleet-wide synchronization cannot yet be confirmed."
            )
        elif summary["status"] == "Multiple time sources":
            st.warning(
                "The checked endpoints report different time sources. Review "
                "the approved organizational time hierarchy."
            )
        elif summary["status"] == "Synchronization gap":
            st.error(
                "At least one endpoint is unsynchronized, stale or outside "
                "the configured source/manager thresholds."
            )
        else:
            st.info(
                "Collect endpoint evidence before making a fleet-wide "
                "synchronization conclusion."
            )

        st.dataframe(
            _ntp_inventory_rows(assets),
            width="stretch",
            hide_index=True,
            height=460,
        )


def apply_bulk_status(asset_tags: list[str], new_status: str) -> int:
    """Apply one lifecycle status to explicitly selected asset tags."""
    if not asset_tags:
        return 0
    changed = 0
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    for asset in assets:
        if asset.get("asset_tag") in asset_tags:
            asset["status"] = new_status
            changed += 1
    if changed:
        set_asset_inventory(assets)
    return changed


def mark_asset_scan(asset_ip: str) -> None:
    """Record the local timestamp of a completed OpenVAS scan on the asset."""
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    for asset in assets:
        if asset.get("ip") == asset_ip:
            asset["last_scan"] = _utc_now()
            break
    set_asset_inventory(assets)


def _load_all_scan_history_raw() -> list[dict[str, Any]]:
    """Load all scan records from PostgreSQL."""
    return load_all_scan_history()


def load_scan_history(client_name: str | None = None) -> list[dict[str, Any]]:
    """Load saved scanner reports for one client from PostgreSQL."""
    client = _active_client(client_name)
    records = []
    for item in load_scan_history_for_client(client, MAX_SCAN_HISTORY):
        if not isinstance(item, dict):
            continue
        item["client_name"] = client
        records.append(item)
    return records[:MAX_SCAN_HISTORY]


def save_scan_history(history: list[dict[str, Any]], client_name: str | None = None) -> None:
    """Save dashboard data for the active client in PostgreSQL."""
    client = _active_client(client_name)
    active_records = []
    for record in history[:MAX_SCAN_HISTORY]:
        item = dict(record)
        item["client_name"] = client
        active_records.append(item)
    save_scan_history_for_client(client, active_records, MAX_SCAN_HISTORY)


def upsert_scan_history(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Save one scan record for the active client, replacing the same report."""
    client = get_active_client_name()
    item = dict(record)
    item["client_name"] = client
    history = list(st.session_state.scan_history)
    report_id = item.get("report_id")
    history = [entry for entry in history if entry.get("report_id") != report_id]
    history.insert(0, item)
    st.session_state.scan_history = history[:MAX_SCAN_HISTORY]
    save_scan_history(st.session_state.scan_history, client)
    return st.session_state.scan_history


def make_scan_record(
    *,
    report_id: str,
    asset: dict[str, str],
    findings: list[dict[str, Any]],
    final_status: str,
) -> dict[str, Any]:
    """Build a locally persisted representation of one OpenVAS report."""
    return {
        "client_name": get_active_client_name(),
        "scanner": "OpenVAS / Greenbone",
        "scanner_engine": ENGINE_OPENVAS,
        "report_id": report_id,
        "asset_ip": asset["ip"],
        "asset": asset,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "final_status": final_status,
        "findings": ensure_iso_mapping(findings),
        "ciso_sync": None,
        "ciso_asset_id": None,
    }


def sync_scan_record_to_ciso(
    record: dict[str, Any],
    progress_placeholder: Any | None = None,
) -> dict[str, Any]:
    """Synchronize a completed OpenVAS report into CISO Assistant."""
    folder_id, perimeter_id = resolve_ciso_scope_ids()

    def update_progress(message: str) -> None:
        if progress_placeholder is not None:
            progress_placeholder.info(message)

    update_progress("Synchronizing the scanned asset to CISO Assistant…")
    ciso_asset, _created = sync_asset_to_ciso(record["asset"])
    ciso_asset_id = ciso_asset.get("id")
    if not ciso_asset_id:
        raise CisoApiError("CISO asset synchronization did not return an ID.")

    record["findings"] = ensure_iso_mapping(record.get("findings", []))
    client = CisoAssistantClient(load_ciso_config())
    sync_result = client.sync_openvas_findings(
        findings=record["findings"],
        folder_id=folder_id,
        perimeter_id=perimeter_id,
        asset_id=str(ciso_asset_id),
        report_id=record["report_id"],
        target_ip=record["asset_ip"],
        risk_min_cvss=CISO_MIN_CVSS_FOR_RISK,
        progress_callback=update_progress,
    )
    sync_result["ciso_asset_id"] = ciso_asset_id
    return sync_result


def get_severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Return ordered finding counts for the dashboard."""
    order = ["Critical", "High", "Medium", "Low", "Info"]
    counter = Counter(str(item.get("Severity", "Info")) for item in findings)
    return {severity: counter.get(severity, 0) for severity in order}


def severity_style(severity: str) -> tuple[str, str, str]:
    """Return a CSS class, compact label, and icon for a severity."""
    styles = {
        "Critical": ("critical", "CRITICAL", "⚠"),
        "High": ("high", "HIGH", "▲"),
        "Medium": ("medium", "MEDIUM", "●"),
        "Low": ("low", "LOW", "●"),
        "Info": ("info", "INFO", "i"),
    }
    return styles.get(severity, styles["Info"])


# Compatibility names retain existing callers; one shared implementation owns HTML.
dashboard_metric_card = metric_card
dashboard_panel = panel_heading


def render_severity_donut(severity_counts: dict[str, int]) -> None:
    """Render a modern donut chart with no extra chart dependencies."""
    chart_data = pd.DataFrame(
        {
            "Severity": list(severity_counts.keys()),
            "Findings": list(severity_counts.values()),
        }
    )
    chart_data = chart_data[chart_data["Findings"] > 0]

    if chart_data.empty:
        st.info("No scored findings are available for this report.")
        return

    chart_spec = {
        "mark": {
            "type": "arc",
            "innerRadius": 66,
            "cornerRadius": 5,
            "padAngle": 0.02,
        },
        "encoding": {
            "theta": {
                "field": "Findings",
                "type": "quantitative",
                "stack": True,
            },
            "color": {
                "field": "Severity",
                "type": "nominal",
                "legend": {"title": None, "orient": "bottom"},
                "scale": {
                    "domain": ["Critical", "High", "Medium", "Low", "Info"],
                    "range": [
                        "#ef4444",
                        "#f97316",
                        "#fbbf24",
                        "#38bdf8",
                        "#94a3b8",
                    ],
                },
            },
            "tooltip": [
                {"field": "Severity", "type": "nominal"},
                {"field": "Findings", "type": "quantitative"},
            ],
        },
        "view": {"stroke": None},
        "height": 270,
    }
    st.vega_lite_chart(chart_data, chart_spec, width="stretch")


def _report_option_label(record: dict[str, Any]) -> str:
    """Build a readable report selector label."""
    report_id = str(record.get("report_id", "unknown"))
    scanned_at = str(record.get("scanned_at", "")).replace("T", " ")[:19]
    engine = str(record.get("scanner_engine") or record.get("scanner") or "OpenVAS")
    return (
        f"{engine} • {record.get('asset_ip', 'Unknown host')} • "
        f"{scanned_at or 'Unknown date'} • {report_id[:8]}"
    )


def _iso_status_style(status: str) -> str:
    """Return a compact status label used in ISO assessment tables."""
    value = str(status or "")
    if value in {"Implemented", "Likely implemented"}:
        return "Implemented / positive evidence"
    if value in {"Partially implemented"} or "Partially implemented" in value:
        return "Partial implementation"
    if value in {"Not implemented", "Gap detected"} or "Gap detected" in value:
        return "Gap / not implemented"
    if value == "Not applicable":
        return "Not applicable"
    return "Needs evidence / validation"


def _iso_assessment_table_rows(assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in assessments:
        rows.append(
            {
                "Control": item["control_id"],
                "Control name": item["control_name"],
                "Automated conclusion": item["automated_status"],
                "Confidence": item["confidence"],
                "Technical score": item["score"],
                "Applicability": item["applicability"],
                "Validated status": item["validated_status"],
                "Final status": item["final_status"],
                "Evidence sources": ", ".join(item.get("sources") or []),
                "Main evidence": " | ".join(text for text in (item.get("evidence") or []) if text),
                "Main gaps": " | ".join(text for text in (item.get("gaps") or []) if text),
                "Owner": item.get("owner") or "",
                "Reviewed by": item.get("reviewed_by") or "",
                "Review date": item.get("review_date") or "",
            }
        )
    return rows


def render_iso_mapping_page() -> None:
    """Render complete ISO/IEC 27001 Annex A.8 implementation assessment."""
    client_name = get_active_client_name()
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    records = list(st.session_state.scan_history)

    try:
        persisted_clock_rows = load_latest_clock_evidence(client_name)
    except ClockEvidenceDatabaseError:
        persisted_clock_rows = []

    wazuh_rows: list[dict[str, Any]] = []
    wazuh_warning = ""
    if WAZUH_INTEGRATION_AVAILABLE:
        try:
            wazuh_rows = load_latest_wazuh_status(client_name)
        except Exception as exc:
            wazuh_warning = str(exc)

    try:
        reviews = load_iso_control_reviews(client_name)
    except IsoAssessmentDatabaseError as exc:
        st.error(f"Could not load ISO control reviews from PostgreSQL: {exc}")
        reviews = {}

    if persisted_clock_rows:
        assets = match_clock_evidence_to_assets(
            assets,
            persisted_clock_rows,
            agent_rows=wazuh_rows,
        )

    automated = evaluate_a8_controls(assets, records, wazuh_rows)
    assessments = add_maturity(merge_reviews(automated, reviews))
    assurance_summary = assessment_summary(assessments)

    page_hero(
        "ISO/IEC 27001:2022 — A.8 TECHNICAL ASSURANCE",
        "Technical Assurance",
        (
            "SecureScope combines Nmap inventory, OpenVAS/Nuclei findings, Wazuh monitoring "
            "and manually validated enterprise evidence. Scanner evidence alone cannot "
            "prove every organizational or development control."
        ),
        f"{len(assessments)} A.8 controls evaluated",
        "ready" if assets or records or wazuh_rows else "warning",
    )

    st.button(
        "Back to Control Assurance",
        icon=":material/arrow_back:",
        width="content",
        key="technical_assurance_back_to_controls",
        on_click=_select_sidebar_navigation,
        args=("Gap Assessment",),
    )

    st.warning(
        "Automated conclusions are decision support. A control is shown as fully "
        "Implemented only after an authorized analyst validates applicability, "
        "evidence, ownership and operating effectiveness."
    )

    if wazuh_warning:
        st.info(
            "Wazuh evidence could not be loaded, so logging/monitoring conclusions "
            f"may be incomplete: {wazuh_warning}"
        )

    implemented = sum(1 for item in assessments if item["final_status"] == "Implemented")
    partial = sum(
        1
        for item in assessments
        if item["final_status"] == "Partially implemented"
        or "Partially implemented" in item["final_status"]
    )
    not_implemented = sum(
        1
        for item in assessments
        if item["final_status"] == "Not implemented" or "Gap detected" in item["final_status"]
    )
    pending = sum(
        1
        for item in assessments
        if item["validated_status"] == "Not reviewed" and item["applicability"] != "Not applicable"
    )

    metric_cols = st.columns(6)
    with metric_cols[0]:
        dashboard_metric_card(
            "Readiness",
            f"{assurance_summary['readiness_score']}%",
            "Average evidence score across A.8",
            "ready" if assurance_summary["readiness_score"] >= 75 else "risk",
        )
    with metric_cols[1]:
        dashboard_metric_card(
            "Maturity",
            f"{assurance_summary['maturity_level']} · {assurance_summary['maturity_label']}",
            "Evidence-based maturity indicator",
            "neutral",
        )
    with metric_cols[2]:
        dashboard_metric_card(
            "Implemented",
            implemented,
            "Validated by analyst",
            "ready" if implemented else "neutral",
        )
    with metric_cols[3]:
        dashboard_metric_card(
            "Partial", partial, "Technical or validated partial", "medium" if partial else "neutral"
        )
    with metric_cols[4]:
        dashboard_metric_card(
            "Gaps",
            not_implemented,
            "Detected or validated gaps",
            "critical" if not_implemented else "neutral",
        )
    with metric_cols[5]:
        dashboard_metric_card(
            "Pending review",
            pending,
            "Analyst validation required",
            "risk" if pending else "neutral",
        )

    tabs = module_tabs(
        container=st.container(key="iso_a8_icon_tabs"),
        labels=[
            ":material/dashboard: A.8 dashboard",
            ":material/fact_check: Review control",
            ":material/link: Technical evidence",
            ":material/schema: Methodology",
            ":material/description: A.8 export",
        ],
    )

    with tabs[0]:
        section_heading(
            "All technological controls",
            "Filter, review and export the combined automated and validated assessment.",
        )

        filter_left, filter_middle, filter_right = st.columns(3)
        with filter_left:
            auto_filter = st.multiselect(
                "Automated conclusion",
                [
                    "Likely implemented",
                    "Partially implemented",
                    "Gap detected",
                    "Insufficient evidence",
                ],
                default=[
                    "Likely implemented",
                    "Partially implemented",
                    "Gap detected",
                    "Insufficient evidence",
                ],
                key="iso_a8_auto_filter",
            )
        with filter_middle:
            confidence_filter = st.multiselect(
                "Confidence",
                ["High", "Medium", "Low"],
                default=["High", "Medium", "Low"],
                key="iso_a8_confidence_filter",
            )
        with filter_right:
            final_filter = st.multiselect(
                "Validated/final status",
                [
                    "Implemented",
                    "Partially implemented",
                    "Not implemented",
                    "Not applicable",
                    "Pending validation",
                ],
                default=[
                    "Implemented",
                    "Partially implemented",
                    "Not implemented",
                    "Not applicable",
                    "Pending validation",
                ],
                key="iso_a8_final_filter",
            )

        def matches_final(item: dict[str, Any]) -> bool:
            final_value = item["final_status"]
            if final_value.startswith("Pending validation"):
                return "Pending validation" in final_filter
            return final_value in final_filter

        filtered = [
            item
            for item in assessments
            if item["automated_status"] in auto_filter
            and item["confidence"] in confidence_filter
            and matches_final(item)
        ]

        table_rows = _iso_assessment_table_rows(filtered)
        table_columns = [
            "Control",
            "Control name",
            "Automated conclusion",
            "Confidence",
            "Technical score",
            "Applicability",
            "Validated status",
            "Final status",
            "Main evidence",
            "Main gaps",
            "Owner",
            "Review date",
        ]
        st.dataframe(
            (
                pd.DataFrame(table_rows)[table_columns]
                if table_rows
                else pd.DataFrame(columns=table_columns)
            ),
            width="stretch",
            hide_index=True,
            height=620,
        )

        export_rows = _iso_assessment_table_rows(assessments)
        export_frame = pd.DataFrame(export_rows)

        export_col, snapshot_col = st.columns(2)
        with export_col:
            st.download_button(
                "Export complete A.8 assessment CSV",
                data=export_frame.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"{client_name.replace(' ', '_').lower()}_iso27001_a8_assessment.csv",
                mime="text/csv",
                width="stretch",
            )

        with snapshot_col:
            if st.button(
                "Save assessment snapshot to PostgreSQL",
                width="stretch",
                key="save_iso_a8_snapshot",
            ):
                try:
                    snapshot_id = save_iso_assessment_snapshot(client_name, assessments)
                    action_count = synchronize_corrective_actions(
                        client_name,
                        assessments,
                    )
                    st.success(
                        f"ISO A.8 assessment snapshot #{snapshot_id} saved; "
                        f"{action_count} corrective action(s) synchronized."
                    )
                except IsoAssessmentDatabaseError as exc:
                    st.error(f"Could not save assessment snapshot: {exc}")

        try:
            latest_snapshot = latest_iso_assessment_snapshot(client_name)
        except IsoAssessmentDatabaseError:
            latest_snapshot = None

        if latest_snapshot:
            st.caption(
                f"Latest saved assessment snapshot: #{latest_snapshot.get('id')} "
                f"at {latest_snapshot.get('created_at')}."
            )

    with tabs[1]:
        section_heading(
            "Analyst validation and enterprise evidence",
            "Review one control and approve the final implementation status.",
        )

        control_options = {
            f"{item['control_id']} — {item['control_name']}": item for item in assessments
        }
        selected_label = st.selectbox(
            "Select A.8 control",
            list(control_options.keys()),
            key="iso_a8_control_selector",
        )
        selected = control_options[selected_label]

        detail_metrics = st.columns(4)
        with detail_metrics[0]:
            dashboard_metric_card(
                "Automated conclusion",
                selected["automated_status"],
                f"Confidence: {selected['confidence']}",
                "neutral",
            )
        with detail_metrics[1]:
            dashboard_metric_card(
                "Technical score",
                selected["score"] if selected["score"] is not None else "Not assessed",
                (
                    "Human assessment required"
                    if selected["score"] is None
                    else "0–100 evidence signal"
                ),
                "neutral",
            )
        with detail_metrics[2]:
            dashboard_metric_card(
                "Validated status",
                selected["validated_status"],
                "Analyst-approved status",
                "neutral",
            )
        with detail_metrics[3]:
            dashboard_metric_card(
                "Final status",
                selected["final_status"],
                _iso_status_style(selected["final_status"]),
                "neutral",
            )

        st.subheader(f"{selected['control_id']} — {selected['control_name']}")
        st.write(selected["description"])
        st.caption(f"Automatic assessment scope: {selected['automatic_scope']}")

        evidence_col, gaps_col = st.columns(2)
        with evidence_col:
            st.markdown("#### Technical evidence")
            evidence_items = [item for item in selected.get("evidence", []) if item]
            if evidence_items:
                for item in evidence_items:
                    st.success(item)
            else:
                st.info("No reliable technical evidence is currently available.")

            st.caption("Sources: " + ", ".join(selected.get("sources") or ["No source"]))

        with gaps_col:
            st.markdown("#### Missing evidence / gaps")
            gap_items = [item for item in selected.get("gaps", []) if item]
            if gap_items:
                for item in gap_items:
                    st.warning(item)
            else:
                st.success("No technical gap is currently recorded.")

        with st.form("iso_a8_review_form"):
            form_left, form_right = st.columns(2)

            with form_left:
                applicability_index = (
                    APPLICABILITY_OPTIONS.index(selected["applicability"])
                    if selected["applicability"] in APPLICABILITY_OPTIONS
                    else 0
                )
                applicability = st.selectbox(
                    "Applicability",
                    APPLICABILITY_OPTIONS,
                    index=applicability_index,
                )

                validated_index = (
                    VALIDATED_STATUSES.index(selected["validated_status"])
                    if selected["validated_status"] in VALIDATED_STATUSES
                    else 0
                )
                validated_status = st.selectbox(
                    "Validated implementation status",
                    VALIDATED_STATUSES,
                    index=validated_index,
                    help=(
                        "Select Implemented only when design, implementation and "
                        "operating effectiveness are supported by evidence."
                    ),
                )

                owner = st.text_input(
                    "Control owner",
                    value=selected.get("owner") or "",
                    placeholder="Example: IT Operations Manager",
                )

            with form_right:
                reviewed_by = st.text_input(
                    "Reviewed by",
                    value=selected.get("reviewed_by") or "",
                    placeholder="Example: Information Security Officer",
                )

                current_review_date = selected.get("review_date")
                try:
                    default_review_date = datetime.fromisoformat(str(current_review_date)).date()
                except Exception:
                    default_review_date = datetime.now().date()

                review_date = st.date_input(
                    "Review date",
                    value=default_review_date,
                )

                evidence_notes = st.text_area(
                    "Enterprise evidence references and analyst notes",
                    value=selected.get("evidence_notes") or "",
                    height=170,
                    placeholder=(
                        "Examples: policy ID, screenshot, ticket, repository setting, "
                        "restore-test report, firewall rule review, access-review record."
                    ),
                )

            save_review = st.form_submit_button(
                "Save control review",
                type="primary",
                width="stretch",
            )

        if save_review:
            try:
                save_iso_control_review(
                    client_name=client_name,
                    control_id=selected["control_id"],
                    applicability=applicability,
                    validated_status=validated_status,
                    owner=owner,
                    reviewed_by=reviewed_by,
                    review_date=review_date.isoformat(),
                    evidence_notes=evidence_notes,
                )
                st.success(f"{selected['control_id']} review saved in PostgreSQL.")
                st.rerun()
            except (IsoAssessmentDatabaseError, ValueError) as exc:
                st.error(f"Could not save control review: {exc}")

    with tabs[2]:
        section_heading(
            "Vulnerability finding-to-control evidence",
            "Technical findings are mapped to relevant controls for analyst review.",
        )

        all_findings: list[dict[str, Any]] = []
        for record in records:
            mapped_findings = ensure_iso_mapping(record.get("findings", []))
            for finding in mapped_findings:
                mappings = finding.get("ISO Mapping") or []
                all_findings.append(
                    {
                        "Report ID": record.get("report_id"),
                        "Asset": record.get("asset_ip"),
                        "Severity": finding.get("Severity"),
                        "CVSS": finding.get("CVSS"),
                        "Finding": finding.get("Finding"),
                        "Port": finding.get("Port"),
                        "CVE": finding.get("CVE"),
                        "Mapped controls": ", ".join(item.get("id", "") for item in mappings),
                        "Treatment priority": finding.get("Treatment Priority"),
                    }
                )

        if all_findings:
            selected_severities = st.multiselect(
                "Severity",
                ["Critical", "High", "Medium", "Low", "Info"],
                default=["Critical", "High", "Medium", "Low", "Info"],
                key="iso_a8_finding_severity",
            )
            visible = [item for item in all_findings if item.get("Severity") in selected_severities]
            st.dataframe(
                pd.DataFrame(visible),
                width="stretch",
                hide_index=True,
                height=560,
            )
        else:
            st.info(
                "No vulnerability findings are stored yet. Run OpenVAS or Nuclei to generate "
                "finding-to-control evidence."
            )

    with tabs[3]:
        section_heading(
            "Assessment methodology and limitations",
            "How SecureScope decides whether a technological control is supported.",
        )

        st.markdown(
            (
                "\n            ### Evidence model\n\n            **Nmap** "
                "provides asset, host, port, service, operating-system and\n  "
                "          segmentation metadata.\n\n            **OpenVAS and "
                "Nuclei** provide vulnerability, CVE, CVSS, configuration,\n  "
                "          authentication, software, network-service and "
                "cryptography evidence.\n\n            **Wazuh** provides "
                "endpoint coverage, logging and monitoring evidence.\n\n       "
                "     **Asset Management** provides owners, locations, "
                "VLANs, criticality,\n            CIA classification and "
                "lifecycle context.\n\n            **Analyst evidence** "
                "provides policies, procedures, reviews,\n            "
                "approvals, contracts, backups, source-control, development "
                "and other\n            organizational evidence that scanners "
                "cannot verify.\n\n            ### Status logic\n\n            - "
                "**Likely implemented:** strong technical evidence exists, "
                "but analyst validation is still required.\n            - "
                "**Partially implemented:** some evidence exists, but "
                "coverage or governance evidence is incomplete.\n            "
                "- **Gap detected:** the technical data shows a material "
                "weakness or missing capability.\n            - "
                "**Insufficient evidence:** Nmap/scanner/Wazuh evidence "
                "cannot reliably assess the control.\n            - "
                "**Implemented:** only an analyst can approve this final "
                "status after checking evidence and effectiveness.\n\n         "
                "   ### Important limitation\n\n            A clean "
                "vulnerability scan does **not** prove that a control is\n    "
                "        implemented. It only means the stored scan did not "
                "detect a matching\n            technical weakness. "
                "Organizational controls must be validated with\n            "
                "documents, configurations, interviews, logs, tickets and "
                "operating evidence.\n            "
            )
        )

        methodology_rows = [
            {
                "Control": control_id,
                "Control name": details["name"],
                "Automatic assessment scope": details["automatic_scope"],
            }
            for control_id, details in sorted(
                ISO_A8_CONTROLS.items(),
                key=lambda item: int(item[0].split(".")[-1]),
            )
        ]
        st.dataframe(
            pd.DataFrame(methodology_rows),
            width="stretch",
            hide_index=True,
            height=620,
        )

    with tabs[4]:
        section_heading(
            "A.8 assurance export",
            (
                "Export the reviewed technical-assurance view without duplicating "
                "the full Evidence Hub workflow."
            ),
        )

        try:
            report_actions = list_corrective_actions(client_name)
        except IsoAssessmentDatabaseError:
            report_actions = []

        clock_summary = fleet_clock_summary(assets)
        export_columns = st.columns(2, gap="medium")
        with export_columns[0]:
            try:
                assurance_pdf = build_iso_assurance_pdf(
                    client_name=client_name,
                    assessments=assessments,
                    actions=report_actions,
                    clock_summary=clock_summary,
                )
                st.download_button(
                    "Download A.8 assurance PDF",
                    data=assurance_pdf,
                    file_name=(f"{client_name}_ISO_27001_A8_assurance.pdf").replace(" ", "_"),
                    mime="application/pdf",
                    type="primary",
                    width="stretch",
                )
            except Exception as exc:
                st.error(f"Could not generate ISO PDF: {exc}")

        with export_columns[1]:
            st.info(
                "The Evidence Hub is the canonical place for evidence review, "
                "requests and auditor packages. Technical Assurance only keeps "
                "the A.8-specific assessment export."
            )
            st.button(
                "Open Evidence Hub",
                width="stretch",
                key="iso_a8_open_evidence_hub",
                on_click=_select_sidebar_navigation,
                args=("ISO Evidence Hub",),
            )

        st.markdown("#### Follow-up")
        follow_up_columns = st.columns(2, gap="medium")
        with follow_up_columns[0]:
            st.button(
                "Review control gaps & SoA",
                width="stretch",
                key="iso_a8_open_controls_soa",
                on_click=_select_sidebar_navigation,
                args=("Gap Assessment",),
            )
        with follow_up_columns[1]:
            st.button(
                "Open technical remediation",
                width="stretch",
                key="iso_a8_open_remediation",
                on_click=_select_sidebar_navigation,
                args=("Remediation",),
            )


def page_hero(
    eyebrow: str,
    title: str,
    subtitle: str,
    badge: str,
    badge_style: str = "neutral",
) -> None:
    """Render a compact page title without duplicating explanatory content.

    Args:
        eyebrow: Legacy section label retained for API compatibility.
        title: User-facing page title.
        subtitle: Legacy descriptive text retained for API compatibility.
        badge: Optional short current-state label.
        badge_style: Visual state for the compact badge.

    Returns:
        None.
    """

    del eyebrow, subtitle
    chip = (
        f'<span class="ss-page-chip {safe_text(badge_style)}">' f"{safe_text(badge)}</span>"
        if str(badge or "").strip()
        else ""
    )
    st.markdown(
        f"""
        <div class="ss-simple-page-header">
            <h1>{safe_text(title)}</h1>
            {chip}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_heading(title: str, subtitle: str = "") -> None:
    """Delegate section titles to the shared escaped component.

    Args:
        title: Section title.
        subtitle: Supporting text.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    panel_heading(title, subtitle)


def asset_meta_card(label: str, value: Any) -> None:
    """Render an asset property through the shared metric component.

    Args:
        label: Property label.
        value: Property value.
    Returns:
        None.
    Raises:
        Streamlit rendering errors propagate.
    """
    metric_card(label, value if value is not None else "Unknown")


def get_current_asset() -> dict[str, str] | None:
    """Return the asset selected in the current Streamlit session."""
    selected_ip = st.session_state.get("selected_ip")
    return next(
        (asset for asset in st.session_state.assets if asset.get("ip") == selected_ip),
        None,
    )


def navigate_to_scan_center(asset_ip: str) -> None:
    """Set the selected OpenVAS target before Streamlit renders widgets.

    Streamlit callbacks run before widgets are instantiated for the new run,
    which makes this safe for updating the sidebar navigation radio key.
    """
    st.session_state.selected_ip = asset_ip
    navigate_to("3 · Scan Center")


def latest_scan_record() -> dict[str, Any] | None:
    """Return the most recent locally stored scan record."""
    history = st.session_state.scan_history
    if not history:
        return None

    return max(
        history,
        key=lambda item: str(item.get("scanned_at", "")),
    )


def _select_sidebar_navigation(navigation_label: str) -> None:
    """Navigate using the modern page registry with a legacy fallback."""

    navigate_to(navigation_label)


def _switch_client_from_dialog(client_name: str) -> None:
    """Open a client and route to its engagement-aware workspace overview.

    Args:
        client_name: Exact client workspace selected in the dialog.

    Returns:
        None.

    Raises:
        DatabaseError: Propagated when the workspace cannot be loaded.
    """

    switch_client_workspace(client_name)
    st.session_state["client_selector"] = client_name
    navigate_to("ISO Command Center")


@st.dialog("Client workspaces", width="large")
def render_client_workspace_dialog() -> None:
    """Readable client switch/create dialog outside the dark sidebar."""
    clients = load_clients()
    active_client = get_active_client_name()

    st.caption(
        "Workspaces keep separate assets, scanner history, findings, reports "
        "and ISO control reviews."
    )

    switch_tab, create_tab = module_tabs(["Switch workspace", "Create workspace"])

    with switch_tab:
        search = st.text_input(
            "Search clients",
            placeholder="Type a client name",
            key="client_dialog_search",
        )
        filtered = [client for client in clients if search.strip().lower() in client.lower()]

        if not filtered:
            st.info("No client workspace matches this search.")
        else:
            for client in filtered:
                active = client == active_client
                left, right = st.columns([4, 1], vertical_alignment="center")
                with left:
                    st.markdown(f"**{safe_text(client)}**")
                    st.caption("Current workspace" if active else "Available workspace")
                with right:
                    if st.button(
                        "Overview" if active else "Open",
                        icon=(":material/dashboard:" if active else ":material/login:"),
                        type="primary" if active else "secondary",
                        width="stretch",
                        key=(
                            "client_dialog_open_" + re.sub(r"[^a-zA-Z0-9_-]+", "_", client.lower())
                        ),
                    ):
                        _switch_client_from_dialog(client)
                        st.toast(f"Opened {client}.", icon="✅")
                        st.rerun()
                st.divider()

    with create_tab:
        with st.form("client_dialog_create_form", clear_on_submit=True):
            new_client = st.text_input(
                "Client name",
                placeholder="Example: Acme Tunisia",
            )
            open_after_creation = st.checkbox(
                "Open after creation",
                value=True,
            )
            create_clicked = st.form_submit_button(
                "Create workspace",
                icon=":material/add_business:",
                type="primary",
                width="stretch",
            )

        if create_clicked:
            if not str(new_client or "").strip():
                st.warning("Enter a client name.")
            else:
                clean_client = _clean_client_name(new_client)
                existed = clean_client in clients
                ensure_client_exists(clean_client)

                if open_after_creation:
                    _switch_client_from_dialog(clean_client)

                st.toast(
                    (
                        f"Opened existing workspace: {clean_client}"
                        if existed
                        else f"Created workspace: {clean_client}"
                    ),
                    icon="✅",
                )
                st.rerun()


@st.dialog("Connection status", width="large")
def render_connection_status_dialog() -> None:
    """Readable scanner-provider and CISO diagnostics dialog."""
    openvas_tab, nuclei_tab, ciso_tab = module_tabs(
        ["OpenVAS / GVM", "ProjectDiscovery Nuclei", "CISO Assistant"]
    )

    with openvas_tab:
        from securescope.ui.integration_presentation import configured_value, integration_summary

        status = (
            "Unavailable"
            if not OPENVAS_ENGINE_ENABLED
            else "Configured — Not verified" if configured_value(GVM_PASSWORD) else "Needs setup"
        )
        integration_summary(
            "OpenVAS / Greenbone",
            status,
            "Test the management connection before starting an assessment.",
        )
        with st.expander("Technical details"):
            st.code(f"{LOCAL_TUNNEL_HOST}:{LOCAL_TUNNEL_PORT}")
        if not OPENVAS_ENGINE_ENABLED:
            st.info("OpenVAS is disabled on this installation.")
        elif not GVM_PASSWORD:
            st.warning("OpenVAS credentials are missing. Configure them on the scanner host.")
        else:
            st.caption("This tests the SSH tunnel and the Greenbone management connection.")
            if st.button(
                "Test OpenVAS connection",
                icon=":material/network_check:",
                type="primary",
                width="stretch",
                key="dialog_test_openvas",
            ):
                try:
                    version = test_gvm_tunnel()
                    st.success(f"Connected successfully · GVM {version}")
                except ConnectionRefusedError:
                    st.error("The OpenVAS SSH tunnel is not running.")
                except socket.timeout:
                    st.error("GVM did not answer before the timeout.")
                except (GvmError, OSError) as exc:
                    st.error(f"OpenVAS connection failed: {exc}")

    with nuclei_tab:
        if NUCLEI_ENGINE_ENABLED:
            render_nuclei_connection_panel()
        else:
            st.info("Nuclei is disabled on this installation.")

    with ciso_tab:
        st.markdown("#### CISO Assistant API")
        with st.expander("Technical details"):
            st.code(os.getenv("CISO_BASE_URL", "API URL not configured"))
        if st.button(
            "Test CISO Assistant",
            icon=":material/api:",
            type="primary",
            width="stretch",
            key="dialog_test_ciso",
        ):
            try:
                identity = test_ciso_connection()
                st.success(f"Connected successfully as {identity}")
            except CisoApiError as exc:
                st.error(f"CISO connection failed: {exc}")


def render_client_workspace_page() -> None:
    """Render the persistent client-workspace management page.

    The previous sidebar dialog remains available for fast switching, while
    this page provides a stable route for the Stitch navigation model.

    Returns:
        None.
    """

    clients = load_clients()
    active_client = get_active_client_name()
    st.title("Client Workspace")
    from securescope.ui.grc_workspace.context import current_actor
    from securescope.ui.grc_workspace.formal import (
        render_membership_manager,
        render_operator_access,
    )

    render_operator_access(active_client)
    render_membership_manager(active_client, current_actor())
    st.caption(
        "Manage isolated client workspaces, then continue into the active ISO "
        "programme and technical assurance context."
    )

    metrics = st.columns(3, gap="medium")
    with metrics[0]:
        dashboard_metric_card(
            "Workspaces",
            len(clients),
            "Isolated client environments",
            "neutral",
        )
    with metrics[1]:
        dashboard_metric_card(
            "Active assets",
            len(st.session_state.get("assets", [])),
            active_client,
            "ready",
        )
    with metrics[2]:
        dashboard_metric_card(
            "Saved scans",
            len(st.session_state.get("scan_history", [])),
            "Current workspace history",
            "neutral",
        )

    from securescope.ui.workspace_deletion import render_workspace_deletion

    delete_target = st.session_state.get("workspace_delete_target")
    if delete_target and render_workspace_deletion(str(delete_target)):
        st.session_state.pop("workspace_delete_target", None)
        st.rerun()

    search = (
        st.text_input(
            "Search workspaces",
            placeholder="Search client name...",
            key="workspace_page_search",
        )
        .strip()
        .casefold()
    )
    filtered = [client for client in clients if not search or search in client.casefold()]

    st.markdown("### Client workspaces")
    if not filtered:
        st.info("No client workspace matches this search.")
    else:
        for client in filtered:
            is_active = client == active_client
            with st.container(
                border=True, key=f"workspace_card_{re.sub(r'[^a-zA-Z0-9_-]+', '_', client)}"
            ):
                copy_column, action_column = st.columns(
                    [4, 1],
                    vertical_alignment="center",
                )
                with copy_column:
                    st.markdown(f"**{safe_text(client)}**")
                    st.caption("Active workspace" if is_active else "Available client workspace")
                with action_column:
                    button_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", client)
                    open_col, delete_col = st.columns(2, gap="small")
                    with open_col:
                        if st.button(
                            "Continue" if is_active else "Open workspace",
                            type="primary" if is_active else "secondary",
                            key=f"workspace_page_open_{button_slug}",
                        ):
                            if not is_active:
                                switch_client_workspace(client)
                                st.session_state["client_selector"] = client
                            navigate_to("ISO Command Center")
                    with delete_col:
                        if st.button(
                            "Delete",
                            type="secondary",
                            key=f"workspace_page_delete_{button_slug}",
                            help="Delete this client workspace (two confirmations required)",
                        ):
                            st.session_state["workspace_delete_target"] = client
                            st.rerun()

    with st.expander("Create client workspace", expanded=False):
        with st.form("workspace_page_create_form", clear_on_submit=True):
            new_client = st.text_input(
                "Client name",
                placeholder="Example: Acme Tunisia",
            )
            open_after_creation = st.checkbox("Open after creation", value=True)
            submitted = st.form_submit_button(
                "Create workspace",
                type="primary",
                width="stretch",
            )
        if submitted:
            if not str(new_client or "").strip():
                st.warning("Enter a client name.")
            else:
                clean_client = _clean_client_name(new_client)
                ensure_client_exists(clean_client)
                if open_after_creation:
                    switch_client_workspace(clean_client)
                    st.session_state["client_selector"] = clean_client
                    navigate_to("ISO Command Center")
                else:
                    st.success(f"Workspace created: {clean_client}")
                    st.rerun()


def render_app_sidebar(
    page_objects: Mapping[str, Any] | None = None,
    active_page_key: str | None = None,
) -> str:
    """Render the Stitch sidebar around the modern Streamlit route system.

    Args:
        page_objects: Optional registry of stable route keys to ``st.Page`` objects.
        active_page_key: Current stable route key returned by ``st.navigation``.

    Returns:
        Internal page name selected by the user.
    """

    return render_sidebar_menu(
        active_client=get_active_client_name(),
        asset_count=len(st.session_state.get("assets", [])),
        report_count=len(st.session_state.get("scan_history", [])),
        open_workspace_dialog=render_client_workspace_dialog,
        open_connection_dialog=render_connection_status_dialog,
        page_objects=page_objects,
        active_navigation_key=active_page_key,
    )


def _coerce_openvas_batch_id(
    value: Any,
    valid_batch_ids: list[int] | set[int] | tuple[int, ...],
) -> int | None:
    """Convert current or legacy Streamlit batch-selector state to an ID.

    Older SecureScope versions stored a full display label such as:
    "#12 · Multiple assets · Submitted · run 9c9bb711".
    New versions store the numeric batch ID. This helper safely accepts both.
    """
    valid_ids = {int(batch_id) for batch_id in valid_batch_ids}

    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if value in valid_ids else None

    text = str(value).strip()
    if not text:
        return None

    # Current numeric state.
    try:
        parsed = int(text)
    except ValueError:
        parsed = None

    if parsed is not None:
        return parsed if parsed in valid_ids else None

    # Legacy label state beginning with "#<batch id>".
    match = re.match(r"^\s*#?\s*(\d+)(?:\s|·|$)", text)
    if not match:
        return None

    parsed = int(match.group(1))
    return parsed if parsed in valid_ids else None


def _canonical_asset_ip(value: Any) -> str:
    """Normalize an inventory IP for safe comparison."""
    return str(value or "").strip().lower()


def _asset_record_quality(asset: dict[str, Any]) -> tuple[int, str]:
    """Prefer the richest duplicate inventory record deterministically."""
    normalized = normalize_asset(asset)
    meaningful_fields = (
        "asset_tag",
        "hostname",
        "operating_system",
        "device_type",
        "manufacturer",
        "mac_address",
        "open_ports",
        "owner",
        "location",
    )
    score = sum(
        1
        for field in meaningful_fields
        if str(normalized.get(field) or "").strip().lower()
        not in {"", "unknown", "not detected", "not inspected", "n/a", "unassigned"}
    )
    return score, str(normalized.get("asset_tag") or "")


def _deduplicate_assets_by_ip(
    assets: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Return one scan target per IP and describe duplicate inventory rows."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    without_ip: list[dict[str, Any]] = []

    for raw_asset in assets:
        asset = normalize_asset(raw_asset)
        ip = _canonical_asset_ip(asset.get("ip"))
        if not ip or ip in {"unknown", "not detected", "n/a"}:
            without_ip.append(asset)
            continue
        grouped.setdefault(ip, []).append(asset)

    unique_assets: list[dict[str, Any]] = []
    duplicates: dict[str, list[dict[str, Any]]] = {}

    for ip, candidates in grouped.items():
        ordered = sorted(
            candidates,
            key=_asset_record_quality,
            reverse=True,
        )
        unique_assets.append(ordered[0])
        if len(ordered) > 1:
            duplicates[ip] = ordered

    unique_assets.extend(without_ip)
    unique_assets.sort(
        key=lambda asset: (
            _canonical_asset_ip(asset.get("ip")),
            str(asset.get("asset_tag") or ""),
        )
    )
    return unique_assets, duplicates


def _record_timestamp(record: dict[str, Any]) -> str:
    return str(record.get("scanned_at") or record.get("created_at") or "")


def _latest_reports_by_ip(
    history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep the latest report for each IP for current-posture metrics."""
    latest: dict[str, dict[str, Any]] = {}

    for record in history:
        ip = _canonical_asset_ip(record.get("asset_ip"))
        report_key = ip or str(record.get("report_id") or "")
        if not report_key:
            continue

        current = latest.get(report_key)
        if current is None or _record_timestamp(record) > _record_timestamp(current):
            latest[report_key] = record

    return sorted(
        latest.values(),
        key=_record_timestamp,
        reverse=True,
    )


def _current_posture_findings(
    history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in _latest_reports_by_ip(history):
        for finding in record.get("findings", []) or []:
            item = dict(finding)
            item.setdefault("Host", record.get("asset_ip") or "Unknown")
            item["_report_id"] = record.get("report_id") or ""
            item["_scanned_at"] = record.get("scanned_at") or ""
            findings.append(item)
    return findings


def _priority_finding_rows(
    findings: list[dict[str, Any]],
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda item: (
            float(item.get("CVSS", 0) or 0),
            str(item.get("Severity") or ""),
        ),
        reverse=True,
    )[:limit]

    rows: list[dict[str, Any]] = []
    for finding in ordered:
        rows.append(
            {
                "Severity": severity_display(finding.get("Severity") or "Info"),
                "CVSS": float(finding.get("CVSS", 0) or 0),
                "Finding": (
                    finding.get("Name")
                    or finding.get("title")
                    or finding.get("Vulnerability")
                    or "Unnamed finding"
                ),
                "Asset": (finding.get("Host") or finding.get("asset_ip") or "Unknown"),
                "Port": finding.get("Port") or finding.get("port") or "",
                "CVE": finding.get("CVE") or finding.get("cve") or "",
            }
        )
    return rows


def _recent_scan_rows(
    history: list[dict[str, Any]],
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in sorted(
        history,
        key=_record_timestamp,
        reverse=True,
    )[:limit]:
        findings = record.get("findings", []) or []
        counts = get_severity_counts(findings)
        rows.append(
            {
                "Asset": record.get("asset_ip") or "Unknown",
                "Scanned": _record_timestamp(record)[:19].replace("T", " "),
                "Findings": len(findings),
                "Critical": counts["Critical"],
                "High": counts["High"],
                "Medium": counts["Medium"],
                "Report": str(record.get("report_id") or "")[:12],
            }
        )
    return rows


def _dashboard_wazuh_counts(
    client_name: str,
) -> tuple[int, int, str]:
    if not WAZUH_INTEGRATION_AVAILABLE:
        return 0, 0, "Unavailable"

    try:
        rows = load_latest_wazuh_status(client_name)
    except Exception:
        return 0, 0, "No snapshot"

    total = len(rows)
    monitored = sum(
        1 for row in rows if str(row.get("monitoring_status") or "") == "Monitoring verified"
    )
    return monitored, total, "Available"


def _exposure_kpi_card(
    label: str,
    value: Any,
    meta: str,
    tone: str,
) -> None:
    """Render one compact Exposure Overview KPI card.

    Args:
        label: Short metric label.
        value: Primary metric value.
        meta: Supporting context shown below the value.
        tone: Visual tone name: blue, lilac, mint or sand.

    Returns:
        None.

    Raises:
        ValueError: Never raised for displayable values.
    """

    st.html(
        f'<div class="exposure-kpi-card {safe_text(tone)}">'
        f'<div class="exposure-kpi-label">{safe_text(label)}</div>'
        f'<div class="exposure-kpi-value">{safe_text(value)}</div>'
        f'<div class="exposure-kpi-meta">{safe_text(meta)}</div>'
        "</div>"
    )


def _canonical_severity_counts(
    findings: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """Return ordered severity counts for canonical findings.

    Args:
        findings: Canonical finding rows from PostgreSQL.

    Returns:
        Severity count mapping compatible with the dashboard donut.

    Raises:
        ValueError: Never raised for mapping-like rows.
    """

    order = ("Critical", "High", "Medium", "Low", "Info")
    counter = Counter(str(row.get("severity") or "Info") for row in findings)
    return {severity: counter.get(severity, 0) for severity in order}


def _canonical_priority_rows(
    findings: Sequence[Mapping[str, Any]],
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Build a concise, decision-oriented priority-finding table.

    Args:
        findings: Active canonical finding rows.
        limit: Maximum rows to return.

    Returns:
        Display rows ordered by exploit signal, severity and CVSS.

    Raises:
        ValueError: Never raised for mapping-like rows.
    """

    severity_rank = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1,
    }

    def row_key(row: Mapping[str, Any]) -> tuple[int, int, float, float]:
        kev = 1 if row.get("kev_known_exploited") is True else 0
        severity = severity_rank.get(str(row.get("severity") or "Info"), 0)
        cvss = float(row.get("cvss") or 0.0)
        epss = float(row.get("epss_score") or 0.0)
        return (kev, severity, cvss, epss)

    ordered = sorted(findings, key=row_key, reverse=True)
    priority = [row for row in ordered if str(row.get("severity") or "") in {"Critical", "High"}]
    selected = (priority or ordered)[:limit]

    rows: list[dict[str, Any]] = []
    for row in selected:
        scanners = row.get("scanners") or []
        if isinstance(scanners, Sequence) and not isinstance(scanners, (str, bytes)):
            scanner_text = ", ".join(str(value) for value in scanners if str(value).strip())
        else:
            scanner_text = str(scanners or "")

        epss = row.get("epss_score")
        if row.get("kev_known_exploited") is True:
            exploit_signal = "CISA KEV"
        elif epss is not None and float(epss) >= 0.5:
            exploit_signal = f"EPSS {float(epss):.0%}"
        elif row.get("enrichment_status"):
            exploit_signal = str(row["enrichment_status"])
        else:
            exploit_signal = "Unavailable · refresh feed"

        last_seen = row.get("last_seen")
        if isinstance(last_seen, datetime):
            last_seen_display = last_seen.strftime("%Y-%m-%d %H:%M")
        else:
            last_seen_display = str(last_seen or "—")[:19].replace("T", " ")

        rows.append(
            {
                "Severity": severity_display(row.get("severity") or "Info"),
                "Finding": row.get("title")
                or row.get("vulnerability_identity")
                or "Unnamed finding",
                "Asset": row.get("asset_identity") or "Unknown",
                "CVSS": float(row.get("cvss") or 0.0),
                "Exploit signal": exploit_signal,
                "Source": scanner_text or "Unknown",
                "Last seen": last_seen_display,
            }
        )
    return rows


def _exposure_source_row(name: str, percentage: float | None, value: str) -> str:
    """Return safe HTML for one exposure coverage source row.

    Args:
        name: Human-readable evidence source name.
        percentage: Coverage percentage, or None when unavailable.
        value: Short value label shown at the right.

    Returns:
        Safe HTML fragment.

    Raises:
        ValueError: Never raised; percentages are clamped to 0–100.
    """

    safe_percentage = 0.0 if percentage is None else min(100.0, max(0.0, float(percentage)))
    return (
        '<div class="exposure-source-row">'
        f'<div class="exposure-source-name">{safe_text(name)}</div>'
        '<div class="exposure-source-track">'
        f'<div class="exposure-source-fill" style="width:{safe_percentage:.1f}%"></div>'
        "</div>"
        f'<div class="exposure-source-value">{safe_text(value)}</div>'
        "</div>"
    )


def _exposure_health_badge(engine: str, data: Mapping[str, Any]) -> str:
    """Return a compact scanner-provider health row.

    Args:
        engine: Scanner engine label.
        data: Provider metrics returned by scanner_fabric_metrics().

    Returns:
        Safe HTML fragment.

    Raises:
        ValueError: Never raised for mapping-like provider data.
    """

    health = data.get("health") or {}
    ready = bool(health.get("ready"))
    worker_healthy = bool(health.get("worker_healthy"))
    active = int((data.get("counts") or {}).get("active") or 0)
    if ready and worker_healthy:
        label = "Ready"
        badge_class = "ready"
    elif ready:
        label = "Worker attention"
        badge_class = "warning"
    else:
        label = "Unavailable"
        badge_class = "warning"
    if active:
        label = f"{label} · {active} active"
    return (
        '<div class="exposure-health-row">'
        f"<span>{safe_text(engine)}</span>"
        f'<span class="exposure-health-badge {badge_class}">{safe_text(label)}</span>'
        "</div>"
    )


def _render_exposure_concentration(
    analysis: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Render active finding concentration by asset.

    Args:
        analysis: Workspace finding analysis payload.

    Returns:
        None.

    Raises:
        ValueError: Never raised; missing analysis becomes an empty state.
    """

    rows = list(analysis.get("affected_assets") or [])[:6]
    if not rows:
        st.caption("No active exposure concentration is available yet.")
        return

    frame = pd.DataFrame(rows).rename(
        columns={"asset_identity": "Asset", "finding_count": "Findings"}
    )
    chart_spec = {
        "mark": {"type": "bar", "cornerRadiusEnd": 5, "color": "#5aa7e8"},
        "encoding": {
            "y": {
                "field": "Asset",
                "type": "nominal",
                "sort": "-x",
                "title": None,
                "axis": {"labelLimit": 160},
            },
            "x": {
                "field": "Findings",
                "type": "quantitative",
                "title": None,
                "axis": {"grid": False, "tickMinStep": 1},
            },
            "tooltip": [
                {"field": "Asset", "type": "nominal"},
                {"field": "Findings", "type": "quantitative"},
            ],
        },
        "height": 235,
        "view": {"stroke": None},
    }
    st.vega_lite_chart(frame, chart_spec, width="stretch")


def _render_exposure_age(
    analysis: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Render current vulnerability-age distribution.

    Args:
        analysis: Workspace finding analysis payload.

    Returns:
        None.

    Raises:
        ValueError: Never raised; missing analysis becomes an empty state.
    """

    rows = list(analysis.get("age_buckets") or [])
    if not rows:
        st.caption("No active vulnerability-age data is available yet.")
        return

    total = sum(int(row.get("finding_count") or 0) for row in rows)
    ordered_labels = ("0-30 days", "31-60 days", "61-90 days", "90+ days")
    by_label = {str(row.get("age_bucket")): int(row.get("finding_count") or 0) for row in rows}
    for label in ordered_labels:
        count = by_label.get(label, 0)
        ratio = count / total if total else 0.0
        left, right = st.columns([4, 1])
        with left:
            st.caption(label)
        with right:
            st.caption(f"**{count}**")
        st.progress(ratio)


def _render_exposure_attention(
    *,
    critical: int,
    high: int,
    kev: int | None,
    scan_gap: int,
    wazuh_gap: int | None,
    overdue_remediation: int,
) -> None:
    """Render only action-worthy exposure signals.

    Args:
        critical: Active critical finding count.
        high: Active high finding count.
        kev: Known-exploited active finding count, or None when not enriched.
        scan_gap: Number of inventory assets lacking current scan coverage.
        wazuh_gap: Number of inventory assets lacking monitoring, or None.
        overdue_remediation: Overdue remediation-plan count.

    Returns:
        None.

    Raises:
        ValueError: Never raised for numeric values.
    """

    items: list[tuple[str, str, str, str]] = []
    if critical:
        items.append(
            ("critical", "Critical vulnerabilities", "Immediate review required", str(critical))
        )
    if kev:
        items.append(
            (
                "critical",
                "Known exploited exposure",
                "CISA KEV-listed findings are active",
                str(kev),
            )
        )
    if high:
        items.append(
            (
                "high",
                "High-severity vulnerabilities",
                "Prioritize remediation after critical findings",
                str(high),
            )
        )
    if scan_gap:
        items.append(
            (
                "warning",
                "Assets without current scan coverage",
                "Exposure may be incomplete",
                str(scan_gap),
            )
        )
    if wazuh_gap:
        items.append(
            (
                "warning",
                "Assets without verified Wazuh monitoring",
                "Monitoring coverage is incomplete",
                str(wazuh_gap),
            )
        )
    if overdue_remediation:
        items.append(
            (
                "high",
                "Overdue remediation plans",
                "Past their committed due date",
                str(overdue_remediation),
            )
        )

    if not items:
        items.append(
            (
                "good",
                "No immediate exposure action",
                "No critical coverage or remediation condition is currently flagged",
                "Current",
            )
        )

    fragments = []
    for tone, title, detail, value in items[:5]:
        fragments.append(
            '<div class="exposure-attention-item">'
            f'<span class="exposure-attention-dot {safe_text(tone)}"></span>'
            '<div class="exposure-attention-copy">'
            f"<strong>{safe_text(title)}</strong><span>{safe_text(detail)}</span>"
            "</div>"
            f'<div class="exposure-attention-value">{safe_text(value)}</div>'
            "</div>"
        )
    st.html("".join(fragments))


def _exposure_recommended_action(
    *,
    asset_count: int,
    scan_coverage: float,
    priority_count: int,
    overdue_remediation: int,
    active_jobs: int,
) -> tuple[str, str, str | None, str | None]:
    """Choose one primary next action for Exposure Overview.

    Args:
        asset_count: Number of unique inventory assets.
        scan_coverage: Current vulnerability scan coverage percentage.
        priority_count: Active Critical + High canonical finding count.
        overdue_remediation: Overdue remediation-plan count.
        active_jobs: Number of active scanner jobs.

    Returns:
        Title, explanation, button label and sidebar navigation key.

    Raises:
        ValueError: Never raised for numeric values.
    """

    if asset_count == 0:
        return (
            "Discover the environment",
            (
                "No usable asset inventory is available. Start with authorized "
                "asset discovery before measuring exposure."
            ),
            "Discover assets",
            "1 · Asset Discovery",
        )
    if scan_coverage < 100:
        return (
            "Complete vulnerability coverage",
            (
                f"{100 - scan_coverage:.0f}"
                "% of the current asset inventory has no latest "
                "vulnerability report."
            ),
            "Open Scan Center",
            "3 · Scan Center",
        )
    if priority_count:
        return (
            "Review priority vulnerabilities",
            (
                f"{priority_count}"
                " Critical or High finding(s) require analyst review and "
                "remediation decisions."
            ),
            "Review findings",
            "4 · Reports & Findings",
        )
    if overdue_remediation:
        return (
            "Resolve overdue remediation",
            f"{overdue_remediation} remediation plan(s) are past their due date.",
            "Open Remediation",
            "Remediation",
        )
    if active_jobs:
        return (
            "Scans are running",
            f"{active_jobs} scan job(s) are currently active. Review progress in Scan Center.",
            "Open Scan Center",
            "3 · Scan Center",
        )
    return (
        "Exposure review is current",
        (
            "No immediate Critical/High, scan-coverage, or overdue-remediation"
            " condition is driving the next action."
        ),
        None,
        None,
    )


def _overview_affected_asset_rows(
    analysis: Mapping[str, Sequence[Mapping[str, Any]]],
    canonical_findings: Sequence[Mapping[str, Any]],
    assets: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build the compact Most Affected Assets decision table.

    Args:
        analysis: Canonical workspace finding analysis.
        canonical_findings: Active canonical finding rows.
        assets: Workspace-filtered normalized inventory.

    Returns:
        Up to six decision-oriented asset rows with Asset Tag as identity.

    Raises:
        No exceptions are raised.
    """

    asset_lookup: dict[str, Mapping[str, Any]] = {}
    for asset in assets:
        tag = str(asset.get("asset_tag") or "").strip()
        ip = _canonical_asset_ip(asset.get("ip"))
        if tag:
            asset_lookup[tag.casefold()] = asset
        if ip and ip not in {"unknown", "not detected", "n/a"}:
            asset_lookup[ip.casefold()] = asset

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    status_rank = {
        "Ready for verification": 0,
        "In progress": 1,
        "Planned": 2,
        "Triaged": 3,
        "Mitigated": 4,
        "Reopened": 5,
        "New": 6,
    }
    rows: list[dict[str, Any]] = []
    for concentration in list(analysis.get("affected_assets") or [])[:6]:
        identity = str(concentration.get("asset_identity") or "Unknown").strip()
        asset = asset_lookup.get(identity.casefold(), {})
        tag = str(asset.get("asset_tag") or identity or "Unknown")
        related = [
            finding
            for finding in canonical_findings
            if str(finding.get("asset_identity") or "").strip().casefold() == identity.casefold()
        ]
        severities = [str(item.get("severity") or "Info") for item in related]
        highest = (
            min(severities, key=lambda value: severity_rank.get(value, 99)) if severities else "—"
        )
        statuses = [str(item.get("status") or "New") for item in related]
        remediation = (
            min(statuses, key=lambda value: status_rank.get(value, 99)) if statuses else "—"
        )
        if remediation == "Ready for verification":
            remediation = "Ready to verify"
        rows.append(
            {
                "Asset Tag": tag,
                "Criticality": str(asset.get("criticality") or "Not set"),
                "Finding Count": int(concentration.get("finding_count") or 0),
                "Highest Severity": highest,
                "Remediation": remediation,
            }
        )
    return rows


@st.fragment
def render_overview_page() -> None:
    """Render the Stitch-aligned Exposure Overview decision dashboard.

    The page answers three questions: what is exposed now, which in-scope assets
    lack technical coverage, and what deserves action next. Historical detail
    and scanner administration remain available but secondary.

    Legacy hierarchy labels retained for design/test traceability:
    Recommended next step; Exposure posture; Coverage & sources; Needs action;
    Exposure concentration; Vulnerability age.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository/provider errors degrade to safe
            UI states instead of blocking the dashboard.
    """

    client_name = get_active_client_name()
    history = list(st.session_state.scan_history)
    assets_raw = [normalize_asset(asset) for asset in st.session_state.assets]
    assets, duplicate_inventory = _deduplicate_assets_by_ip(assets_raw)

    unique_asset_ips = {
        _canonical_asset_ip(asset.get("ip"))
        for asset in assets
        if _canonical_asset_ip(asset.get("ip")) not in {"", "unknown", "not detected", "n/a"}
    }
    current_reports = _latest_reports_by_ip(history)
    scanned_ips = {
        _canonical_asset_ip(record.get("asset_ip"))
        for record in current_reports
        if _canonical_asset_ip(record.get("asset_ip"))
    }
    scanned_asset_count = len(scanned_ips & unique_asset_ips)
    scan_coverage = (
        round(scanned_asset_count / len(unique_asset_ips) * 100, 1) if unique_asset_ips else 0.0
    )

    repository_error = ""
    repository_available = False
    canonical_findings: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    analysis: dict[str, Sequence[Mapping[str, Any]]] = {}
    try:
        if history:
            synchronize_findings_from_history(client_name, history)
        canonical_findings = list_findings(
            client_name,
            statuses=sorted(ACTIVE_FINDING_STATUSES),
            limit=10_000,
        )
        metrics = workspace_dashboard_metrics(client_name)
        analysis = workspace_finding_analysis(client_name, days=30)
        repository_available = True
    except ExposureRepositoryError as exc:
        repository_error = str(exc)

    if repository_available:
        severity_counts = _canonical_severity_counts(canonical_findings)
        active_findings = int(metrics.get("unique_active_findings") or 0)
    else:
        fallback_findings = _current_posture_findings(history)
        severity_counts = get_severity_counts(fallback_findings)
        active_findings = len(fallback_findings)

    priority_count = severity_counts["Critical"] + severity_counts["High"]
    kev_value = metrics.get("kev")
    kev_count = int(kev_value) if kev_value is not None else None
    high_epss_value = metrics.get("high_epss")
    mean_age = metrics.get("mean_age_days")
    overdue_remediation = int(metrics.get("overdue_remediation") or 0)

    wazuh_monitored, wazuh_total, wazuh_state = _dashboard_wazuh_counts(client_name)
    wazuh_coverage = (
        round(min(wazuh_monitored, len(unique_asset_ips)) / len(unique_asset_ips) * 100, 1)
        if unique_asset_ips and wazuh_total
        else None
    )
    wazuh_gap = (
        max(0, len(unique_asset_ips) - min(wazuh_monitored, len(unique_asset_ips)))
        if unique_asset_ips and wazuh_total
        else None
    )
    scan_gap = max(0, len(unique_asset_ips) - scanned_asset_count)

    fabric_metrics = scanner_fabric_metrics(client_name)
    active_job_count = int(fabric_metrics.get("totals", {}).get("active") or 0)
    next_title, next_text, next_button, next_navigation = _exposure_recommended_action(
        asset_count=len(unique_asset_ips),
        scan_coverage=scan_coverage,
        priority_count=priority_count,
        overdue_remediation=overdue_remediation,
        active_jobs=active_job_count,
    )

    header_column, action_column = st.columns(
        [4.8, 1.2],
        gap="medium",
        vertical_alignment="bottom",
    )
    with header_column:
        st.title("Exposure Overview")
        st.caption(
            "Current vulnerability exposure and technical coverage across the active ISMS scope."
        )
    with action_column:
        if next_button and next_navigation:
            if st.button(
                next_button,
                type="primary",
                width="stretch",
                key="exposure_primary_action",
                help=next_text,
            ):
                _select_sidebar_navigation(next_navigation)
        else:
            if st.button(
                "Review Findings",
                type="primary",
                width="stretch",
                key="exposure_review_findings",
            ):
                _select_sidebar_navigation("4 · Reports & Findings")

    render_stitch_metrics(
        (
            StitchMetric(
                "Active Vulnerabilities",
                str(active_findings),
                (
                    "Unique active canonical findings"
                    if repository_available
                    else "Current saved scanner posture"
                ),
                "neutral",
            ),
            StitchMetric(
                "Priority Findings",
                str(priority_count),
                f"{severity_counts['Critical']} Critical · {severity_counts['High']} High",
                "danger" if priority_count else "neutral",
            ),
            StitchMetric(
                "Scan Coverage",
                f"{scan_coverage:.0f}%",
                (
                    f"{scanned_asset_count}"
                    "/"
                    f"{len(unique_asset_ips)}"
                    " inventoried assets with a current "
                    "report"
                ),
                "primary",
            ),
            StitchMetric(
                "Monitoring Coverage",
                f"{wazuh_coverage:.0f}%" if wazuh_coverage is not None else "—",
                (
                    (
                        f"{min(wazuh_monitored, len(unique_asset_ips))}"
                        "/"
                        f"{len(unique_asset_ips)}"
                        " assets monitored"
                    )
                    if unique_asset_ips and wazuh_coverage is not None
                    else "No current Wazuh coverage snapshot"
                ),
                "info",
            ),
        )
    )

    if duplicate_inventory:
        st.warning(
            f"Asset data quality: {len(duplicate_inventory)} duplicate IP group(s) exist. "
            "Review them in Asset Management; exposure metrics use one target per IP."
        )
    if repository_error:
        st.caption(
            "Canonical exposure analytics are temporarily unavailable; saved "
            "scan history is used where possible. "
            f"Repository detail: {repository_error}"
        )

    exposure_column, trigger_column = st.columns([2, 1], gap="large")
    with exposure_column:
        with st.container(border=True, key="exposure_severity_panel"):
            section_heading(
                "Exposure by Severity",
                (
                    "Active canonical vulnerability findings, deduplicated across "
                    "scanner observations."
                ),
            )
            if active_findings:
                render_severity_bars(severity_counts)
            else:
                st.success("No active vulnerability findings are currently recorded.")

        section_heading(
            "Most Affected Assets",
            (
                "Asset Tag remains the primary identity; hostname is intentionally"
                " excluded from this decision table."
            ),
        )
        affected_rows = _overview_affected_asset_rows(
            analysis,
            canonical_findings,
            assets,
        )
        if affected_rows:
            st.dataframe(
                pd.DataFrame(affected_rows),
                width="stretch",
                hide_index=True,
                height=min(330, 82 + len(affected_rows) * 42),
                column_config={
                    "Asset Tag": st.column_config.TextColumn("Asset Tag", width="medium"),
                    "Criticality": st.column_config.TextColumn("Criticality", width="small"),
                    "Finding Count": st.column_config.NumberColumn("Finding Count", width="small"),
                    "Highest Severity": st.column_config.TextColumn(
                        "Highest Severity", width="small"
                    ),
                    "Remediation": st.column_config.TextColumn("Remediation", width="medium"),
                },
            )
        else:
            st.info("No active asset exposure concentration is available yet.")

    with trigger_column:
        trigger_items: list[dict[str, str]] = []
        if kev_count:
            trigger_items.append(
                {
                    "title": "CISA KEV catalog match",
                    ("detail"): (
                        f"{kev_count}"
                        " active finding(s) match known exploited "
                        "vulnerabilities."
                    ),
                    "status": "Urgent",
                    "tone": "danger",
                }
            )
        if high_epss_value:
            trigger_items.append(
                {
                    "title": "High EPSS probability",
                    ("detail"): (
                        f"{int(high_epss_value)}"
                        " finding(s) have a high likelihood of "
                        "exploitation."
                    ),
                    "status": "High probability",
                    "tone": "warning",
                }
            )
        age_rows = list(analysis.get("age_buckets") or [])
        aged_90 = next(
            (
                int(row.get("finding_count") or 0)
                for row in age_rows
                if str(row.get("age_bucket")) == "90+ days"
            ),
            0,
        )
        if aged_90:
            trigger_items.append(
                {
                    "title": "90+ day aging",
                    ("detail"): (
                        f"{aged_90}" " active finding(s) have remained open for 90 days or " "more."
                    ),
                    "status": "Review SLA",
                    "tone": "warning",
                }
            )
        if overdue_remediation:
            trigger_items.append(
                {
                    "title": "Overdue remediation",
                    "detail": f"{overdue_remediation} remediation plan(s) are past due.",
                    "status": "Overdue",
                    "tone": "danger",
                }
            )
        if not trigger_items:
            trigger_items.append(
                {
                    "title": "No immediate risk trigger",
                    "detail": (
                        "No KEV, high-EPSS, 90+ day, or overdue-remediation signal is "
                        "currently available."
                    ),
                    "status": "Current",
                    "tone": "info",
                }
            )
        render_attention_panel(trigger_items, title="Actionable Risk Triggers")
        # Coverage Gaps: in-scope assets missing scan or monitoring evidence.
        render_coverage_gaps(unscanned=scan_gap, unmonitored=wazuh_gap)
        if st.button(
            "Review Coverage",
            width="stretch",
            key="exposure_review_coverage",
        ):
            if scan_gap:
                _select_sidebar_navigation("3 · Scan Center")
            else:
                _select_sidebar_navigation("2 · Asset Management")
            st.rerun()
        st.caption(f"Recommended next step: {next_title}. {next_text}")

    section_heading(
        "Priority Findings",
        (
            "Technical findings most likely to change remediation priority. "
            "Full lifecycle actions remain in Vulnerabilities."
        ),
    )
    if repository_available:
        priority_rows = _canonical_priority_rows(canonical_findings)
    else:
        fallback_rows = _priority_finding_rows(_current_posture_findings(history), limit=8)
        priority_rows = [
            {
                "Severity": row.get("Severity", "Info"),
                "Finding": row.get("Finding", "Unnamed finding"),
                "Asset": row.get("Asset", "Unknown"),
                "CVSS": row.get("CVSS", 0.0),
                "Exploit signal": "—",
                "Source": "Saved report",
                "Last seen": "—",
            }
            for row in fallback_rows
        ]
    if priority_rows:
        st.dataframe(
            pd.DataFrame(priority_rows),
            width="stretch",
            hide_index=True,
            height=min(420, 82 + len(priority_rows) * 38),
            column_config={
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Finding": st.column_config.TextColumn("Finding", width="large"),
                "Asset": st.column_config.TextColumn("Asset", width="medium"),
                "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
                "Exploit signal": st.column_config.TextColumn("Exploit signal", width="small"),
                "Source": st.column_config.TextColumn("Source", width="medium"),
                "Last seen": st.column_config.TextColumn("Last seen", width="medium"),
            },
        )
    else:
        st.success("No active Critical or High finding is currently driving remediation.")

    with st.expander("Exposure analysis and recent scan activity", expanded=False):
        age_column, history_column = st.columns([1, 1.6], gap="large")
        with age_column:
            st.markdown("#### Vulnerability age")
            _render_exposure_age(analysis)
            if mean_age is not None:
                st.caption(f"Mean active finding age: {float(mean_age):.0f} days")
        with history_column:
            st.markdown("#### Recent scan activity")
            st.caption(
                (
                    "Historical scan records remain available for auditability but do "
                    "not define current canonical exposure."
                )
            )
            recent_rows = _recent_scan_rows(history, limit=8)
            if recent_rows:
                recent_frame = pd.DataFrame(recent_rows)
                st.dataframe(
                    recent_frame,
                    width="stretch",
                    hide_index=True,
                    height=min(360, 82 + len(recent_frame) * 36),
                )
            else:
                st.info("No completed scan activity has been saved yet.")


def _asset_table_rows(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert persistent asset objects into concise table rows."""
    rows: list[dict[str, Any]] = []
    for asset in assets:
        item = normalize_asset(asset)
        rows.append(
            {
                "Asset tag": item["asset_tag"],
                "IP address": item["ip"],
                "Manufacturer": item["manufacturer"],
                "Device type": item["device_type"],
                "Operating system": item["operating_system"],
                "Owner": item["owner"],
                "Classification": item["information_classification"],
                "CIA impact": cia_summary(item),
                "VLAN": (f"{item['vlan_id']} — {item['vlan_name']}".strip(" —") or "Not assigned"),
                "Lifecycle": lifecycle_display(item["status"]),
                "Criticality": criticality_display(item["criticality"]),
                "Last seen": str(item["last_seen"]).replace("T", " ")[:19] or "Never",
                "Last scan": str(item["last_scan"]).replace("T", " ")[:19] or "Never",
            }
        )
    return rows


def _select_asset_from_list(
    assets: list[dict[str, Any]],
    key: str,
) -> dict[str, Any] | None:
    """Render an asset selector and keep the selected IP consistent globally."""
    if not assets:
        return None
    labels = {
        f"{asset['asset_tag']} • {asset['ip']} • {asset['hostname']}": asset for asset in assets
    }
    selected_label = st.selectbox("Select asset", list(labels), key=key)
    selected = labels[selected_label]
    st.session_state.selected_ip = selected["ip"]
    return selected


@st.fragment
def render_asset_management_page() -> None:
    """Render a persistent asset register inspired by professional asset tools."""
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    badge = f"{len(assets)} managed asset(s)" if assets else "Inventory empty"
    page_hero(
        "ASSET MANAGEMENT",
        "Asset Management",
        (
            "Manage lifecycle, ownership, location, VLAN context and security "
            "activity. Discovery and inspection enrich this persistent inventory."
        ),
        badge,
        "ready" if assets else "warning",
    )

    total = len(assets)
    pending = sum(1 for item in assets if item["status"] in {"Discovered", "Pending review"})
    managed = sum(1 for item in assets if item["status"] == "Managed")
    critical = sum(1 for item in assets if item["criticality"] in {"High", "Critical"})
    metric_columns = st.columns(4)
    with metric_columns[0]:
        dashboard_metric_card("Total assets", total, "Persistent local register", "neutral")
    with metric_columns[1]:
        dashboard_metric_card(
            "Pending review", pending, "Newly discovered or not validated", "medium"
        )
    with metric_columns[2]:
        dashboard_metric_card("Managed", managed, "Approved inventory assets", "neutral")
    with metric_columns[3]:
        dashboard_metric_card(
            "High criticality", critical, "Analyst-set business criticality", "risk"
        )

    if st.button(
        "Discover assets with Nmap", icon=":material/travel_explore:", key="asset_register_discover"
    ):
        navigate_to("1 · Asset Discovery")

    section_heading(
        "Committed inventory",
        (
            "Maintain ownership and lifecycle here. Nmap discovery adds "
            "technical observations to these records."
        ),
    )
    if not assets:
        st.markdown(
            """
            <div class="empty-state">
              <div class="empty-icon">▦</div>
              <h3>No assets registered yet</h3>
              <p>Open Asset Discovery to run the fast Nmap <code>-sn</code> pass,
              then validate and enrich selected devices here.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    filters = st.columns([1.8, 1, 1])
    with filters[0]:
        query = st.text_input("Search", placeholder="Tag, IP, owner or manufacturer")
    with filters[1]:
        lifecycle_filter = st.multiselect(
            "Lifecycle", sorted({asset["status"] for asset in assets}), default=[]
        )
    with filters[2]:
        criticality_filter = st.multiselect(
            "Criticality", ["Low", "Medium", "High", "Critical"], default=[]
        )

    query_lower = query.strip().lower()
    filtered_assets: list[dict[str, Any]] = []
    for asset in assets:
        searchable = " ".join(
            str(asset.get(field, ""))
            for field in (
                "asset_tag",
                "hostname",
                "ip",
                "owner",
                "manufacturer",
                "location",
                "vlan_id",
                "vlan_name",
            )
        ).lower()
        if query_lower and query_lower not in searchable:
            continue
        if lifecycle_filter and asset["status"] not in lifecycle_filter:
            continue
        if criticality_filter and asset["criticality"] not in criticality_filter:
            continue
        filtered_assets.append(asset)

    st.markdown(
        (
            '\n        <div class="asset-toolbar">\n          '
            "<strong>"
            f"{len(filtered_assets)}"
            " asset(s) displayed</strong>\n          <span>Asset tags are "
            "permanent. IP addresses can change; lifecycle and ownership "
            "remain with the asset record.</span>\n        </div>\n        "
        ),
        unsafe_allow_html=True,
    )
    render_asset_legends()
    monitoring = {}
    asset_table_frame = pd.DataFrame(_asset_table_rows(filtered_assets))
    if WAZUH_INTEGRATION_AVAILABLE and not asset_table_frame.empty:
        try:
            monitoring = {
                r["asset_ip"]: r for r in load_latest_wazuh_status(get_active_client_name())
            }
            asset_table_frame["Wazuh monitoring"] = [
                monitoring.get(a["ip"], {}).get("monitoring_status", "Monitoring not verified")
                for a in filtered_assets
            ]
        except WazuhDatabaseError:
            asset_table_frame["Wazuh monitoring"] = "Source unavailable"
    readable_table(
        asset_table_frame,
        key=f"assets::{get_active_client_name()}",
        height=420,
        column_config={
            "Asset tag": st.column_config.TextColumn("Asset tag", width="small"),
            "IP address": st.column_config.TextColumn("IP address", width="small"),
            "Owner": st.column_config.TextColumn("🔒 Owner", width="medium"),
            "VLAN": st.column_config.TextColumn("🔒 VLAN", width="medium"),
            "Lifecycle": st.column_config.TextColumn("Lifecycle", width="medium"),
            "Criticality": st.column_config.TextColumn("🔒 Criticality", width="small"),
            "Last seen": st.column_config.DatetimeColumn("Last seen", width="medium"),
            "Last scan": st.column_config.DatetimeColumn("Last scan", width="medium"),
        },
    )
    st.download_button(
        "Export asset register CSV",
        data=asset_table_frame.to_csv(index=False).encode("utf-8"),
        file_name="securescope_asset_register.csv",
        mime="text/csv",
    )

    section_heading(
        "Bulk lifecycle update", "Apply an asset status to explicitly selected records."
    )
    tag_options = [asset["asset_tag"] for asset in filtered_assets]
    bulk_left, bulk_middle, bulk_right = st.columns([1.8, 1.1, 0.7])
    with bulk_left:
        bulk_tags = st.multiselect("Assets", tag_options, key="bulk_asset_tags")
    with bulk_middle:
        bulk_status = st.selectbox(
            "New lifecycle",
            [
                "Discovered",
                "Pending review",
                "Managed",
                "Inspection queued",
                "Scan queued",
                "Retired",
            ],
            key="bulk_asset_status",
        )
    bulk_is_disruptive = bool(bulk_tags) and bulk_status == "Retired"
    bulk_confirmed = True
    if bulk_is_disruptive:
        bulk_confirmed = st.checkbox(
            f"Confirm retiring {len(bulk_tags)} selected asset(s)",
            value=False,
            key="confirm_bulk_retire",
            help=(
                "This changes the lifecycle presentation state to Retired. Asset "
                "data is preserved."
            ),
        )
    with bulk_right:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button(
            "Apply",
            width="stretch",
            disabled=bulk_is_disruptive and not bulk_confirmed,
        ):
            count = apply_bulk_status(bulk_tags, bulk_status)
            if count:
                st.success(f"Updated {count} asset(s).")
                st.rerun()
            else:
                st.warning("Select at least one asset first.")

    section_heading("Asset record", "Review technical evidence and maintain business context.")
    selected = _select_asset_from_list(filtered_assets or assets, "asset_management_selector")
    if not selected:
        return

    st.markdown(
        f"""
        <div class="asset-spotlight">
          <div class="page-eyebrow" style="color:#4380a5;">{safe_text(selected[(
              'asset_tag'
          )])} • {safe_text(selected[(
              'status'
          )]).upper()}</div>
          <h3>{safe_text(selected[(
              'hostname'
          )] if selected[(
              'hostname'
          )] != (
              'Unknown'
          ) else selected[(
              'ip'
          )])}</h3>
          <div>
            <span class="asset-pill">{safe_text(selected['ip'])}</span>
            <span class="asset-pill">{safe_text(selected['criticality'])} criticality</span>
            <span class="asset-pill">{safe_text(selected['confirmation'])}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if monitoring:
        from securescope.ui.wazuh_monitoring_ui import render_monitoring_detail

        current_monitoring = monitoring.get(selected["ip"])
        if current_monitoring:
            render_monitoring_detail([current_monitoring], f"asset::{get_active_client_name()}")

    details = [
        ("MAC address", selected["mac_address"]),
        ("Manufacturer", selected["manufacturer"]),
        ("Device type", selected["device_type"]),
        ("Operating system", selected["operating_system"]),
        ("Information classification", selected["information_classification"]),
        ("CIA impact", cia_summary(selected)),
        ("Open ports", selected["open_ports"]),
        ("Last inspected", str(selected["last_inspected"]).replace("T", " ")[:19] or "Never"),
    ]
    st.markdown(
        '<div class="asset-detail-grid">'
        + "".join(
            f"<div><label>{safe_text(label)}</label><strong>{safe_text(value)}</strong></div>"
            for label, value in details
        )
        + "</div>",
        unsafe_allow_html=True,
    )

    from securescope.ui.assurance_queue import render_asset_assurance

    render_asset_assurance(get_active_client_name(), selected["ip"])
    action_one, action_two, action_three = st.columns(3)
    with action_one:
        inspect_clicked = st.button("Inspect selected asset", type="primary", width="stretch")
    with action_two:
        sync_clicked = st.button("Sync to CISO Assistant", width="stretch")
    with action_three:
        st.button(
            "Use as scan target",
            width="stretch",
            on_click=navigate_to_scan_center,
            args=(selected["ip"],),
        )

    if inspect_clicked:
        try:
            with st.spinner("Running selected-host inspection with -Pn and all TCP ports…"):
                inspected = inspect_asset(selected["ip"])
            merge_asset(st.session_state.assets, inspected)
            st.success(inspected["inspection_note"])
            st.rerun()
        except (nmap.PortScannerError, OSError, RuntimeError) as exc:
            st.error(f"Nmap inspection failed: {exc}")
    if sync_clicked:
        try:
            with st.spinner("Synchronizing selected asset to CISO Assistant…"):
                ciso_asset, created = sync_asset_to_ciso(selected)
            merge_asset(st.session_state.assets, selected)
            st.success(
                f"CISO asset {'created' if created else 'updated'}"
                f": {ciso_asset.get('name', selected['ip'])}"
            )
        except CisoApiError as exc:
            st.error(f"CISO synchronization failed: {exc}")
    st.markdown("<br>", unsafe_allow_html=True)
    with st.form(f"asset_editor_{selected['asset_tag']}"):
        st.markdown("#### Edit asset management fields")
        row_one = st.columns(3)
        with row_one[0]:
            status = st.selectbox(
                "Lifecycle",
                [
                    "Discovered",
                    "Pending review",
                    "Managed",
                    "Inspection queued",
                    "Scan queued",
                    "Retired",
                ],
                index=(
                    max(
                        0,
                        [
                            "Discovered",
                            "Pending review",
                            "Managed",
                            "Inspection queued",
                            "Scan queued",
                            "Retired",
                        ].index(selected["status"]),
                    )
                    if selected["status"]
                    in [
                        "Discovered",
                        "Pending review",
                        "Managed",
                        "Inspection queued",
                        "Scan queued",
                        "Retired",
                    ]
                    else 0
                ),
            )
        with row_one[1]:
            criticality = st.selectbox(
                "Business criticality",
                ["Low", "Medium", "High", "Critical"],
                index=(
                    max(0, ["Low", "Medium", "High", "Critical"].index(selected["criticality"]))
                    if selected["criticality"] in ["Low", "Medium", "High", "Critical"]
                    else 1
                ),
            )
        with row_one[2]:
            owner = st.text_input("Owner", value=selected["owner"])

        st.markdown("#### Information classification")
        st.caption(
            "Classification and CIA impact are related but independent. "
            "Choose the handling label explicitly, then score the impact "
            "of confidentiality, integrity and availability loss."
        )
        information_classification = st.selectbox(
            "Information handling classification",
            INFORMATION_CLASSIFICATION_OPTIONS,
            index=INFORMATION_CLASSIFICATION_OPTIONS.index(selected["information_classification"]),
            help=(
                "Public, Internal Use, Confidential or Restricted. "
                "This value is no longer calculated automatically from CIA."
            ),
        )

        st.markdown("#### CIA impact scoring")
        cia_cols = st.columns(3)
        with cia_cols[0]:
            confidentiality_score = st.selectbox(
                "Confidentiality",
                CLASSIFICATION_OPTIONS,
                index=CLASSIFICATION_OPTIONS.index(selected["confidentiality_score"]),
                format_func=format_cia_option,
                help=" | ".join(CIA_GUIDANCE["confidentiality"].values()),
            )
        with cia_cols[1]:
            integrity_score = st.selectbox(
                "Integrity",
                CLASSIFICATION_OPTIONS,
                index=CLASSIFICATION_OPTIONS.index(selected["integrity_score"]),
                format_func=format_cia_option,
                help=" | ".join(CIA_GUIDANCE["integrity"].values()),
            )
        with cia_cols[2]:
            availability_score = st.selectbox(
                "Availability",
                CLASSIFICATION_OPTIONS,
                index=CLASSIFICATION_OPTIONS.index(selected["availability_score"]),
                format_func=format_cia_option,
                help=" | ".join(CIA_GUIDANCE["availability"].values()),
            )
        st.info(
            "Impact profile: "
            f"C{confidentiality_score} / "
            f"I{integrity_score} / "
            f"A{availability_score} · "
            f"Handling classification: {information_classification}"
        )

        row_two = st.columns(3)
        with row_two[0]:
            location = st.text_input("Location", value=selected["location"])
        with row_two[1]:
            vlan_id = st.text_input("VLAN ID", value=selected["vlan_id"])
        with row_two[2]:
            vlan_name = st.text_input("VLAN name", value=selected["vlan_name"])
        notes = st.text_area("Analyst notes", value=selected["notes"], height=110)
        saved = st.form_submit_button("Save asset record", type="primary")
        if saved:
            update_asset_management_fields(
                selected["asset_tag"],
                status=status,
                criticality=criticality,
                information_classification=information_classification,
                confidentiality_score=confidentiality_score,
                integrity_score=integrity_score,
                availability_score=availability_score,
                owner=owner,
                location=location,
                vlan_id=vlan_id,
                vlan_name=vlan_name,
                notes=notes,
            )
            st.success("Asset record saved.")
            st.rerun()


BANNER_KEYS = ("product", "version", "extrainfo")


def _format_port_summary(port: dict[str, Any]) -> str:
    """Render one open port as 'port/proto service (product version extrainfo)'."""
    head = f"{port.get('port')}/{port.get('protocol')} {port.get('service') or ''}".strip()
    banner = " ".join(str(port.get(key) or "").strip() for key in BANNER_KEYS).strip()
    return f"{head} ({banner})" if banner else head


def _nmap_parsed_asset_to_inventory_asset(
    parsed_asset: dict[str, Any], profile_name: str
) -> dict[str, Any]:
    """Convert parsed Nmap XML data into the SecureScope asset inventory format."""
    now = _utc_now()
    open_ports_list = parsed_asset.get("open_ports") or []
    open_ports_text = (
        "; ".join(_format_port_summary(port) for port in open_ports_list) or "Not inspected"
    )

    products = []
    for port in open_ports_list:
        product = " ".join(
            str(port.get(key) or "").strip()
            for key in ("product", "version", "extrainfo")
            if str(port.get(key) or "").strip()
        )
        if product and product not in products:
            products.append(product)

    try:
        from securescope.scanners.nmap.nmap_profile_builder import infer_asset_classification

        inferred = infer_asset_classification(parsed_asset)
    except Exception:
        inferred = {}

    return normalize_asset(
        {
            "ip": parsed_asset.get("ip") or "Unknown",
            "hostname": parsed_asset.get("hostname") or "Unknown",
            "mac_address": parsed_asset.get("mac_address") or "Unknown",
            "manufacturer": parsed_asset.get("mac_vendor") or "Unknown",
            "device_type": inferred.get("device_type") or "Not inspected",
            "operating_system": parsed_asset.get("os_guess") or "Not inspected",
            "os_confidence": (
                str((parsed_asset.get("os_matches") or [{}])[0].get("accuracy", "Unknown"))
                if parsed_asset.get("os_matches")
                else "Not inspected"
            ),
            "products": "; ".join(products) or "Not inspected",
            "open_ports": open_ports_text,
            "status": "Discovered",
            "criticality": inferred.get("criticality") or "Medium",
            "source": f"Nmap profile: {profile_name}",
            "confirmation": "Confirmed by Nmap",
            "first_seen": now,
            "last_seen": now,
            "last_inspected": now if open_ports_list or parsed_asset.get("os_guess") else "",
            "inspection_note": (
                "Discovered or enriched by Asset Discovery. Existing useful inventory "
                "values are protected; later scans only fill empty/unknown fields."
            ),
        }
    )


def _asset_discovery_automatic_flags(profile: dict[str, Any]) -> list[str]:
    """Return prepared flags for automatic mode."""
    return list(profile.get("options", []))


@st.fragment
def render_asset_discovery_page() -> None:
    """Render Asset Discovery with automatic prepared scans and manual custom scans.

    Flow:
    Asset Discovery -> Asset Management -> Dual-engine Scan Center.
    """
    page_hero(
        "ASSET DISCOVERY",
        "Asset Discovery",
        (
            "Choose Automatic mode for prepared commands, or Manual mode to customize "
            "all Nmap options. Repeated scans update only empty/unknown asset fields."
        ),
        "Nmap → Asset Management → Scan Center",
        "neutral",
    )

    try:
        from securescope.scanners.nmap.nmap_profile_builder import (
            PROFILE_PRESETS,
            build_nmap_command,
            command_to_display,
            grouped_options,
            parse_nmap_xml,
            run_nmap,
            validate_target_text,
        )
    except Exception as exc:
        st.error(f"Nmap custom builder files are missing or invalid: {exc}")
        st.info(
            "The Nmap profile module is unavailable. Reinstall the SecureScope "
            "package and verify the src/securescope/scanners/nmap directory."
        )
        return

    scans_dir = Path("scans")
    scans_dir.mkdir(exist_ok=True)

    import shutil

    from securescope.ui.integration_presentation import integration_summary

    integration_summary(
        "Nmap",
        "Configured — Not verified" if shutil.which("nmap") else "Unavailable",
        (
            "Executable detected. Target access is checked when an authorized scan runs."
            if shutil.which("nmap")
            else "Install Nmap on the scanner host before starting discovery."
        ),
    )

    section_heading(
        "Nmap target",
        "The scan target is configured here. Results are saved to the asset inventory.",
    )

    top_left, top_right = st.columns([1.5, 1])
    with top_left:
        target = st.text_input(
            "Authorized target / CIDR / hostname",
            value=DEFAULT_NETWORK,
            help="Examples: 192.168.100.0/24, 192.168.100.4, server.local",
            key="asset_discovery_target",
        )
    with top_right:
        scan_mode = st.radio(
            "Scan mode",
            ["Automatic prepared scan", "Manual custom scan"],
            horizontal=True,
            key="asset_discovery_mode",
        )

    authorized = st.checkbox(
        "I am authorized to scan this target",
        value=False,
        key="asset_discovery_authorized",
    )

    profile_names = list(PROFILE_PRESETS.keys())
    default_profile = "Discovery only - fast inventory"
    default_index = profile_names.index(default_profile) if default_profile in profile_names else 0

    selected_flags: list[str] = []
    top_ports = 1000
    ports = ""
    scripts = ""
    max_retries = 2
    host_timeout = "5m"
    custom_args = ""

    if scan_mode == "Automatic prepared scan":
        section_heading(
            "Automatic prepared commands",
            "Choose a ready profile. You can preview the exact Nmap command before running.",
        )

        profile_name = st.selectbox(
            "Prepared Nmap command",
            profile_names,
            index=default_index,
            key="asset_discovery_auto_profile",
        )
        profile = PROFILE_PRESETS[profile_name]
        selected_flags = _asset_discovery_automatic_flags(profile)
        top_ports = int(profile.get("top_ports", 1000))
        ports = str(profile.get("ports", ""))
        scripts = str(profile.get("scripts", ""))
        max_retries = int(profile.get("max_retries", 2))
        host_timeout = str(profile.get("host_timeout", "5m"))

        st.info(profile.get("description", "Prepared Nmap scan."))
        st.markdown(
            """
            **Prepared workflow examples**
            - Discovery only: `-sn -n -PR`
            - Fast service inventory: `-sV --version-light --top-ports 1000`
            - Balanced asset inspection: `-sV -O --top-ports 2000`
            - NTP check: `-sU -p 123 --script ntp-info`
            """
        )

    else:
        section_heading(
            "Manual custom scan",
            "Choose the exact Nmap flags and values you need.",
        )

        profile_name = "Manual custom scan"
        include_advanced = st.toggle(
            "Show advanced / noisy Nmap options",
            value=False,
            key="asset_discovery_manual_advanced",
        )

        st.info("Important: `-O` is OS detection. `-sO` is IP protocol scan, not OS detection.")

        for category, options in grouped_options(include_advanced=include_advanced).items():
            with st.expander(
                category, expanded=category in {"Host discovery", "Scan technique", "Detection"}
            ):
                labels = {f"{opt.flag} — {opt.label}": opt.flag for opt in options}
                defaults = []
                chosen = st.multiselect(
                    f"{category} options",
                    list(labels.keys()),
                    default=defaults,
                    key=f"asset_discovery_manual_opts_{category}",
                )
                selected_flags.extend(labels[label] for label in chosen)
                for opt in options:
                    st.caption(f"`{opt.flag}` — {opt.description}")

        if not selected_flags:
            selected_flags = ["-n"]

        st.subheader("Manual values")
        col1, col2, col3 = st.columns(3)
        with col1:
            top_ports = st.number_input(
                "Value for --top-ports",
                min_value=1,
                max_value=65535,
                value=1000,
                step=100,
                key="asset_discovery_manual_top_ports",
            )
        with col2:
            ports = st.text_input(
                "Value for -p",
                value="",
                placeholder="22,80,443 or 1-1000 or -",
                key="asset_discovery_manual_ports",
            )
        with col3:
            max_retries = st.number_input(
                "Value for --max-retries",
                min_value=0,
                max_value=10,
                value=2,
                key="asset_discovery_manual_max_retries",
            )

        host_timeout = st.text_input(
            "Value for --host-timeout",
            value="5m",
            key="asset_discovery_manual_host_timeout",
        )
        scripts = st.text_input(
            "Value for --script",
            value="",
            placeholder="default,safe or ntp-info",
            key="asset_discovery_manual_scripts",
        )
        custom_args = st.text_area(
            "Extra custom Nmap arguments",
            value="",
            placeholder="Example: --reason --defeat-rst-ratelimit",
            key="asset_discovery_manual_custom_args",
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_profile = re.sub(r"[^a-zA-Z0-9_-]+", "_", profile_name.lower()).strip("_")
    output_xml = str(scans_dir / f"asset_discovery_{safe_profile}_{timestamp}.xml")
    valid_target, validation_message = validate_target_text(target)

    command_args = build_nmap_command(
        target=target,
        selected_flags=selected_flags,
        output_xml=output_xml,
        top_ports=int(top_ports),
        ports=ports,
        scripts=scripts,
        max_retries=int(max_retries),
        host_timeout=host_timeout,
        custom_args=custom_args,
        nmap_binary="nmap",
    )

    section_heading(
        "Command preview",
        "The app runs this exact command and parses the XML output.",
    )

    if not valid_target:
        st.error(validation_message)
    if "-sn" in command_args and any(flag in command_args for flag in ["-sV", "-O", "-A", "-sC"]):
        st.warning(
            "You selected `-sn` with detection options. `-sn` disables port scanning, "
            "so service/OS results may not appear."
        )
    if "-sO" in command_args:
        st.warning("`-sO` is IP protocol scan. For OS detection, use `-O`.")

    with st.expander("Technical details · Nmap command"):
        st.code(command_to_display(command_args), language="text")
        st.caption(f"XML output: `{display_tool_output(output_xml)}`")

    protect_note = (
        "Inventory update rule: if an asset already exists, this scan "
        "fills only empty/Unknown/Not inspected fields. "
        "Existing useful values and manual context are preserved."
    )
    st.info(protect_note)

    disruptive_nmap = any(flag in command_args for flag in ["-A", "-p-", "-T5", "--script"])
    disruptive_confirmed = True
    if disruptive_nmap:
        disruptive_confirmed = st.checkbox(
            "I reviewed the generated command and confirm this intensive scan",
            value=False,
            key="confirm_intensive_nmap",
            help="Required for aggressive, all-port, T5 or NSE-script scans.",
        )

    run_clicked = st.button(
        "Run Nmap and update Asset Management",
        type="primary",
        width="stretch",
        disabled=(
            not authorized or not valid_target or (disruptive_nmap and not disruptive_confirmed)
        ),
    )

    if not authorized:
        st.warning("Check the authorization box before running Nmap.")

    if run_clicked:
        status = st.status(
            "Running the selected Nmap workflow…",
            expanded=True,
        )
        status.write("1/4 Resolving the authorized target and generated command")
        status.write("2/4 Running Nmap")
        result = run_nmap(command_args, timeout_seconds=1800)
        status.write("3/4 Parsing XML output")
        status.write("4/4 Updating the protected asset register")

        if result.get("ok"):
            status.update(
                label=f"Nmap completed in {result.get('duration_seconds')} seconds",
                state="complete",
                expanded=False,
            )
        else:
            status.update(
                label=f"Nmap failed or timed out — return code {result.get('returncode')}",
                state="error",
                expanded=True,
            )

        with st.expander("Live / diagnostic Nmap output", expanded=False):
            st.code(display_tool_output(result.get("stdout") or ""), language="text")
        with st.expander("Nmap error output", expanded=False):
            st.code(display_tool_output(result.get("stderr") or ""), language="text")

        parsed_assets = parse_nmap_xml(output_xml)
        inventory_assets = [
            _nmap_parsed_asset_to_inventory_asset(asset, profile_name)
            for asset in parsed_assets
            if asset.get("ip")
        ]

        if inventory_assets:
            before_count = len(st.session_state.assets)
            upsert_assets(inventory_assets)
            after_count = len(st.session_state.assets)
            st.session_state.last_discovery_ips = [asset["ip"] for asset in inventory_assets]
            st.session_state.selected_ip = inventory_assets[0]["ip"]

            st.success(
                f"{len(inventory_assets)} host(s) processed. "
                f"Inventory now has {after_count} asset(s). "
                f"New assets added: {max(after_count - before_count, 0)}."
            )

            st.dataframe(
                _asset_table_rows([normalize_asset(asset) for asset in st.session_state.assets]),
                width="stretch",
                hide_index=True,
                height=330,
            )
        else:
            st.info("No hosts were parsed from the Nmap XML output.")

    section_heading(
        "Current Asset Management table",
        (
            "Discovery updates are saved to the committed inventory. Use Asset"
            " Management to assign owners and review lifecycle."
        ),
    )
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    if assets:
        st.dataframe(_asset_table_rows(assets), width="stretch", hide_index=True, height=330)
        st.info("Next: go to Scan Center, choose an engine, then choose single or batch scanning.")
    else:
        st.markdown(
            """
            <div class="empty-state"><div class="empty-icon">⌁</div>
            <h3>No local asset inventory yet</h3>
            <p>Run an authorized Nmap scan to create the first Asset Management table.</p></div>
            """,
            unsafe_allow_html=True,
        )


def _render_latest_openvas_findings() -> None:
    """Render latest OpenVAS findings already stored in session state."""
    if not st.session_state.last_findings:
        section_heading(
            "Latest scan results",
            "Findings will appear here after the first completed scan.",
        )
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-icon">◒</div>
                <h3>Waiting for a scan result</h3>
                <p>The latest OpenVAS findings will show a concise priority view here.
                The complete analytics workspace is available in Findings Dashboard.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    findings = st.session_state.last_findings
    severity_counts = get_severity_counts(findings)
    section_heading(
        "Latest scan results",
        "Priority findings from the latest OpenVAS report.",
    )

    scan_metrics = st.columns(4)
    with scan_metrics[0]:
        dashboard_metric_card("Total findings", len(findings), "Latest report", "neutral")
    with scan_metrics[1]:
        dashboard_metric_card(
            "Critical", severity_counts["Critical"], "Immediate action", "critical"
        )
    with scan_metrics[2]:
        dashboard_metric_card("High", severity_counts["High"], "Priority remediation", "high")
    with scan_metrics[3]:
        dashboard_metric_card("Medium", severity_counts["Medium"], "Planned remediation", "medium")

    result_columns = ["Severity", "CVSS", "Finding", "Host", "Port", "CVE", "QOD", "ISO Controls"]
    st.dataframe(
        [{key: item.get(key) for key in result_columns} for item in findings],
        width="stretch",
        hide_index=True,
        height=270,
    )

    with st.expander("Review detailed evidence and remediation"):
        for finding in sorted(
            findings, key=lambda item: float(item.get("CVSS", 0) or 0), reverse=True
        ):
            st.markdown(
                f"**{finding.get('Severity', 'Info')} • CVSS {finding.get('CVSS', '0.0')}** "
                f"— {finding.get('Finding', 'Unnamed finding')}"
            )
            detail_left, detail_right = st.columns(2)
            with detail_left:
                st.caption(f"Host: {finding.get('Host', '—')} • Port: {finding.get('Port', '—')}")
                st.caption(f"CVE: {finding.get('CVE', 'N/A')} • QOD: {finding.get('QOD', 'N/A')}")
            with detail_right:
                st.caption(f"NVT OID: {finding.get('NVT OID', 'N/A')}")
            st.info(finding.get("Solution", "No remediation provided by the scanner."))
            st.divider()

    if st.session_state.last_openvas_report_id:
        st.caption(f"OpenVAS report ID: {st.session_state.last_openvas_report_id}")


def _new_openvas_status_row(
    asset: dict[str, Any],
    queue_position: int,
) -> dict[str, Any]:
    """Create a complete status row for one OpenVAS asset."""
    normalized = normalize_asset(asset)
    return {
        "Queue": queue_position,
        "Asset tag": normalized.get("asset_tag") or "Unassigned",
        "IP": normalized.get("ip") or "Not detected",
        "Hostname": normalized.get("hostname") or "Unknown",  # Internal only.
        "Status": "Ready",
        "Submission stage": "Waiting",
        "Progress": "0%",
        "Task ID": "Pending",
        "Report ID": "Pending",
        "Findings": 0,
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Result": "Waiting for submission",
        "PDF report": "Pending",
        "Error": "",
    }


def _render_openvas_status_table(
    placeholder: Any,
    rows: list[dict[str, Any]],
) -> None:
    """Render all rows safely, including rows saved by older releases.

    reindex prevents KeyError when an older row does not yet contain a newly
    introduced display column such as Submission stage.
    """
    display_columns = [
        "Queue",
        "Asset tag",
        "IP",
        "Status",
        "Submission stage",
        "Progress",
        "Task ID",
        "Report ID",
        "Findings",
        "Critical",
        "High",
        "Medium",
        "Result",
        "PDF report",
        "Error",
    ]

    frame = pd.DataFrame(rows)
    if frame.empty:
        placeholder.dataframe(
            pd.DataFrame(columns=display_columns),
            width="stretch",
            hide_index=True,
        )
        return

    display_frame = frame.reindex(columns=display_columns, fill_value="").copy()

    text_columns = [
        "Asset tag",
        "IP",
        "Status",
        "Submission stage",
        "Progress",
        "Task ID",
        "Report ID",
        "Result",
        "PDF report",
        "Error",
    ]
    for column in text_columns:
        display_frame[column] = display_frame[column].map(
            lambda value: "—" if value is None or str(value).strip() == "" else str(value)
        )

    placeholder.dataframe(
        display_frame,
        width="stretch",
        hide_index=True,
        height=min(620, 100 + len(rows) * 36),
        column_config={
            "Queue": st.column_config.NumberColumn("#", width="small"),
            "Asset tag": st.column_config.TextColumn("Asset", width="small"),
            "IP": st.column_config.TextColumn("IP address", width="small"),
            "Status": st.column_config.TextColumn("Status", width="medium"),
            "Submission stage": st.column_config.TextColumn(
                "Current stage",
                width="medium",
            ),
            "Progress": st.column_config.TextColumn("Progress", width="small"),
            "Task ID": st.column_config.TextColumn("Task ID", width="medium"),
            "Report ID": st.column_config.TextColumn("Report ID", width="medium"),
            "Findings": st.column_config.NumberColumn("Findings", width="small"),
            "Critical": st.column_config.NumberColumn("Critical", width="small"),
            "High": st.column_config.NumberColumn("High", width="small"),
            "Medium": st.column_config.NumberColumn("Medium", width="small"),
            "Result": st.column_config.TextColumn("Result", width="large"),
            "PDF report": st.column_config.TextColumn("PDF", width="medium"),
            "Error": st.column_config.TextColumn("Error", width="large"),
        },
    )


def _extract_openvas_result_nodes(report: Any) -> list[Any]:
    """Extract result nodes from the different GMP report response layouts."""
    candidate_paths = [
        "report/report/results/result",
        "report/results/result",
        ".//report/results/result",
        ".//results/result",
    ]

    extracted: list[Any] = []
    seen: set[int] = set()

    for xpath in candidate_paths:
        try:
            nodes = report.xpath(xpath)
        except Exception:
            continue

        for node in nodes:
            identity = id(node)
            if identity in seen:
                continue
            seen.add(identity)
            extracted.append(node)

        if extracted:
            break

    return extracted


def _fetch_openvas_report_results(
    gmp: GMP,
    report_id: str,
) -> tuple[list[Any], str]:
    """Fetch a completed OpenVAS report with broad fallback filters.

    A report can legitimately contain zero findings. The function distinguishes
    that case from a response-layout parsing problem and records a clear note.
    """
    filters = [
        f"rows={max(REPORT_MAX_ROWS, 1000)} min_qod=0",
        f"rows={max(REPORT_MAX_ROWS, 1000)}",
        "",
    ]

    best_results: list[Any] = []
    successful_fetches = 0
    last_error = ""

    for attempt, filter_string in enumerate(filters, start=1):
        try:
            report = gmp.get_report(
                report_id,
                filter_string=filter_string,
                details=True,
                ignore_pagination=False,
            )
            successful_fetches += 1
            results = _extract_openvas_result_nodes(report)

            if len(results) > len(best_results):
                best_results = results

            if best_results:
                return (
                    best_results,
                    f"Report fetched successfully: {len(best_results)} raw result(s)",
                )

        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < len(filters):
            time.sleep(2)

    if successful_fetches:
        return (
            [],
            "Report fetched successfully; OpenVAS returned 0 vulnerability results",
        )

    raise GvmError(f"OpenVAS report {report_id} could not be fetched. {last_error}")


def _openvas_batch_resources(gmp: GMP) -> tuple[str, str, str]:
    """Resolve the selected OpenVAS resources once per authenticated session."""
    configs = gmp.get_scan_configs()
    config_id = find_first_id(
        configs.xpath(f"config[name='{SCAN_CONFIG_NAME}']/@id"),
        f"Scan config '{SCAN_CONFIG_NAME}'",
    )

    port_lists = gmp.get_port_lists()
    port_list_id = find_first_id(
        port_lists.xpath(f"port_list[name='{PORT_LIST_NAME}']/@id"),
        f"Port list '{PORT_LIST_NAME}'",
    )

    scanners = gmp.get_scanners()
    scanner_id = find_first_id(
        scanners.xpath(f"scanner[name='{SCANNER_NAME}']/@id"),
        f"Scanner '{SCANNER_NAME}'",
    )
    return config_id, port_list_id, scanner_id


def _extract_gmp_task_value(
    response: Any,
    relative_path: str,
    default: str = "",
) -> str:
    """Read a task value from supported GMP get_task response layouts."""
    paths = [
        f"task/{relative_path}/text()",
        f".//task/{relative_path}/text()",
        f".//{relative_path}/text()",
    ]
    for path in paths:
        try:
            values = response.xpath(path)
        except Exception:
            continue
        value = get_first_text(values, default="")
        if value:
            return value
    return default


def _scanner_runtime_diagnostics(
    gmp: GMP,
    scanner_id: str,
) -> dict[str, Any]:
    """Verify the selected scanner and return readable runtime details."""
    result = {
        "verified": False,
        "name": SCANNER_NAME,
        "status": "Unknown",
        "host": "",
        "port": "",
        "message": "",
    }

    try:
        scanner = gmp.get_scanner(scanner_id)
        result["name"] = get_first_text(
            scanner.xpath("scanner/name/text()") or scanner.xpath(".//scanner/name/text()"),
            default=SCANNER_NAME,
        )
        result["status"] = get_first_text(
            scanner.xpath("scanner/status/text()") or scanner.xpath(".//scanner/status/text()"),
            default="Unknown",
        )
        result["host"] = get_first_text(
            scanner.xpath("scanner/host/text()") or scanner.xpath(".//scanner/host/text()"),
            default="",
        )
        result["port"] = get_first_text(
            scanner.xpath("scanner/port/text()") or scanner.xpath(".//scanner/port/text()"),
            default="",
        )

        verify_response = gmp.verify_scanner(scanner_id)
        verify_status = str(verify_response.get("status") or "")
        verify_text = str(verify_response.get("status_text") or "")
        result["verified"] = verify_status.startswith("2") or not verify_status
        result["message"] = verify_text or "Scanner verification completed."
    except Exception as exc:
        result["message"] = f"{type(exc).__name__}: {exc}"

    return result


def openvas_submission_preflight() -> dict[str, Any]:
    """Test the shared prerequisites required before submitting any asset.

    A batch-wide authentication, tunnel or resource error should be shown once,
    instead of displaying the same generic 'Submission failed' status for every IP.
    """
    transform = EtreeCheckCommandTransform()
    result: dict[str, Any] = {
        "ok": False,
        "version": "",
        "config_id": "",
        "port_list_id": "",
        "scanner_id": "",
        "error_stage": "",
        "error": "",
    }

    stage = "Connect to the local SSH tunnel"
    try:
        with GMP(connection=make_gmp_connection(), transform=transform) as gmp:
            stage = "Read the GVM version"
            version_response = gmp.get_version()
            result["version"] = get_first_text(
                version_response.xpath("version/text()"),
                default="Unknown",
            )

            stage = "Authenticate to GVM"
            gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)

            stage = "Resolve scan configuration, port list and scanner"
            config_id, port_list_id, scanner_id = _openvas_batch_resources(gmp)

            stage = "Verify OpenVAS scanner readiness"
            scanner_diagnostic = _scanner_runtime_diagnostics(
                gmp,
                scanner_id,
            )
            if not scanner_diagnostic.get("verified"):
                raise GvmError(
                    "OpenVAS scanner verification failed: "
                    + str(scanner_diagnostic.get("message") or "Unknown error")
                )

            result.update(
                {
                    "ok": True,
                    "config_id": config_id,
                    "port_list_id": port_list_id,
                    "scanner_id": scanner_id,
                    "scanner": scanner_diagnostic,
                }
            )
            return result

    except Exception as exc:
        result["error_stage"] = stage
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result


def _mark_all_submission_blocked(
    status_rows: list[dict[str, Any]],
    table_placeholder: Any,
    stage: str,
    error: str,
) -> None:
    for row in status_rows:
        row["Status"] = "Submission blocked"
        row["Submission stage"] = stage
        row["Error"] = error
    _render_openvas_status_table(table_placeholder, status_rows)


def submit_all_openvas_tasks(
    assets: list[dict[str, Any]],
    status_rows: list[dict[str, Any]],
    table_placeholder: Any,
) -> list[dict[str, Any]]:
    """Create and start every selected task using a persistent GMP session.

    The previous implementation opened and closed a separate GMP connection for
    every asset and reloaded the same OpenVAS resources each time. This version:

    1. Runs one shared preflight.
    2. Authenticates once per connection.
    3. Resolves the config, port list and scanner once.
    4. Creates and starts all tasks through the same session.
    5. Reconnects only when the management connection is actually reset.
    6. Displays the exact failing stage and full error for each affected asset.
    """
    if not assets:
        return []

    preflight = openvas_submission_preflight()
    if not preflight.get("ok"):
        _mark_all_submission_blocked(
            status_rows,
            table_placeholder,
            str(preflight.get("error_stage") or "OpenVAS preflight"),
            str(preflight.get("error") or "Unknown OpenVAS preflight error"),
        )
        return []

    transform = EtreeCheckCommandTransform()
    batch_stamp = f"{int(time.time())}-{len(assets)}"

    jobs: list[dict[str, Any]] = []
    next_index = 0
    attempts_by_index: dict[int, int] = {index: 0 for index in range(len(assets))}

    # Resource IDs are stable for the batch. They were validated by preflight.
    config_id = str(preflight["config_id"])
    port_list_id = str(preflight["port_list_id"])
    scanner_id = str(preflight["scanner_id"])

    while next_index < len(assets):
        try:
            with GMP(connection=make_gmp_connection(), transform=transform) as gmp:
                gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)

                while next_index < len(assets):
                    index = next_index
                    asset = normalize_asset(assets[index])
                    row = status_rows[index]
                    target_ip = str(asset.get("ip") or "").strip()
                    attempt = attempts_by_index[index]

                    row["Status"] = "Submitting to OpenVAS"
                    row["Submission stage"] = "Validate target"
                    row["Error"] = ""
                    _render_openvas_status_table(table_placeholder, status_rows)

                    if not target_ip or target_ip.lower() == "unknown":
                        row["Status"] = "Submission failed"
                        row["Submission stage"] = "Validate target"
                        row["Error"] = "The asset has no valid IP address."
                        next_index += 1
                        _render_openvas_status_table(table_placeholder, status_rows)
                        continue

                    target_id = ""
                    task_id = ""

                    try:
                        row["Submission stage"] = "Create OpenVAS target"
                        _render_openvas_status_table(table_placeholder, status_rows)

                        target_response = gmp.create_target(
                            name=(
                                "securescope-batch-"
                                f"{batch_stamp}"
                                "-"
                                f"{index + 1}"
                                "-"
                                f"{target_ip}"
                                "-a"
                                f"{attempt}"
                            ),
                            hosts=[target_ip],
                            port_list_id=port_list_id,
                        )
                        target_id = str(target_response.get("id") or "")
                        if not target_id:
                            raise GvmError("OpenVAS did not return a target ID.")

                        row["Submission stage"] = "Create OpenVAS task"
                        _render_openvas_status_table(table_placeholder, status_rows)

                        task_response = gmp.create_task(
                            name=(
                                "securescope-scan-"
                                f"{batch_stamp}"
                                "-"
                                f"{index + 1}"
                                "-"
                                f"{target_ip}"
                                "-a"
                                f"{attempt}"
                            ),
                            config_id=config_id,
                            target_id=target_id,
                            scanner_id=scanner_id,
                        )
                        task_id = str(task_response.get("id") or "")
                        if not task_id:
                            raise GvmError("OpenVAS did not return a task ID.")

                        row["Submission stage"] = "Start OpenVAS task"
                        _render_openvas_status_table(table_placeholder, status_rows)

                        start_response = gmp.start_task(task_id)

                        # start_task normally returns the first report ID. Keeping it
                        # here improves diagnostics but monitoring still reads the
                        # authoritative report ID from the task later.
                        initial_report_id = get_first_text(
                            start_response.xpath("report_id/text()"),
                            default="",
                        )

                        row["Status"] = "Submitted / scheduled"
                        row["Submission stage"] = "Task started"
                        row["Result"] = "OpenVAS accepted the task"
                        row["Task ID"] = task_id
                        if initial_report_id:
                            row["Report ID"] = initial_report_id

                        jobs.append(
                            {
                                "asset": asset,
                                "row_index": index,
                                "target_id": target_id,
                                "task_id": task_id,
                                "report_id": initial_report_id,
                                "final_status": "Requested",
                                "results": [],
                                "error": "",
                                "scanner_id": scanner_id,
                                "submitted_at": time.monotonic(),
                                "requested_since": time.monotonic(),
                                "last_scanner_diagnostic_at": 0.0,
                                "scanner_diagnostic": preflight.get("scanner") or {},
                            }
                        )

                        next_index += 1
                        _render_openvas_status_table(table_placeholder, status_rows)

                    except Exception as exc:
                        full_error = f"{type(exc).__name__}: {exc}"

                        if (
                            _is_retryable_gvm_connection_error(exc)
                            and attempt < OPENVAS_BATCH_SUBMIT_RETRIES
                        ):
                            attempts_by_index[index] += 1
                            row["Status"] = (
                                f"Submission reconnect "
                                f"{attempts_by_index[index]}/{OPENVAS_BATCH_SUBMIT_RETRIES}"
                            )
                            row["Error"] = full_error
                            _render_openvas_status_table(table_placeholder, status_rows)

                            # Reconnect the outer session and retry the current asset.
                            raise

                        row["Status"] = "Submission failed"
                        row["Error"] = full_error
                        next_index += 1
                        _render_openvas_status_table(table_placeholder, status_rows)

        except Exception as exc:
            current_index = min(next_index, len(assets) - 1)
            current_attempt = attempts_by_index.get(current_index, 0)

            if (
                _is_retryable_gvm_connection_error(exc)
                and current_attempt <= OPENVAS_BATCH_SUBMIT_RETRIES
            ):
                time.sleep(OPENVAS_RECONNECT_DELAY_SECONDS)
                continue

            # A shared connection/authentication problem blocks the remaining batch.
            shared_error = f"{type(exc).__name__}: {exc}"
            for index in range(next_index, len(assets)):
                row = status_rows[index]
                row["Status"] = "Submission blocked"
                row["Submission stage"] = "GMP connection/authentication"
                row["Error"] = shared_error
            _render_openvas_status_table(table_placeholder, status_rows)
            break

    return jobs


def monitor_parallel_openvas_tasks(
    jobs: list[dict[str, Any]],
    status_rows: list[dict[str, Any]],
    table_placeholder: Any,
    overall_placeholder: Any,
) -> list[dict[str, Any]]:
    """Monitor every submitted task and explain long Requested/Queued waits."""
    pending = {job["task_id"]: job for job in jobs if job.get("task_id")}
    retry_count = 0
    transform = EtreeCheckCommandTransform()

    while pending:
        try:
            with GMP(
                connection=make_gmp_connection(),
                transform=transform,
            ) as gmp:
                gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
                retry_count = 0

                while pending:
                    done_task_ids: list[str] = []

                    for task_id, job in list(pending.items()):
                        row = status_rows[job["row_index"]]

                        try:
                            task = gmp.get_task(task_id)
                            task_status = _extract_gmp_task_value(
                                task,
                                "status",
                                default="Unknown",
                            )
                            progress = _extract_gmp_task_value(
                                task,
                                "progress",
                                default="0",
                            )

                            row["Status"] = task_status
                            row["Progress"] = f"{progress}%"
                            job["final_status"] = task_status

                            if task_status in {"Requested", "Queued"}:
                                requested_since = float(
                                    job.get("requested_since") or time.monotonic()
                                )
                                job["requested_since"] = requested_since
                                waiting_seconds = int(time.monotonic() - requested_since)
                                row["Submission stage"] = "Waiting for scanner"
                                row["Result"] = f"{task_status} for {waiting_seconds}s"

                                if waiting_seconds >= OPENVAS_REQUESTED_WARNING_SECONDS:
                                    last_check = float(
                                        job.get(
                                            "last_scanner_diagnostic_at",
                                            0.0,
                                        )
                                    )
                                    if (
                                        time.monotonic() - last_check
                                        >= OPENVAS_SCANNER_DIAGNOSTIC_INTERVAL_SECONDS
                                    ):
                                        diagnostic = _scanner_runtime_diagnostics(
                                            gmp,
                                            str(job.get("scanner_id") or ""),
                                        )
                                        job["scanner_diagnostic"] = diagnostic
                                        job["last_scanner_diagnostic_at"] = time.monotonic()

                                    diagnostic = job.get("scanner_diagnostic") or {}
                                    verified = diagnostic.get("verified")
                                    scanner_status = str(diagnostic.get("status") or "Unknown")
                                    scanner_message = str(diagnostic.get("message") or "")

                                    if verified:
                                        row["Status"] = f"{task_status} · scanner wait"
                                        row["Result"] = (
                                            f"Waiting {waiting_seconds}s for "
                                            f"OpenVAS capacity or VT loading. "
                                            f"Scanner status: {scanner_status}."
                                        )
                                        row["Error"] = ""
                                    else:
                                        row["Status"] = f"{task_status} · scanner problem"
                                        row["Result"] = (
                                            f"Scanner verification failed after "
                                            f"{waiting_seconds}s."
                                        )
                                        row["Error"] = scanner_message

                            else:
                                job["requested_since"] = time.monotonic()
                                row["Submission stage"] = "Monitoring OpenVAS task"
                                row["Result"] = (
                                    "OpenVAS task is running"
                                    if task_status not in {"Done", "Stopped", "Interrupted"}
                                    else row.get("Result", "")
                                )

                            if task_status in {
                                "Done",
                                "Stopped",
                                "Interrupted",
                            }:
                                report_id = get_first_text(
                                    task.xpath("task/last_report/report/@id")
                                    or task.xpath(".//task/last_report/report/@id")
                                    or task.xpath(".//last_report/report/@id"),
                                    default="",
                                )
                                job["report_id"] = report_id
                                job["final_status"] = task_status
                                row["Report ID"] = report_id or "Not returned"

                                if report_id:
                                    row["Status"] = "Fetching report"
                                    row["Submission stage"] = "Retrieving vulnerability results"
                                    _render_openvas_status_table(
                                        table_placeholder,
                                        status_rows,
                                    )
                                    (
                                        results,
                                        fetch_note,
                                    ) = _fetch_openvas_report_results(
                                        gmp,
                                        report_id,
                                    )
                                    job["results"] = results
                                    job["report_fetch_note"] = fetch_note
                                    row["Submission stage"] = "Report fetched"
                                    row["Result"] = fetch_note
                                else:
                                    row["Submission stage"] = "No report ID"
                                    row["Result"] = "Task ended without a report ID"
                                    row["Error"] = "OpenVAS did not return a report ID."

                                done_task_ids.append(task_id)

                        except Exception as exc:
                            if _is_retryable_gvm_connection_error(exc):
                                raise

                            row["Status"] = "Monitoring failed"
                            row["Submission stage"] = "Read task status"
                            row["Error"] = f"{type(exc).__name__}: {exc}"
                            job["error"] = row["Error"]
                            job["final_status"] = "Failed"
                            done_task_ids.append(task_id)

                    for task_id in done_task_ids:
                        pending.pop(task_id, None)

                    completed = len(jobs) - len(pending)
                    requested_count = sum(
                        1
                        for job in pending.values()
                        if str(job.get("final_status") or "") in {"Requested", "Queued"}
                    )
                    overall_placeholder.info(
                        f"OpenVAS batch: {completed}/{len(jobs)} finished · "
                        f"{len(pending)} active · "
                        f"{requested_count} waiting for scanner."
                    )
                    _render_openvas_status_table(
                        table_placeholder,
                        status_rows,
                    )

                    if pending:
                        time.sleep(OPENVAS_BATCH_POLL_SECONDS)

        except Exception as exc:
            if _is_retryable_gvm_connection_error(exc) and retry_count < OPENVAS_CONNECTION_RETRIES:
                retry_count += 1
                overall_placeholder.warning(
                    "The GMP management connection was reset. "
                    f"Reconnecting in {OPENVAS_RECONNECT_DELAY_SECONDS}s "
                    f"({retry_count}/{OPENVAS_CONNECTION_RETRIES}). "
                    "OpenVAS tasks continue on the scanner."
                )
                time.sleep(OPENVAS_RECONNECT_DELAY_SECONDS)
                continue

            for job in pending.values():
                row = status_rows[job["row_index"]]
                row["Status"] = "Monitoring failed"
                row["Submission stage"] = "GMP connection"
                row["Error"] = f"{type(exc).__name__}: {exc}"
                job["error"] = row["Error"]
                job["final_status"] = "Failed"

            pending.clear()
            _render_openvas_status_table(
                table_placeholder,
                status_rows,
            )

    return jobs


def finalize_openvas_job(
    job: dict[str, Any],
    status_rows: list[dict[str, Any]],
    sync_to_ciso: bool,
) -> dict[str, Any]:
    """Parse, persist, synchronize and generate one PDF report."""
    row = status_rows[job["row_index"]]
    asset = normalize_asset(job["asset"])
    final_status = job.get("final_status") or "Unknown"
    report_id = job.get("report_id") or ""

    if job.get("error"):
        return row

    findings = parse_openvas_results(job.get("results") or [], report_id)
    record = make_scan_record(
        report_id=report_id,
        asset=asset,
        findings=findings,
        final_status=final_status,
    )

    if final_status == "Done":
        mark_asset_scan(asset["ip"])

    ciso_status = "Not requested"
    if sync_to_ciso and final_status == "Done":
        try:
            record["ciso_sync"] = sync_scan_record_to_ciso(record)
            record["ciso_asset_id"] = record["ciso_sync"].get("ciso_asset_id")
            ciso_status = "Synchronized"
        except Exception as exc:
            ciso_status = f"Failed: {exc}"

    try:
        pdf_path = save_asset_report_pdf(
            record,
            client_name=get_active_client_name(),
            output_root=APP_DIR / "reports",
        )
        record["pdf_report_path"] = str(pdf_path)
        record["pdf_report_name"] = pdf_path.name
        row["PDF report"] = pdf_path.name
    except Exception as exc:
        record["pdf_report_error"] = str(exc)
        row["PDF report"] = "Generation failed"
        row["Error"] = f"{row.get('Error') or ''} PDF: {exc}".strip()

    upsert_scan_history(record)
    st.session_state.last_openvas_report_id = report_id
    st.session_state.last_findings = findings

    severity = get_severity_counts(findings)
    row.update(
        {
            "Status": "Completed" if final_status == "Done" else final_status,
            "Submission stage": "Finalized",
            "Progress": "100%" if final_status == "Done" else row.get("Progress", ""),
            "Report ID": report_id or "Not returned",
            "Findings": len(findings),
            "Critical": severity["Critical"],
            "High": severity["High"],
            "Medium": severity["Medium"],
            "Result": (
                f"{len(findings)} normalized vulnerability finding(s)"
                if findings
                else job.get("report_fetch_note") or "Completed with 0 vulnerability findings"
            ),
            "CISO status": ciso_status,
        }
    )
    return row


def _available_pdf_records() -> list[dict[str, Any]]:
    records = []
    for record in st.session_state.scan_history:
        path = Path(str(record.get("pdf_report_path") or ""))
        if path.exists() and path.is_file():
            records.append(record)
    return records


def _parse_live_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _live_age_seconds(value: Any) -> int | None:
    parsed = _parse_live_timestamp(value)
    if parsed is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))


def _live_elapsed_label(job: dict[str, Any]) -> str:
    status = str(job.get("status") or "Unknown")
    if status == "Queued":
        position = job.get("queue_position")
        return f"Batch queue #{position}" if position else "Queued"

    started = job.get("started_at") or job.get("submitted_at") or job.get("created_at")
    seconds = _live_age_seconds(started)
    if seconds is None:
        return "Unknown"
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _provider_sync_state(
    job: dict[str, Any],
    *,
    provider_online: bool = True,
) -> str:
    """Return a provider-only synchronization state for one exact task.

    Local PostgreSQL updates must never masquerade as a Greenbone poll. Only
    last_provider_sync_at proves that gvmd was read for this task.
    """
    task_id = str(job.get("task_id") or "").strip()
    if not task_id:
        return "Local only"
    if not provider_online:
        return "Offline"

    provider_sync = job.get("last_provider_sync_at")
    error_text = str(job.get("error") or "").lower()
    stage_text = str(job.get("stage") or "").lower()
    provider_text = str(job.get("provider_status") or "").lower()
    if (
        "server error 500" in error_text
        or "internal error" in error_text
        or "provider error" in provider_text
        or "gvmd internal error" in stage_text
    ):
        return "Provider error"
    if provider_sync is None or str(provider_sync).strip() == "":
        age = _live_age_seconds(job.get("submitted_at") or job.get("created_at"))
        if age is not None and age <= OPENVAS_LIVE_STALE_SECONDS:
            return "Pending poll"
        return "Never synced"

    age = _live_age_seconds(provider_sync)
    if age is None:
        return "Never synced"
    if age > OPENVAS_LIVE_STALE_SECONDS:
        return "Stale"
    return "Live"


def _is_live_job_stale(
    job: dict[str, Any],
    *,
    provider_online: bool = True,
) -> bool:
    if str(job.get("status") or "") in {
        "Completed",
        "Recovered report",
        "Failed",
        "Stopped",
        "Interrupted",
        "Submission failed",
        "Submission blocked",
        "Abandoned",
        "Cancelled",
    }:
        return False
    return _provider_sync_state(
        job,
        provider_online=provider_online,
    ) in {"Stale", "Never synced"}


def _openvas_job_group(
    job: dict[str, Any],
    *,
    provider_online: bool = True,
) -> str:
    status = str(job.get("status") or "Unknown")
    if status == "Queued":
        return "Queued"
    if status in {"Completed", "Recovered report"}:
        return "Completed"
    if status in {
        "Failed",
        "Stopped",
        "Interrupted",
        "Submission failed",
        "Submission blocked",
        "Abandoned",
        "Cancelled",
    } or _is_live_job_stale(job, provider_online=provider_online):
        return "Needs attention"
    return "Active"


def _compact_openvas_rows(
    jobs: list[dict[str, Any]],
    *,
    provider_online: bool = True,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for job in jobs:
        rows.append(
            {
                "Job": int(job.get("id") or 0),
                "Asset": job.get("asset_tag") or "Unassigned",
                "IP address": job.get("asset_ip") or "Unknown",
                "Status": str(job.get("status") or "Unknown"),
                "Provider": str(job.get("provider_status") or "Not started"),
                "Task raw": str(
                    job.get("provider_task_status") or job.get("provider_status") or "Not read"
                ),
                "Report raw": str(job.get("provider_report_status") or "No report state"),
                "Source": str(job.get("provider_progress_source") or "Not read"),
                "Sync": _provider_sync_state(
                    job,
                    provider_online=provider_online,
                ),
                "Stage": job.get("stage") or "Waiting",
                "Progress": int(job.get("progress") or 0),
                "Queue / elapsed": _live_elapsed_label(job),
                "Findings": int(job.get("findings_count") or 0),
                "Start error": (
                    str(job.get("error") or "")[:140]
                    if str(job.get("status") or "") in {"Submission failed", "Submission blocked"}
                    else ""
                ),
                "Report": report_action_value(ENGINE_OPENVAS, job),
                "Last update": str(
                    job.get("last_provider_sync_at")
                    or job.get("last_synced_at")
                    or job.get("updated_at")
                    or ""
                )[:19].replace("T", " "),
            }
        )
    return rows


def _arrow_safe_text(value: Any) -> str:
    """Return a stable text value for Streamlit/PyArrow tables."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _technical_openvas_identity(job: dict[str, Any]) -> list[dict[str, str]]:
    """Build a two-column technical identity table with consistent types."""
    values = [
        ("Workspace client", job.get("client_name") or get_active_client_name()),
        ("Batch ID", job.get("batch_id")),
        ("Job UUID", job.get("job_uuid") or "Legacy"),
        ("Database job ID", job.get("id")),
        ("Logical job", job.get("logical_job_id") or "Legacy"),
        ("Attempt", job.get("attempt_number") or 1),
        ("Target ID", job.get("target_id") or "Not created"),
        ("Task ID", job.get("task_id") or "Not created"),
        ("Launch report ID", job.get("launch_report_id") or "Pending"),
        ("Current report ID", job.get("report_id") or "Pending"),
        ("Provider effective status", job.get("provider_status") or "Not started"),
        ("Provider task raw status", job.get("provider_task_status") or "Not read"),
        ("Provider report raw status", job.get("provider_report_status") or "Not read"),
        ("Progress/status source", job.get("provider_progress_source") or "Not read"),
        ("Provider scan start", job.get("provider_scan_start") or "Not reported"),
        ("Provider scan end", job.get("provider_scan_end") or "Not reported"),
        ("Provider last sync", job.get("last_provider_sync_at") or "Never"),
        ("SecureScope status", job.get("ui_status") or job.get("status") or "Unknown"),
    ]
    return [
        {"Field": _arrow_safe_text(field), "Value": _arrow_safe_text(value)}
        for field, value in values
    ]


def _persist_openvas_batch_submission(
    *,
    client_name: str,
    batch_id: int,
    selected_assets: list[dict[str, Any]],
    jobs: list[dict[str, Any]],
    status_rows: list[dict[str, Any]],
    sync_to_ciso: bool,
) -> None:
    jobs_by_ip = {str((job.get("asset") or {}).get("ip") or ""): job for job in jobs}

    for index, asset in enumerate(selected_assets):
        normalized = normalize_asset(asset)
        asset_ip = str(normalized.get("ip") or "")
        job = jobs_by_ip.get(asset_ip)
        row = status_rows[index] if index < len(status_rows) else {}

        if job:
            create_or_update_openvas_job(
                client_name,
                batch_id=batch_id,
                asset=normalized,
                target_id=str(job.get("target_id") or ""),
                task_id=str(job.get("task_id") or ""),
                report_id=str(job.get("report_id") or ""),
                launch_report_id=str(job.get("report_id") or ""),
                scanner_id=str(job.get("scanner_id") or ""),
                status="Submitted",
                stage="Waiting for persistent worker",
                progress=0,
                result_message=(
                    "Task saved in PostgreSQL. The persistent worker will "
                    "monitor this existing task ID."
                ),
                sync_to_ciso=sync_to_ciso,
            )
        else:
            create_or_update_openvas_job(
                client_name,
                batch_id=batch_id,
                asset=normalized,
                status=str(row.get("Status") or "Submission failed"),
                stage=str(row.get("Submission stage") or "OpenVAS submission failed"),
                progress=0,
                result_message=str(row.get("Result") or ""),
                error=str(row.get("Error") or "Task was not created."),
                sync_to_ciso=sync_to_ciso,
            )

    update_batch_counters(batch_id)


def _openvas_worker_summary() -> tuple[bool, str]:
    """Return health of the embedded server-side reconciliation worker."""
    worker_name = os.getenv("OPENVAS_WORKER_NAME", "openvas-monitor")
    state = get_worker_state(worker_name)
    runtime = OPENVAS_WORKER_BOOTSTRAP.snapshot()

    if not state:
        return (
            False,
            "The embedded OpenVAS worker is starting. " + str(runtime.get("message") or ""),
        )

    age = int(state.get("heartbeat_age_seconds") or 999999)
    worker_status = str(state.get("status") or "unknown")
    message = str(state.get("message") or "")
    online = age <= 20 and worker_status not in {"stopped", "error"}

    if not online and runtime.get("error"):
        message = str(runtime.get("error"))

    return (
        online,
        f"Worker {worker_status}; heartbeat {age}s ago" + (f"; {message}" if message else ""),
    )


@st.fragment(run_every="3s")
def render_persistent_openvas_batch(batch_id: int) -> None:
    """Workspace-scoped OpenVAS operations console for one exact scan run."""
    # The fragment reads PostgreSQL only. The global embedded worker owns all
    # Greenbone polling, task creation and report reconciliation.

    batch = get_openvas_batch(batch_id)
    jobs = load_openvas_batch_jobs(batch_id)
    if not batch:
        st.error("The selected OpenVAS scan run no longer exists.")
        return

    active_client = get_active_client_name()
    if str(batch.get("client_name") or "") != str(active_client):
        st.error("Workspace isolation blocked this run: it belongs to another client.")
        st.session_state.pop("selected_persistent_openvas_batch_id", None)
        st.session_state.pop("persistent_openvas_batch_id_selector", None)
        return

    online, worker_message = _openvas_worker_summary()
    runtime_snapshot = OPENVAS_WORKER_BOOTSTRAP.snapshot()
    tunnel_online, tunnel_message = probe_gmp_tunnel(timeout_seconds=0.5)
    sync_error = str(runtime_snapshot.get("error") or "")
    deep_sync_error = str(runtime_snapshot.get("deep_error") or "")
    starter_error = str(runtime_snapshot.get("starter_error") or "")
    priority_syncing = batch_id in set(runtime_snapshot.get("priority_inflight") or [])
    priority_message = str(runtime_snapshot.get("priority_message") or "")
    priority_error = str(runtime_snapshot.get("priority_error") or "")

    # Continuously register the visible workspace batch with the dedicated
    # provider-status watcher. v4.10.17 only requested an exact sync after a
    # row had already become Stale, so a busy global cycle could let live rows
    # age out. The watch lease is renewed by this 3-second fragment and expires
    # automatically after the user leaves the page.
    if tunnel_online and any(str(job.get("task_id") or "").strip() for job in jobs):
        watch_batch = getattr(OPENVAS_WORKER_BOOTSTRAP, "watch_batch", None)
        if callable(watch_batch):
            watch_batch(batch_id)
        elif any(
            _provider_sync_state(job, provider_online=True)
            in {"Pending poll", "Never synced", "Stale"}
            for job in jobs
            if str(job.get("task_id") or "").strip()
        ):
            OPENVAS_WORKER_BOOTSTRAP.wake(batch_id=batch_id)

    st.markdown(
        f"""
        <div class="dash-panel" style="padding:1.15rem 1.25rem;margin-bottom:0.8rem;">
          <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
            <div>
              <div class="eyebrow">OPENVAS LIVE EXECUTION</div>
              <h3 style="margin:.2rem 0;">{safe_text(active_client)} · Batch #{batch_id}</h3>
              <div style="color:#64748b;">
                Run {safe_text(str(batch.get('batch_uuid') or '')[:8])} ·
                {safe_text(batch.get('profile_name') or 'Unknown profile')} ·
                created {safe_text(str(batch.get('created_at') or '')[:19].replace('T', ' '))}
              </div>
            </div>
            <div style="text-align:right;color:#475569;">
              <strong>Parallel scans {OPENVAS_MAX_CONCURRENT_SCANS}</strong><br/>
              <span>Auto-refresh every 3 seconds</span>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    health_cols = st.columns(5, gap="small")
    health_items = [
        ("Worker", "Healthy" if online else "Degraded", worker_message),
        (
            "GMP tunnel",
            "Healthy" if tunnel_online else "Offline",
            tunnel_message,
        ),
        ("PostgreSQL", "Healthy", "Workspace-scoped batch and jobs loaded."),
        (
            "Scanner queue",
            "Protected",
            f"Parallel limit: {OPENVAS_MAX_CONCURRENT_SCANS} active scan(s).",
        ),
        (
            "VM resources",
            "Not connected",
            "No remote RAM/CPU telemetry source is configured.",
        ),
    ]
    for column, (label, status, detail) in zip(health_cols, health_items):
        with column:
            tone = "success" if status in {"Healthy", "Protected"} else "warning"
            getattr(st, tone)(f"**{label}**\n\n{status}")
            st.caption(detail)

    if not tunnel_online:
        st.error(
            "OpenVAS synchronization is paused because the local SSH tunnel "
            f"is offline. {tunnel_message}"
        )
    if starter_error:
        st.error(f"Background OpenVAS queue starter failed: {starter_error}")
    if sync_error:
        st.error(f"Background fast Greenbone status sync failed: {sync_error}")
    if deep_sync_error:
        st.warning(f"Background report reconciliation is delayed: {deep_sync_error}")
    if priority_syncing:
        st.info(f"Direct live synchronization is running for batch #{batch_id}.")
    elif priority_error:
        st.warning(f"Last direct batch synchronization error: {priority_error}")
    elif priority_message and priority_message != "Not started":
        st.caption(priority_message)
    if runtime_snapshot.get("last_cycle_at"):
        st.caption(
            "Last global fast status cycle: "
            + str(runtime_snapshot.get("last_cycle_at"))[:19].replace("T", " ")
            + " UTC · "
            + str(runtime_snapshot.get("message") or "")
        )
    if runtime_snapshot.get("last_priority_cycle_at"):
        st.caption(
            "Last direct batch status cycle: "
            + str(runtime_snapshot.get("last_priority_cycle_at"))[:19].replace("T", " ")
            + " UTC · "
            + priority_message
        )
    if runtime_snapshot.get("last_deep_cycle_at"):
        st.caption(
            "Last report/finalization cycle: "
            + str(runtime_snapshot.get("last_deep_cycle_at"))[:19].replace("T", " ")
            + " UTC · "
            + str(runtime_snapshot.get("deep_message") or "")
        )
    if runtime_snapshot.get("last_start_cycle_at"):
        st.caption(
            "Last queue-start cycle: "
            + str(runtime_snapshot.get("last_start_cycle_at"))[:19].replace("T", " ")
            + " UTC · "
            + str(runtime_snapshot.get("starter_message") or "")
        )

    total = len(jobs)
    queued = sum(
        1 for job in jobs if _openvas_job_group(job, provider_online=tunnel_online) == "Queued"
    )
    active = sum(
        1 for job in jobs if _openvas_job_group(job, provider_online=tunnel_online) == "Active"
    )
    completed = sum(
        1 for job in jobs if _openvas_job_group(job, provider_online=tunnel_online) == "Completed"
    )
    attention = sum(
        1
        for job in jobs
        if _openvas_job_group(job, provider_online=tunnel_online) == "Needs attention"
    )
    tasks_created = sum(1 for job in jobs if str(job.get("task_id") or "").strip())
    tasks_missing = max(0, total - tasks_created)
    retryable_start_failures = sum(
        1
        for job in jobs
        if str(job.get("status") or "") == "Submission failed"
        and str(job.get("task_id") or "").strip()
        and any(
            token in str(job.get("error") or "").lower()
            for token in ("timed out", "timeouterror", "connection reset", "forcibly closed")
        )
    )
    start_confirmation_pending = sum(
        1
        for job in jobs
        if str(job.get("provider_status") or "").strip().lower()
        in {"start confirmation pending", "task lookup pending"}
    )
    queue_snapshot = get_openvas_queue_snapshot(
        batch_id,
        active_stale_seconds=OPENVAS_ACTIVE_SLOT_FRESH_SECONDS,
    )

    if retryable_start_failures:
        st.warning(
            f"{retryable_start_failures} task(s) have a preserved task UUID "
            "from an older start timeout. The background worker will verify "
            "and retry those exact tasks automatically; no duplicate task is created."
        )
        if st.button(
            "Retry preserved timed-out task(s) now",
            icon=":material/replay:",
            key=f"retry_preserved_start_timeouts_{batch_id}",
        ):
            recovered = requeue_ambiguous_openvas_start_failures(
                batch_id=batch_id,
            )
            start_result = trigger_openvas_queue_start_cycle(
                timeout_seconds=10.0,
            )
            if recovered:
                st.success(
                    f"Requeued {len(recovered)} exact task(s); "
                    f"starter submitted {start_result.get('started', 0)} task(s)."
                )
                st.rerun(scope="fragment")
            else:
                st.info(
                    "No timed-out task required requeueing. The worker may "
                    "already have recovered it."
                )

    if start_confirmation_pending:
        st.info(
            f"{start_confirmation_pending} task(s) have an unconfirmed GMP "
            "response. Their exact task IDs are preserved while SecureScope "
            "checks Greenbone; they are not treated as failed or recreated."
        )

    raw_requested = sum(
        1
        for job in jobs
        if str(job.get("provider_task_status") or "").strip().lower() == "requested"
        and not str(job.get("provider_scan_start") or "").strip()
        and int(job.get("progress") or 0) == 0
    )
    if raw_requested:
        st.info(
            f"Greenbone still reports raw task status Requested for "
            f"{raw_requested} task(s), with no scan_start or non-zero provider "
            "progress yet. SecureScope will keep polling the task and its "
            "launch report; it will change the effective state to Running as "
            "soon as provider evidence appears."
        )

    if queued > 0 and active == 0:
        global_active = int(queue_snapshot.get("global_active") or 0)
        queued_ahead = int(queue_snapshot.get("queued_ahead") or 0)
        if global_active > 0:
            st.info(
                "This batch is waiting because the protected OpenVAS scanner "
                "slot is currently used by another batch. "
                f"{queued_ahead} older queued job(s) are ahead globally. "
                "Workspace asset details remain isolated."
            )
        elif online and tasks_missing > 0:
            st.warning(
                f"This batch has {tasks_missing} asset(s) without a Greenbone "
                "task. Use Create and start all assets in parallel below. "
                "SecureScope submits every prepared task without waiting for "
                "an earlier asset to complete."
            )
        elif online:
            st.warning(
                "Every asset already has a Greenbone task, but no scan is "
                "active. Use Start all prepared tasks in parallel below."
            )
        else:
            st.error(
                "This batch is queued but the embedded worker is offline. "
                "Review the Worker and GMP health messages above."
            )

    if queued > 0 and active == 0:
        failed_rows = [
            job
            for job in jobs
            if str(job.get("status") or "") == "Submission failed"
            or str(job.get("error") or "").strip()
        ]
        with st.container(border=True):
            st.markdown("#### Task creation status")
            st.caption(
                "This section reports the exact create_target → create_task → "
                "start_task path. A job is no longer silently returned to Queued."
            )
            if starter_error:
                st.error(starter_error)
            if failed_rows:
                latest_failed = failed_rows[-1]
                st.error(
                    f"Job #{latest_failed.get('id')} · "
                    f"{latest_failed.get('asset_ip')} · "
                    f"{latest_failed.get('stage')}: "
                    f"{latest_failed.get('error') or 'Unknown submission error'}"
                )
            diag_col, create_col, start_col = st.columns(
                3,
                gap="small",
            )
            with diag_col:
                if st.button(
                    "Test GVM connection and resources",
                    icon=":material/health_and_safety:",
                    width="stretch",
                    key=f"test_openvas_submission_{batch_id}",
                ):
                    with st.spinner("Testing GMP authentication and resources…"):
                        diagnostic = diagnose_openvas_submission_path()
                    if diagnostic.get("ok"):
                        st.success(
                            "Ready: "
                            f"{diagnostic.get('profile_name')} · "
                            f"{diagnostic.get('port_list_name')} · "
                            f"{diagnostic.get('scanner_name')}"
                        )
                        st.json(diagnostic, expanded=False)
                    else:
                        st.error(
                            f"{diagnostic.get('stage') or 'Diagnostic'}: "
                            f"{diagnostic.get('error') or 'Unknown error'}"
                        )

            with create_col:
                if st.button(
                    "Create and start all assets in parallel",
                    icon=":material/playlist_add:",
                    type="primary",
                    width="stretch",
                    key=f"prepare_all_openvas_tasks_{batch_id}",
                    disabled=tasks_missing == 0,
                ):
                    with st.spinner("Creating and starting every selected OpenVAS task…"):
                        parallel = prepare_and_start_openvas_batch_parallel(
                            batch_id,
                            max_parallel=OPENVAS_MAX_CONCURRENT_SCANS,
                            timeout_seconds=90.0,
                        )
                    preparation = parallel.get("preparation") or {}
                    started_batch = parallel.get("start") or {}
                    for item in preparation.get("errors") or []:
                        st.error(
                            f"Job #{item.get('job_id') or '?'} · "
                            f"{item.get('asset_ip') or 'unknown asset'} · "
                            f"{item.get('stage') or 'task creation'}: "
                            f"{item.get('error') or 'Unknown error'}"
                        )
                    for item in started_batch.get("errors") or []:
                        st.error(
                            f"Job #{item.get('job_id') or '?'} · "
                            f"{item.get('asset_ip') or 'unknown asset'} · "
                            f"{item.get('stage') or 'task start'}: "
                            f"{item.get('error') or 'Unknown error'}"
                        )
                    if parallel.get("started"):
                        st.success(
                            f"Created {parallel.get('created', 0)} new task(s) "
                            f"and started {parallel.get('started', 0)} task(s) "
                            "in parallel."
                        )
                        st.rerun(scope="fragment")
                    elif not (preparation.get("errors") or started_batch.get("errors")):
                        st.info(
                            "No additional task was started. Check whether all "
                            "tasks are already active or completed."
                        )

            with start_col:
                if st.button(
                    "Start all prepared tasks in parallel",
                    icon=":material/play_circle:",
                    width="stretch",
                    key=f"start_next_openvas_task_{batch_id}",
                    disabled=tasks_created == 0,
                ):
                    with st.spinner("Submitting start_task for every prepared asset…"):
                        result = start_openvas_batch_parallel(
                            batch_id,
                            max_parallel=OPENVAS_MAX_CONCURRENT_SCANS,
                            timeout_seconds=30.0,
                        )
                    for item in result.get("errors") or []:
                        st.error(
                            f"Job #{item.get('job_id') or '?'} · "
                            f"{item.get('asset_ip') or 'unknown asset'} · "
                            f"{item.get('stage') or 'task start'}: "
                            f"{item.get('error') or 'Unknown error'}"
                        )
                    if result.get("started"):
                        st.success(
                            f"Started {result.get('started', 0)} OpenVAS " "task(s) in parallel."
                        )
                        st.rerun(scope="fragment")
                    elif not result.get("errors"):
                        st.warning(
                            "No prepared task was eligible. Tasks may already "
                            "be active or completed."
                        )

            st.info(
                "Exclusive batch dispatch is enabled. Only this explicitly "
                "launched batch may create or start additional Greenbone tasks. "
                "Historical queued batches remain in PostgreSQL but cannot "
                "silently add more Requested tasks."
            )

            cleanup_confirm = st.checkbox(
                "I confirm that older SecureScope tasks outside this batch may be stopped",
                value=False,
                key=f"confirm_stop_older_securescope_tasks_{batch_id}",
                help=(
                    "Completed tasks are preserved. Historical New tasks are moved "
                    "to trash; Requested, Queued, Running and Processing tasks are stopped."
                ),
            )
            if st.button(
                "Stop older SecureScope tasks outside this batch",
                icon=":material/stop_circle:",
                width="stretch",
                disabled=not cleanup_confirm,
                key=f"stop_older_securescope_tasks_{batch_id}",
            ):
                with st.spinner("Stopping historical SecureScope tasks in Greenbone…"):
                    cleanup_result = stop_other_securescope_tasks(batch_id)
                st.success(
                    f"Cleanup submitted: {cleanup_result.get('stopped', 0)} "
                    f"task(s) stopped; {cleanup_result.get('deleted_new', 0)} "
                    "New task(s) moved to trash. Completed tasks were preserved."
                )
                for cleanup_error in cleanup_result.get("errors") or []:
                    st.error(
                        f"Task {cleanup_error.get('task_id') or '?'} · "
                        f"{cleanup_error.get('status') or 'Unknown'}: "
                        f"{cleanup_error.get('error') or 'Unknown cleanup error'}"
                    )
                st.rerun(scope="fragment")

    metrics = st.columns(6, gap="small")
    for column, label, value in zip(
        metrics,
        [
            "Total",
            "Tasks in OpenVAS",
            "Queued",
            "Active",
            "Completed",
            "Needs attention",
        ],
        [total, tasks_created, queued, active, completed, attention],
    ):
        column.metric(label, value)

    completion_ratio = completed / total if total else 0.0
    st.progress(
        completion_ratio,
        text=(
            f"{completed} of {total} assets completed · "
            f"{tasks_created} tasks created in OpenVAS · "
            f"{queued} queued · {active} active"
        ),
    )
    st.caption(
        "Greenbone percentage represents completed vulnerability tests, not an ETA. "
        f"Global scanner state: {queue_snapshot.get('global_active', 0)} active · "
        f"{queue_snapshot.get('global_queued', 0)} queued."
    )

    with st.expander("OpenVAS provider status guide", expanded=False):
        st.markdown(
            (
                "**Provider** is SecureScope's evidence-based effective "
                "state.  \n**Task raw** is the exact `<task><status>` value "
                "returned by gvmd.  \n**Report raw** is the exact report "
                "`scan_run_status`, when available.  \n**Start submitted** — "
                "start_task returned successfully, but no provider poll has "
                "confirmed runtime state yet.  \n**New** — the task exists "
                "but has not started; SecureScope submits the same task "
                "again without recreating it.  \n**Requested** — gvmd "
                "accepted the request, but the scanner has not reported "
                "execution.  \n**Running** — task status, report status, "
                "scan_start, or non-zero provider progress proves execution. "
                " \n**Processing / Done** — Greenbone is assembling or has "
                "completed the report.  \n**Sync** is based only on the last "
                "successful GMP provider read; local database writes never "
                "mark a row Live."
            )
        )

    filter_col, search_col, sync_col, wake_col = st.columns(
        [1.1, 1.5, 0.65, 0.65],
        gap="small",
    )
    with filter_col:
        selected_filter = st.radio(
            "Status filter",
            ["All", "Active", "Queued", "Completed", "Needs attention"],
            horizontal=True,
            key=f"openvas_live_filter_{batch_id}",
            label_visibility="collapsed",
        )
    with search_col:
        search = st.text_input(
            "Search assets",
            placeholder="Search asset tag or IP",
            key=f"openvas_live_search_{batch_id}",
            label_visibility="collapsed",
        )
    with sync_col:
        if st.button(
            "Sync live status now",
            icon=":material/refresh:",
            width="stretch",
            key=f"refresh_live_batch_{batch_id}",
            help=(
                "Read exact task status/progress for this batch without waiting "
                "for report import."
            ),
        ):
            with st.spinner("Synchronizing this batch with Greenbone…"):
                sync_result = trigger_openvas_fast_status_cycle(
                    batch_id=batch_id,
                    timeout_seconds=35.0,
                )
            if sync_result.get("error"):
                st.error(str(sync_result.get("error")))
            elif sync_result.get("busy"):
                OPENVAS_WORKER_BOOTSTRAP.wake(batch_id=batch_id)
                st.info(str(sync_result.get("message") or "This batch is already synchronizing."))
            else:
                st.toast(
                    f"Live status updated for {sync_result.get('updated', 0)} task(s); "
                    f"{sync_result.get('failed', 0)} failed.",
                    icon="✅",
                )
            st.rerun(scope="fragment")

    with wake_col:
        if st.button(
            "Wake worker",
            icon=":material/play_arrow:",
            width="stretch",
            key=f"wake_openvas_worker_{batch_id}",
            help=(
                "Request an immediate worker cycle. It does not create a "
                "duplicate task because existing task names are reconciled first."
            ),
        ):
            OPENVAS_WORKER_BOOTSTRAP.start()
            if hasattr(OPENVAS_WORKER_BOOTSTRAP, "wake"):
                OPENVAS_WORKER_BOOTSTRAP.wake(batch_id=batch_id)
            st.toast("OpenVAS worker awakened.", icon="✅")
            st.rerun(scope="fragment")

    filtered_jobs = []
    query = str(search or "").strip().lower()
    for job in jobs:
        group = _openvas_job_group(job, provider_online=tunnel_online)
        if selected_filter != "All" and group != selected_filter:
            continue
        searchable = " ".join(
            [
                str(job.get("asset_tag") or ""),
                str(job.get("asset_ip") or ""),
                str(job.get("status") or ""),
                str(job.get("stage") or ""),
            ]
        ).lower()
        if query and query not in searchable:
            continue
        filtered_jobs.append(job)

    compact_rows = _compact_openvas_rows(
        filtered_jobs,
        provider_online=tunnel_online,
    )
    compact_frame = pd.DataFrame(compact_rows)
    if compact_frame.empty:
        st.info("No scan jobs match the current filter.")
    else:
        st.dataframe(
            compact_frame,
            width="stretch",
            hide_index=True,
            height=min(520, 105 + len(compact_rows) * 38),
            column_config={
                "Job": st.column_config.NumberColumn("Job", width="small"),
                "Asset": st.column_config.TextColumn("Asset", width="small"),
                "IP address": st.column_config.TextColumn("IP address", width="small"),
                "Status": st.column_config.TextColumn("Status", width="medium"),
                "Provider": st.column_config.TextColumn("Provider effective", width="medium"),
                "Task raw": st.column_config.TextColumn("Task raw", width="small"),
                "Report raw": st.column_config.TextColumn("Report raw", width="small"),
                "Source": st.column_config.TextColumn("Evidence source", width="medium"),
                "Sync": st.column_config.TextColumn("Sync", width="small"),
                "Stage": st.column_config.TextColumn("Current stage", width="large"),
                "Progress": st.column_config.ProgressColumn(
                    "Progress", min_value=0, max_value=100, format="%d%%", width="medium"
                ),
                "Queue / elapsed": st.column_config.TextColumn("Queue / elapsed", width="small"),
                "Findings": st.column_config.NumberColumn("Findings", width="small"),
                "Start error": st.column_config.TextColumn(
                    "Task creation error",
                    width="large",
                ),
                "Report": st.column_config.TextColumn(
                    "Report",
                    width="small",
                    help="A PDF action is available when the job is complete.",
                ),
                "Last update": st.column_config.TextColumn("Last update", width="medium"),
            },
        )

        # Keep report actions beside the matching asset. Each icon downloads
        # that job's PDF directly, without a second selection panel.
        render_report_downloads(
            active_client,
            ENGINE_OPENVAS,
            filtered_jobs,
            key=f"openvas_reports::{active_client}::{batch_id}",
        )

    if not filtered_jobs:
        return

    selectable_by_id = {int(job["id"]): job for job in filtered_jobs}
    candidate_ids = list(selectable_by_id)
    selected_job_id = st.session_state.get(f"openvas_live_selected_job_id_{batch_id}")
    if selected_job_id not in selectable_by_id:
        selected_job_id = candidate_ids[0]
        st.session_state[f"openvas_live_selected_job_id_{batch_id}"] = selected_job_id

    selected_job_id = int(
        st.selectbox(
            "Selected scan job",
            candidate_ids,
            key=f"openvas_live_selected_job_id_{batch_id}",
            format_func=lambda job_id: (
                f"{selectable_by_id[job_id].get('asset_tag') or 'Asset'} · "
                f"{selectable_by_id[job_id].get('asset_ip')} · "
                f"{selectable_by_id[job_id].get('status')} · "
                f"run {str(selectable_by_id[job_id].get('job_uuid') or '')[:8]}"
            ),
        )
    )
    selected_job = selectable_by_id[selected_job_id]

    if not tunnel_online:
        st.warning(
            "Provider synchronization is offline. This row shows the last "
            "known Greenbone status and progress until the SSH tunnel returns."
        )
    elif _is_live_job_stale(selected_job, provider_online=True):
        st.warning(
            "This row is stale: the worker has not synchronized it within the "
            f"last {OPENVAS_LIVE_STALE_SECONDS} seconds. The displayed percentage may be old."
        )

    overview_tab, timeline_tab, identity_tab, actions_tab = module_tabs(
        ["Current status", "Timeline", "Technical identity", "Actions"]
    )

    with overview_tab:
        status_cols = st.columns(4)
        status_cols[0].metric("SecureScope status", selected_job.get("status") or "Unknown")
        status_cols[1].metric(
            "Provider status", selected_job.get("provider_status") or "Not started"
        )
        status_cols[2].metric("Progress", f"{int(selected_job.get('progress') or 0)}%")
        status_cols[3].metric("Elapsed", _live_elapsed_label(selected_job))
        st.caption(
            "Task raw: "
            + str(selected_job.get("provider_task_status") or "Not read")
            + " · Report raw: "
            + str(selected_job.get("provider_report_status") or "Not read")
            + " · Evidence: "
            + str(selected_job.get("provider_progress_source") or "Not read")
            + " · Sync: "
            + _provider_sync_state(
                selected_job,
                provider_online=tunnel_online,
            )
        )
        st.progress(
            int(selected_job.get("progress") or 0) / 100,
            text=str(selected_job.get("stage") or "Waiting"),
        )
        if selected_job.get("result_message"):
            st.info(str(selected_job.get("result_message")))
        if selected_job.get("error"):
            st.error(str(selected_job.get("error")))

        finding_cols = st.columns(4)
        finding_cols[0].metric("Critical", int(selected_job.get("critical_count") or 0))
        finding_cols[1].metric("High", int(selected_job.get("high_count") or 0))
        finding_cols[2].metric("Medium", int(selected_job.get("medium_count") or 0))
        finding_cols[3].metric("Imported findings", int(selected_job.get("findings_count") or 0))
        if str(selected_job.get("status") or "") not in {"Completed", "Recovered report"}:
            st.caption(
                (
                    "Finding counts remain preliminary or unavailable until the exact "
                    "report is imported."
                )
            )

    with timeline_tab:
        events = list_openvas_job_events(selected_job_id, limit=100)
        if not events:
            st.info("No persistent timeline events are available for this legacy job.")
        else:
            timeline_rows = [
                {
                    "Time": str(event.get("created_at") or "")[:19].replace("T", " "),
                    "Event": str(event.get("event_type") or "").replace("_", " ").title(),
                    "Provider": event.get("provider_status") or "",
                    "Status": event.get("ui_status") or "",
                    "Stage": event.get("stage") or "",
                    "Progress": event.get("progress"),
                    "Message": event.get("message") or event.get("error") or "",
                }
                for event in reversed(events)
            ]
            st.dataframe(pd.DataFrame(timeline_rows), width="stretch", hide_index=True)

    with identity_tab:
        st.dataframe(
            pd.DataFrame(_technical_openvas_identity(selected_job)),
            width="stretch",
            hide_index=True,
        )
        logical_id = str(selected_job.get("logical_job_id") or "")
        if logical_id:
            st.markdown("##### Attempt history")
            attempts = list_openvas_attempts(logical_id)
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Attempt": item.get("attempt_number"),
                            "Current": "Yes" if item.get("is_current_attempt") else "No",
                            "Workspace": item.get("client_name"),
                            "Batch": item.get("batch_id"),
                            "Status": item.get("status"),
                            "Task ID": item.get("task_id") or "Not created",
                            "Launch report": item.get("launch_report_id") or "Pending",
                            "Retry reason": item.get("retry_reason") or "",
                        }
                        for item in attempts
                    ]
                ),
                width="stretch",
                hide_index=True,
            )

    with actions_tab:
        status = str(selected_job.get("status") or "")
        task_id = str(selected_job.get("task_id") or "")
        action_cols = st.columns(4, gap="small")

        with action_cols[0]:
            if status == "Queued":
                if st.button(
                    "Cancel queued job",
                    icon=":material/cancel:",
                    width="stretch",
                    key=f"cancel_queue_{selected_job_id}",
                ):
                    cancel_queued_openvas_job(
                        selected_job_id,
                        reason="Cancelled in the workspace live console.",
                    )
                    st.toast("Queued job cancelled before task creation.", icon="✅")
                    st.rerun(scope="fragment")
            elif st.button(
                "Refresh status",
                icon=":material/refresh:",
                width="stretch",
                disabled=not task_id,
                key=f"refresh_job_{selected_job_id}",
            ):
                request_openvas_job_action(selected_job_id, "refresh")
                st.toast("Refresh queued for the worker.", icon="✅")

        with action_cols[1]:
            if st.button(
                "Stop active task",
                icon=":material/stop_circle:",
                width="stretch",
                disabled=status
                not in {"Starting", "Waiting for scanner", "Running", "Processing results"}
                or not task_id,
                key=f"stop_job_{selected_job_id}",
            ):
                request_openvas_job_action(selected_job_id, "stop")
                st.toast("Stop request queued for the exact task ID.", icon="✅")

        with action_cols[2]:
            if st.button(
                "Resume stopped task",
                icon=":material/play_arrow:",
                width="stretch",
                disabled=status != "Stopped" or not task_id,
                key=f"resume_job_{selected_job_id}",
            ):
                request_openvas_job_action(selected_job_id, "resume")
                st.toast("Resume request queued for the same task ID.", icon="✅")

        with action_cols[3]:
            if st.button(
                "Recover existing report",
                icon=":material/download_for_offline:",
                width="stretch",
                disabled=(not task_id or status in {"Completed", "Recovered report", "Queued"}),
                key=f"recover_job_{selected_job_id}",
            ):
                request_openvas_job_action(selected_job_id, "recover")
                st.toast("Exact report recovery queued.", icon="✅")

        retryable = status in {
            "Failed",
            "Stopped",
            "Interrupted",
            "Submission failed",
            "Submission blocked",
            "Abandoned",
            "Cancelled",
        }
        completed_rescan = status in {"Completed", "Recovered report"}
        reason = st.text_input(
            "Retry or deliberate re-scan reason",
            key=f"retry_reason_{selected_job_id}",
            placeholder="Example: remediation verification or scanner interruption",
        )
        confirm_rescan = False
        if completed_rescan:
            confirm_rescan = st.checkbox(
                "Create a new assessment for this completed asset",
                key=f"confirm_rescan_{selected_job_id}",
            )
        can_retry = retryable or (completed_rescan and confirm_rescan)
        if st.button(
            "Queue new attempt" if retryable else "Queue deliberate re-scan",
            icon=":material/replay:",
            type="primary",
            width="stretch",
            disabled=not can_retry or not reason.strip(),
            key=f"retry_job_{selected_job_id}",
        ):
            result = retry_openvas_jobs(
                active_client,
                [selected_job_id],
                reason=reason,
                allow_completed=completed_rescan and confirm_rescan,
            )
            st.session_state["selected_persistent_openvas_batch_id"] = result["batch_id"]
            st.session_state["persistent_openvas_batch_id_selector"] = result["batch_id"]
            st.success(result["message"])
            st.rerun()

        if status in {
            "Failed",
            "Stopped",
            "Interrupted",
            "Submission failed",
            "Submission blocked",
        }:
            if st.button(
                "Mark attempt abandoned",
                icon=":material/block:",
                width="stretch",
                key=f"abandon_job_{selected_job_id}",
            ):
                abandon_openvas_job(
                    selected_job_id,
                    reason="Abandoned from the workspace live console.",
                )
                st.rerun(scope="fragment")

    csv_frame = pd.DataFrame(_compact_openvas_rows(jobs, provider_online=tunnel_online))
    st.download_button(
        "Download this workspace batch status CSV",
        data=csv_frame.to_csv(index=False).encode("utf-8-sig"),
        file_name=f"openvas_{active_client}_{batch.get('batch_uuid')}_status.csv".replace(" ", "_"),
        mime="text/csv",
        width="stretch",
        key=f"download_live_batch_{batch_id}",
    )

    if str(batch.get("status") or "") in {
        "Completed",
        "Completed with errors",
        "Failed",
        "Cancelled",
    }:
        st.session_state.scan_history = load_scan_history(active_client)


def render_openvas_scan_centre_page() -> None:
    """Render the preserved workspace-scoped OpenVAS scan console."""
    raw_assets = [normalize_asset(asset) for asset in st.session_state.assets]
    assets, duplicate_ip_groups = _deduplicate_assets_by_ip(raw_assets)
    selected_asset = get_current_asset()
    client_name = get_active_client_name()
    active_openvas_batch = get_active_openvas_batch(client_name)

    page_hero(
        "OPENVAS SCAN CENTER",
        "OpenVAS",
        (
            "Select authorized inventory assets, submit OpenVAS tasks, follow each "
            "host independently and download professional vulnerability reports."
        ),
        f"{len(assets)} asset(s) available" if assets else "No assets available",
        "ready" if assets else "warning",
    )

    if not assets:
        st.warning("No assets are available. Run Asset Discovery first.")
        return

    tabs = module_tabs(
        ["1. Select targets", "2. Live execution", "3. PDF reports", "4. Latest findings"]
    )

    with tabs[0]:
        if duplicate_ip_groups:
            duplicate_count = sum(len(records) - 1 for records in duplicate_ip_groups.values())
            st.warning(
                f"{duplicate_count} duplicate inventory record(s) share an IP "
                "with another asset. SecureScope consolidated them into one "
                "OpenVAS target per IP for this scan."
            )
            with st.expander("Review duplicate IP records", expanded=False):
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "IP address": ip,
                                "Records": len(records),
                                "Selected target record": (
                                    records[0].get("asset_tag") or "Unassigned"
                                ),
                                "Consolidated records": ", ".join(
                                    str(record.get("asset_tag") or "Unassigned")
                                    for record in records[1:]
                                ),
                            }
                            for ip, records in duplicate_ip_groups.items()
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )
        scan_mode = render_button_choice(
            "Target selection",
            ["Single asset", "Multiple assets / parallel batch"],
            key="openvas_parallel_scan_mode",
            default="Single asset",
            icons={
                "Single asset": ":material/dns:",
                "Multiple assets / parallel batch": ":material/view_list:",
            },
        )
        asset_labels = {
            f"{asset['asset_tag']} • {asset['ip']} • {asset['hostname']}": asset for asset in assets
        }
        labels = list(asset_labels.keys())

        if scan_mode == "Single asset":
            default_index = 0
            if selected_asset:
                for index, label in enumerate(labels):
                    if asset_labels[label]["ip"] == selected_asset.get("ip"):
                        default_index = index
                        break
            selected_labels = [st.selectbox("OpenVAS target", labels, index=default_index)]
        else:
            scope = st.radio(
                "Parallel batch scope",
                ["All discovered assets", "Choose assets manually"],
                horizontal=True,
                key="openvas_parallel_scope",
            )
            if scope == "All discovered assets":
                selected_labels = labels
                st.info(
                    (
                        "All "
                        f"{len(labels)}"
                        " assets will be submitted to OpenVAS before monitoring "
                        "begins."
                    )
                )
            else:
                selected_labels = st.multiselect(
                    "Assets to scan in parallel",
                    labels,
                    default=labels[: min(10, len(labels))],
                )

        selected_assets_raw = [asset_labels[label] for label in selected_labels]
        selected_assets, selected_duplicate_groups = _deduplicate_assets_by_ip(selected_assets_raw)

        # The same IP is allowed in a later or parallel scan run. Every
        # submission creates a fresh Greenbone task and report identity.
        # We only consolidate duplicate inventory rows selected in this one
        # submission, because they represent the same network endpoint.
        launchable_assets = list(selected_assets)
        st.session_state.openvas_selected_parallel_assets = launchable_assets

        if selected_duplicate_groups:
            st.info(
                "Repeated inventory rows inside this submission were "
                "consolidated into one target per IP. A later re-scan of the "
                "same IP is fully allowed and receives a new task ID."
            )

        summary_cols = st.columns(3, gap="small")

        if scan_mode == "Single asset" and selected_assets:
            target_asset = selected_assets[0]
            summary_values = [
                (
                    "Target",
                    str(target_asset.get("asset_tag") or "Unassigned"),
                    str(target_asset.get("ip") or "No IP address"),
                ),
                (
                    "OpenVAS profile",
                    SCAN_CONFIG_NAME,
                    PORT_LIST_NAME,
                ),
                (
                    "Report output",
                    "Individual PDF",
                    "Download after the task completes",
                ),
            ]
        else:
            summary_values = [
                (
                    "Targets",
                    f"{len(launchable_assets)} asset(s)",
                    "Every new run receives new task and report IDs",
                ),
                (
                    "Execution",
                    "Parallel submission",
                    f"Profile: {SCAN_CONFIG_NAME}",
                ),
                (
                    "Report output",
                    "Per-asset PDF + ZIP",
                    "Download separately or together",
                ),
            ]

        for column, (label, value, detail) in zip(
            summary_cols,
            summary_values,
        ):
            with column:
                with st.container(border=True):
                    st.caption(label.upper())
                    st.markdown(f"**{safe_text(value)}**")
                    st.caption(detail)

        preview = pd.DataFrame(
            [
                {
                    "Asset tag": asset.get("asset_tag") or "Unassigned",
                    "IP": asset.get("ip") or "Not detected",
                    "OS": (
                        asset.get("operating_system")
                        if str(asset.get("operating_system") or "").strip().lower()
                        not in {"", "unknown", "not inspected", "n/a"}
                        else "Not detected"
                    ),
                    "Device type": (
                        asset.get("device_type")
                        if str(asset.get("device_type") or "").strip().lower()
                        not in {"", "unknown", "not inspected", "n/a"}
                        else "Not detected"
                    ),
                    "MAC / vendor": " · ".join(
                        value
                        for value in [
                            (
                                str(asset.get("mac_address"))
                                if str(asset.get("mac_address") or "").strip().lower()
                                not in {"", "unknown", "not inspected", "n/a"}
                                else ""
                            ),
                            (
                                str(asset.get("manufacturer"))
                                if str(asset.get("manufacturer") or "").strip().lower()
                                not in {"", "unknown", "not inspected", "n/a"}
                                else ""
                            ),
                        ]
                        if value
                    )
                    or "Not detected",
                    "Open ports": (
                        asset.get("open_ports")
                        if str(asset.get("open_ports") or "").strip().lower()
                        not in {"", "unknown", "not inspected", "n/a"}
                        else "Not detected"
                    ),
                    "Criticality": asset.get("criticality") or "Medium",
                    "Readiness": (
                        "Enriched"
                        if (
                            str(asset.get("operating_system") or "").strip().lower()
                            not in {"", "unknown", "not inspected", "n/a"}
                            and str(asset.get("open_ports") or "").strip().lower()
                            not in {"", "unknown", "not inspected", "n/a"}
                        )
                        else "Needs Nmap enrichment"
                    ),
                }
                for asset in selected_assets
            ]
        )
        if not preview.empty:
            st.dataframe(
                preview,
                width="stretch",
                hide_index=True,
                height=min(460, 90 + len(preview) * 35),
                column_config={
                    "Asset tag": st.column_config.TextColumn("Asset", width="small"),
                    "IP": st.column_config.TextColumn("IP address", width="small"),
                    "OS": st.column_config.TextColumn("Operating system", width="medium"),
                    "Device type": st.column_config.TextColumn("Device type", width="medium"),
                    "MAC / vendor": st.column_config.TextColumn("MAC / vendor", width="medium"),
                    "Open ports": st.column_config.TextColumn("Open ports", width="large"),
                    "Criticality": st.column_config.TextColumn("Criticality", width="small"),
                    "Readiness": st.column_config.TextColumn("Readiness", width="medium"),
                },
            )

        missing_detail_assets = [
            asset
            for asset in selected_assets
            if (
                str(asset.get("operating_system") or "").strip().lower()
                in {"", "unknown", "not inspected", "n/a"}
                or str(asset.get("open_ports") or "").strip().lower()
                in {"", "unknown", "not inspected", "n/a"}
            )
        ]

        with st.expander(
            f"Nmap enrichment for missing technical fields ({len(missing_detail_assets)})",
            expanded=False,
        ):
            st.write(
                "This uses the existing selected-host Nmap inspection to populate "
                "detectable OS, device, product and open-port fields before OpenVAS."
            )
            st.caption(
                "Some devices block probes. SecureScope will show Not detected rather "
                "than inventing a value when Nmap cannot identify a field."
            )

            enrichment_confirmed = st.checkbox(
                "I confirm detailed Nmap inspection for the selected missing assets",
                value=False,
                key="openvas_nmap_enrichment_confirmation",
            )

            if st.button(
                "Enrich missing selected assets with Nmap",
                width="stretch",
                disabled=not missing_detail_assets or not enrichment_confirmed,
                key="openvas_enrich_missing_assets",
            ):
                enrichment_status = st.status(
                    "Enriching selected assets with Nmap…",
                    expanded=True,
                )
                enrichment_progress = st.progress(0)
                successful_enrichment = 0
                enrichment_errors: list[dict[str, str]] = []

                for asset_index, asset in enumerate(missing_detail_assets, start=1):
                    ip = str(asset.get("ip") or "")
                    enrichment_status.write(
                        f"{asset_index}/{len(missing_detail_assets)} · Inspecting {ip}"
                    )
                    try:
                        inspected = inspect_asset(ip)
                        merge_asset(st.session_state.assets, inspected)
                        successful_enrichment += 1
                    except Exception as exc:
                        enrichment_errors.append(
                            {
                                "IP": ip,
                                "Error": f"{type(exc).__name__}: {exc}",
                            }
                        )

                    enrichment_progress.progress(asset_index / len(missing_detail_assets))

                if enrichment_errors:
                    st.dataframe(
                        pd.DataFrame(enrichment_errors),
                        width="stretch",
                        hide_index=True,
                    )

                enrichment_status.update(
                    label=(
                        f"Nmap enrichment finished: {successful_enrichment} updated, "
                        f"{len(enrichment_errors)} could not be enriched"
                    ),
                    state="complete" if not enrichment_errors else "error",
                    expanded=bool(enrichment_errors),
                )
                st.session_state.openvas_selected_parallel_assets = [
                    normalize_asset(asset)
                    for asset in st.session_state.assets
                    if asset.get("ip") in {selected.get("ip") for selected in selected_assets}
                ]
                st.rerun()

        sync_to_ciso = st.checkbox(
            "Synchronize completed findings and risks to CISO Assistant",
            value=True,
            key="openvas_parallel_ciso_sync",
        )
        st.caption(
            "Parallel means all OpenVAS tasks are created and started before "
            "the app waits for results. "
            "The OpenVAS scanner may queue work internally according to its configured capacity."
        )

        with st.expander("OpenVAS submission diagnostics", expanded=False):
            st.write(
                "Run this before a large batch. It checks the SSH tunnel, GVM authentication, "
                "scan configuration, port list and scanner."
            )
            if st.button(
                "Run OpenVAS submission preflight",
                width="stretch",
                key="openvas_submission_preflight_button",
            ):
                with st.spinner("Testing OpenVAS submission prerequisites..."):
                    diagnostic = openvas_submission_preflight()

                if diagnostic.get("ok"):
                    scanner_info = diagnostic.get("scanner") or {}
                    st.success(
                        f"GVM {diagnostic.get('version')} is ready. "
                        f"Scanner verification: "
                        f"{'passed' if scanner_info.get('verified') else 'failed'}."
                    )
                    st.json(
                        {
                            "scan_config_id": diagnostic.get("config_id"),
                            "port_list_id": diagnostic.get("port_list_id"),
                            "scanner_id": diagnostic.get("scanner_id"),
                            "scanner_name": scanner_info.get("name"),
                            "scanner_status": scanner_info.get("status"),
                            "scanner_message": scanner_info.get("message"),
                        },
                        expanded=False,
                    )
                else:
                    st.error(
                        f"Preflight failed at: {diagnostic.get('error_stage')}\n\n"
                        f"{diagnostic.get('error')}"
                    )

        start_new_anyway = False
        if active_openvas_batch:
            st.warning(
                "An unfinished OpenVAS run already exists for this client. "
                "You may still create a separate scan run, including for the "
                "same IP. The new run receives new Greenbone task/report IDs."
            )
            st.caption(
                f"Active batch #{active_openvas_batch['id']} · "
                f"{active_openvas_batch.get('label')} · "
                f"status {active_openvas_batch.get('status')}"
            )
            start_new_anyway = st.checkbox(
                "Create a separate scan run",
                value=False,
                key="openvas_force_new_batch",
                help=(
                    "The existing run stays unchanged. The new run is "
                    "tracked independently by batch UUID, job UUID and task ID."
                ),
            )

        launch = st.button(
            (
                f"Start {len(launchable_assets)} asset(s) in parallel"
                if not active_openvas_batch
                else f"Start another parallel run for {len(launchable_assets)} asset(s)"
            ),
            type="primary",
            width="stretch",
            disabled=(
                not launchable_assets or (active_openvas_batch is not None and not start_new_anyway)
            ),
            key="openvas_parallel_launch",
        )

        if launch:
            st.session_state.openvas_parallel_pending_launch = True
            st.session_state.openvas_parallel_sync_ciso = sync_to_ciso
            st.session_state.openvas_parallel_scan_mode_value = scan_mode

    with tabs[1]:
        section_heading(
            "Persistent live execution",
            (
                "PostgreSQL is the source of truth. SecureScope creates every selected "
                "Greenbone task and submits all tasks in the batch up to the "
                "configured parallel limit, while preserving exact task/report IDs."
            ),
        )

        if st.session_state.pop(
            "openvas_parallel_pending_launch",
            False,
        ):
            selected_assets = st.session_state.get("openvas_selected_parallel_assets") or []
            sync_to_ciso = bool(st.session_state.get("openvas_parallel_sync_ciso", True))
            submitted_mode = str(
                st.session_state.get(
                    "openvas_parallel_scan_mode_value",
                    "Multiple assets / queued batch",
                )
            )
            submission_banner = st.status(
                "Creating workspace-scoped scan queue…",
                expanded=True,
            )

            try:
                batch = create_openvas_batch(
                    client_name,
                    label=(f"{submitted_mode} · " f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"),
                    scan_mode=submitted_mode,
                    profile_name=SCAN_CONFIG_NAME,
                    port_list_name=PORT_LIST_NAME,
                    sync_to_ciso=sync_to_ciso,
                    status="Queued",
                    dispatch_enabled=False,
                )
                batch_id = int(batch["id"])

                queued_jobs = []
                for position, asset in enumerate(selected_assets, start=1):
                    normalized = normalize_asset(asset)
                    queued_jobs.append(
                        create_or_update_openvas_job(
                            client_name,
                            batch_id=batch_id,
                            asset=normalized,
                            status="Queued",
                            ui_status="Queued",
                            provider_status="Not started",
                            stage="Preparing parallel OpenVAS batch",
                            progress=0,
                            queue_position=position,
                            result_message=(
                                "Saved in the client workspace. SecureScope will "
                                "create and start this exact Greenbone task as part "
                                "of the parallel batch launch."
                            ),
                            sync_to_ciso=sync_to_ciso,
                        )
                    )
                # Queue creation belongs to the UI because it is a short,
                # database-only transaction. Greenbone target/task creation and
                # start_task calls must never run in the Streamlit request. A
                # slow tunnel, gvmd response, or eight parallel starts previously
                # left this page stuck on "Creating workspace-scoped scan queue…".
                update_batch_counters(batch_id)
                activate_openvas_batch_dispatch(
                    batch_id,
                    exclusive=True,
                    note=(
                        "Explicit UI launch queued for background Greenbone "
                        "task creation and parallel start"
                    ),
                )

                OPENVAS_WORKER_BOOTSTRAP.start()
                if hasattr(OPENVAS_WORKER_BOOTSTRAP, "wake"):
                    OPENVAS_WORKER_BOOTSTRAP.wake(batch_id=batch_id)

                st.session_state["selected_persistent_openvas_batch_id"] = batch_id
                st.session_state["persistent_openvas_batch_id_selector"] = batch_id
                st.session_state.pop("persistent_openvas_batch_selector", None)

                submission_banner.update(
                    label=(
                        f"{len(queued_jobs)} asset(s) saved in workspace "
                        f"{client_name}. Background worker activated for batch "
                        f"#{batch_id}."
                    ),
                    state="complete",
                    expanded=False,
                )
                st.success(
                    "The workspace queue is ready. SecureScope is now creating "
                    "and starting the exact Greenbone tasks in the background; "
                    "this page no longer waits for GMP network operations."
                )
            except Exception as exc:
                submission_banner.update(
                    label="OpenVAS queue creation failed",
                    state="error",
                    expanded=True,
                )
                st.error(f"{type(exc).__name__}: {exc}")

        action_col1, action_col2, action_col3 = st.columns(
            [1, 1, 1],
            gap="small",
        )
        with action_col1:
            if st.button(
                "Process scan queue now",
                icon=":material/play_circle:",
                type="primary",
                width="stretch",
                key="manual_trigger_openvas_queue",
                help="Immediately runs a worker cycle to start queued scans.",
            ):
                with st.spinner("Creating missing Greenbone tasks and processing queue…"):
                    selected_batch_id = _coerce_openvas_batch_id(
                        st.session_state.get("selected_persistent_openvas_batch_id")
                    )
                    if selected_batch_id is None:
                        active_for_client = get_active_openvas_batch(client_name)
                        selected_batch_id = (
                            int(active_for_client["id"]) if active_for_client else None
                        )

                    preparation = (
                        prepare_openvas_tasks_for_batch(selected_batch_id)
                        if selected_batch_id is not None
                        else {
                            "created": 0,
                            "recovered": 0,
                            "failed": 0,
                            "errors": [],
                        }
                    )
                    res = trigger_openvas_queue_start_cycle()
                    if preparation.get("errors"):
                        for preparation_error in preparation["errors"]:
                            st.error(
                                f"Task creation failed for job "
                                f"#{preparation_error.get('job_id') or '?'}, "
                                f"asset "
                                f"{preparation_error.get('asset_ip') or 'unknown'}: "
                                f"{preparation_error.get('error') or 'Unknown error'}"
                            )
                    if res.get("error"):
                        st.error(
                            f"Job #{res.get('failed_job_id') or '?'} · "
                            f"{res.get('failed_asset_ip') or 'unknown asset'} · "
                            f"{res.get('failed_stage') or 'submission'}: "
                            f"{res['error']}"
                        )
                    elif res.get("started"):
                        st.success(
                            f"Created {preparation.get('created', 0)} missing "
                            f"Greenbone task(s) and started "
                            f"{res['started']} queued scan(s)."
                        )
                        st.rerun()
                    elif preparation.get("created") or preparation.get("recovered"):
                        st.success(
                            f"Created {preparation.get('created', 0)} Greenbone "
                            f"task(s); {preparation.get('recovered', 0)} existing "
                            "task(s) reattached. No additional task was started "
                            "because the protected scanner slot is occupied."
                        )
                        st.rerun()
                    else:
                        st.info(
                            "All eligible assets already have Greenbone tasks. "
                            "No new scan was started because the scanner slot is "
                            "occupied or no queued task remains."
                        )

        with action_col2:
            if st.button(
                "Recover recent Greenbone tasks",
                icon=":material/restore:",
                width="stretch",
                key="recover_existing_greenbone_tasks",
                help=(
                    "Imports existing SecureScope tasks and their reports "
                    "without calling create_task or start_task."
                ),
            ):
                with st.spinner("Reading existing Greenbone tasks without rescanning…"):
                    try:
                        recovery = recover_recent_securescope_tasks(
                            client_name,
                            limit=150,
                        )
                        if recovery.get("recovered"):
                            st.session_state["selected_persistent_openvas_batch_id"] = recovery.get(
                                "batch_id"
                            )
                            st.success(recovery.get("message"))
                            st.rerun()
                        else:
                            st.info(recovery.get("message"))
                    except Exception as exc:
                        st.error(f"Could not recover Greenbone tasks: {exc}")

        with action_col3:
            online, worker_message = _openvas_worker_summary()
            if online:
                st.success(worker_message)
            else:
                st.warning(worker_message)

        current_batches = list_openvas_batches(
            client_name,
            limit=30,
        )
        if not current_batches:
            st.markdown(
                """
                <div class="empty-state">
                    <h3>No persistent OpenVAS batch yet</h3>
                    <p>Submit a new batch or recover existing Greenbone tasks.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            batches_by_id = {int(batch["id"]): batch for batch in current_batches}
            batch_ids = list(batches_by_id)

            requested_batch_id = _coerce_openvas_batch_id(
                st.session_state.get("selected_persistent_openvas_batch_id"),
                batch_ids,
            )
            if requested_batch_id is None:
                requested_batch_id = batch_ids[0]

            selector_key = "persistent_openvas_batch_id_selector"
            selected_widget_batch_id = _coerce_openvas_batch_id(
                st.session_state.get(selector_key),
                batch_ids,
            )

            # Migrate stale state from v4.9.1/v4.9.2 before creating the widget.
            if selected_widget_batch_id != requested_batch_id:
                st.session_state[selector_key] = requested_batch_id

            # The retired label-based key must never drive the new selector.
            st.session_state.pop(
                "persistent_openvas_batch_selector",
                None,
            )

            selected_batch_value = st.selectbox(
                "OpenVAS scan run",
                batch_ids,
                key=selector_key,
                format_func=lambda value: (
                    f"#{value} · "
                    f"{batches_by_id[value].get('label')} · "
                    f"{batches_by_id[value].get('status')} · "
                    f"run {str(batches_by_id[value].get('batch_uuid') or '')[:8]} · "
                    f"{str(batches_by_id[value].get('created_at'))[:19]}"
                ),
            )
            selected_batch_id = _coerce_openvas_batch_id(
                selected_batch_value,
                batch_ids,
            )
            if selected_batch_id is None:
                # Defensive fallback for any malformed browser session state.
                selected_batch_id = requested_batch_id
                st.session_state[selector_key] = selected_batch_id
            st.session_state["selected_persistent_openvas_batch_id"] = selected_batch_id

            render_persistent_openvas_batch(selected_batch_id)

    with tabs[2]:
        st.session_state.scan_history = load_scan_history(client_name)
        pdf_records = _available_pdf_records()
        section_heading(
            "Per-asset vulnerability reports",
            "Each completed asset has its own professional PDF with findings and remediation.",
        )
        if not pdf_records:
            st.info("No generated PDF report is available yet. Complete an OpenVAS scan first.")
        else:
            report_options = {}
            for record in pdf_records:
                asset_tag = record.get("asset", {}).get("asset_tag", "Asset")
                label = f"{asset_tag} • {record.get('asset_ip')} • {record.get('scanned_at')}"
                report_options[label] = record
            selected_report_label = st.selectbox("Select report", list(report_options.keys()))
            selected_record = report_options[selected_report_label]
            selected_path = Path(selected_record["pdf_report_path"])

            severity = get_severity_counts(selected_record.get("findings") or [])
            report_cols = st.columns(4)
            for column, (label, value) in zip(
                report_cols,
                [
                    ("Findings", len(selected_record.get("findings") or [])),
                    ("Critical", severity["Critical"]),
                    ("High", severity["High"]),
                    ("Report ID", str(selected_record.get("report_id") or "")[:12]),
                ],
            ):
                with column:
                    st.metric(label, value)

            st.download_button(
                "Download selected asset PDF report",
                data=selected_path.read_bytes(),
                file_name=selected_path.name,
                mime="application/pdf",
                type="primary",
                width="stretch",
            )

            all_paths = [record["pdf_report_path"] for record in pdf_records]
            report_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            st.download_button(
                "Download all available asset PDF reports as ZIP",
                data=build_reports_zip(all_paths),
                file_name=f"securescope_openvas_reports_{report_stamp}.zip",
                mime="application/zip",
                width="stretch",
            )

            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Asset": record.get("asset", {}).get("asset_tag"),
                            "IP": record.get("asset_ip"),
                            "Scan date": record.get("scanned_at"),
                            "Findings": len(record.get("findings") or []),
                            "PDF": Path(record.get("pdf_report_path")).name,
                        }
                        for record in pdf_records
                    ]
                ),
                width="stretch",
                hide_index=True,
            )

    with tabs[3]:
        st.session_state.scan_history = load_scan_history(client_name)
        latest_records = list(st.session_state.scan_history)
        st.session_state.last_findings = (
            list(latest_records[0].get("findings") or []) if latest_records else []
        )
        st.session_state.last_openvas_report_id = (
            latest_records[0].get("report_id") if latest_records else None
        )
        _render_latest_openvas_findings()


@st.fragment
def render_scan_centre_page() -> None:
    """Render Nuclei campaigns; historical provider reports remain available.

    Returns:
        None.

    Raises:
        No exceptions are raised directly.
    """
    st.session_state["scan_engine"] = ENGINE_NUCLEI
    render_nuclei_scan_center(
        get_active_client_name(),
        [normalize_asset(asset) for asset in st.session_state.assets],
    )


@st.fragment
def render_client_history_page() -> None:
    """Render workspace asset, scan and audit history.

    Returns:
        None.

    Raises:
        ValueError: Never raised; repository failures are displayed safely.
    """

    client = get_active_client_name()
    records = list(st.session_state.scan_history)
    assets = [normalize_asset(asset) for asset in st.session_state.assets]
    total_findings = sum(len(record.get("findings", [])) for record in records)
    try:
        audit_events = list_audit_events(client)
    except ExposureRepositoryError:
        audit_events = []

    page_hero(
        "REPORTS & AUDIT",
        "Reports & Audit",
        (
            "Review the workspace asset inventory, scanner history and audited "
            "lifecycle decisions without mixing them into the current exposure dashboard."
        ),
        f"{len(records)} scan(s) saved",
        "ready" if records or assets else "neutral",
    )

    metric_cols = st.columns(4)
    with metric_cols[0]:
        dashboard_metric_card("Assets", len(assets), "Saved for this workspace", "neutral")
    with metric_cols[1]:
        dashboard_metric_card("Scans", len(records), "OpenVAS + Nuclei history", "neutral")
    with metric_cols[2]:
        dashboard_metric_card(
            "Findings",
            total_findings,
            "Raw findings across saved reports",
            "risk" if total_findings else "neutral",
        )
    with metric_cols[3]:
        dashboard_metric_card(
            "Audit events",
            len(audit_events),
            "Lifecycle and remediation decisions",
            "neutral",
        )

    section_heading(
        "Asset history",
        "Assets stored under the selected client workspace.",
    )
    if assets:
        st.dataframe(
            _asset_table_rows(assets),
            width="stretch",
            hide_index=True,
            height=360,
        )
        st.download_button(
            "Export workspace assets CSV",
            data=pd.DataFrame(_asset_table_rows(assets)).to_csv(index=False).encode("utf-8"),
            file_name=f"{client.replace(' ', '_').lower()}_asset_history.csv",
            mime="text/csv",
        )
    else:
        st.info("No assets are saved for this workspace yet.")

    section_heading(
        "Scan history",
        "Completed OpenVAS and Nuclei reports retained for this workspace.",
    )
    if records:
        scan_rows = []
        for record in records:
            findings = ensure_iso_mapping(record.get("findings", []))
            severity_counts = get_severity_counts(findings)
            scan_rows.append(
                {
                    "Date": str(record.get("scanned_at", "")).replace("T", " ")[:19],
                    "Engine": (record.get("scanner_engine") or record.get("scanner") or "OpenVAS"),
                    "Asset": (
                        record.get("asset", {}).get("asset_tag")
                        if isinstance(record.get("asset"), dict)
                        else None
                    )
                    or record.get("asset_ip", "Unknown"),
                    "Report ID": str(record.get("report_id") or "")[:12],
                    "Status": record.get("final_status", "Unknown"),
                    "Findings": len(findings),
                    "Critical": severity_counts["Critical"],
                    "High": severity_counts["High"],
                }
            )
        st.dataframe(scan_rows, width="stretch", hide_index=True, height=330)

        with st.expander("Review saved report", expanded=False):
            labels = {
                _report_option_label(record): record
                for record in sorted(
                    records,
                    key=lambda item: str(item.get("scanned_at", "")),
                    reverse=True,
                )
            }
            selected_label = st.selectbox(
                "Saved report",
                list(labels.keys()),
                key="client_history_report_selector",
            )
            record = labels[selected_label]
            findings = ensure_iso_mapping(record.get("findings", []))

            st.write(f"**Asset:** {record.get('asset_ip', 'Unknown')}")
            st.write(f"**Report ID:** {record.get('report_id', 'Unknown')}")
            st.write(f"**Status:** {record.get('final_status', 'Unknown')}")
            if findings:
                display_columns = [
                    "Severity",
                    "CVSS",
                    "Finding",
                    "CVE",
                    "Port",
                    "ISO Controls",
                    "Treatment Priority",
                ]
                st.dataframe(
                    [{key: item.get(key) for key in display_columns} for item in findings],
                    width="stretch",
                    hide_index=True,
                    height=360,
                )
            else:
                st.success("This saved report contains no findings.")

            st.download_button(
                "Export selected report JSON",
                data=json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8"),
                file_name=(
                    f"{client.replace(' ', '_').lower()}_"
                    f"{record.get('report_id', 'report')}.json"
                ),
                mime="application/json",
            )
    else:
        st.info("No vulnerability reports are saved for this workspace yet.")

    section_heading(
        "Audit trail",
        "Lifecycle, remediation and governance decisions recorded by SecureScope.",
    )
    if audit_events:
        preferred = [
            "created_at",
            "event_type",
            "entity_type",
            "entity_id",
            "actor",
            "summary",
        ]
        audit_frame = pd.DataFrame(audit_events)
        visible = [column for column in preferred if column in audit_frame.columns]
        st.dataframe(
            audit_frame[visible] if visible else audit_frame,
            width="stretch",
            hide_index=True,
            height=min(480, 90 + len(audit_events) * 35),
        )
    else:
        st.caption("No lifecycle or remediation audit event has been recorded yet.")


def _wazuh_env_summary() -> dict[str, str]:
    """Return non-secret Wazuh configuration status for UI display."""
    from securescope.ui.integration_presentation import configured_value

    api_url = os.getenv("WAZUH_API_URL", "")
    indexer_url = os.getenv("WAZUH_INDEXER_URL", "")
    return {
        "API URL": api_url or "Not configured",
        "API user": os.getenv("WAZUH_API_USER", "Not configured"),
        "API password": (
            "Provided"
            if configured_value(os.getenv("WAZUH_API_PASSWORD"))
            else "Missing / placeholder"
        ),
        "TLS verify": os.getenv("WAZUH_VERIFY_TLS", "true"),
        "Indexer URL": indexer_url or "Optional / not configured",
        "Indexer user": os.getenv("WAZUH_INDEXER_USER", "Optional / not configured"),
        "Indexer password": (
            "Provided"
            if configured_value(os.getenv("WAZUH_INDEXER_PASSWORD"))
            else "Optional / missing"
        ),
    }


def _wazuh_excel_bytes(
    client_name: str,
    monitoring_df: pd.DataFrame,
    evidence_df: pd.DataFrame,
    clock_df: pd.DataFrame | None = None,
) -> bytes:
    """Create an Excel workbook for Wazuh and ISO evidence."""
    buffer = BytesIO()
    clock_frame = clock_df if clock_df is not None else pd.DataFrame()

    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        summary_rows = [
            {"Metric": "Client", "Value": client_name},
            {"Metric": "Monitoring rows", "Value": len(monitoring_df)},
            {
                "Metric": "Assets with verified monitoring",
                "Value": (
                    int((monitoring_df.get("monitoring_status") == "Monitoring verified").sum())
                    if (not monitoring_df.empty and "monitoring_status" in monitoring_df)
                    else 0
                ),
            },
            {
                "Metric": "Assets with monitoring not verified",
                "Value": (
                    int((monitoring_df.get("monitoring_status") == "Monitoring not verified").sum())
                    if (not monitoring_df.empty and "monitoring_status" in monitoring_df)
                    else 0
                ),
            },
            {
                "Metric": "Assets with clock evidence",
                "Value": (
                    int((clock_frame.get("Status") != "No evidence").sum())
                    if not clock_frame.empty and "Status" in clock_frame
                    else 0
                ),
            },
        ]
        pd.DataFrame(summary_rows).to_excel(
            writer,
            sheet_name="Summary",
            index=False,
        )

        if monitoring_df.empty:
            pd.DataFrame([{"message": "No Wazuh data collected yet"}]).to_excel(
                writer,
                sheet_name="Wazuh Monitoring",
                index=False,
            )
        else:
            monitoring_df.to_excel(
                writer,
                sheet_name="Wazuh Monitoring",
                index=False,
            )

        if clock_frame.empty:
            pd.DataFrame([{"message": "No clock evidence collected yet"}]).to_excel(
                writer,
                sheet_name="Clock Evidence",
                index=False,
            )
        else:
            clock_frame.to_excel(
                writer,
                sheet_name="Clock Evidence",
                index=False,
            )

        if evidence_df.empty:
            pd.DataFrame([{"message": "No ISO evidence collected yet"}]).to_excel(
                writer,
                sheet_name="ISO Evidence",
                index=False,
            )
        else:
            evidence_df.to_excel(
                writer,
                sheet_name="ISO Evidence",
                index=False,
            )

    return buffer.getvalue()


@st.fragment
def render_siem_wazuh_page() -> None:
    """Render Wazuh SIEM integration directly inside the main SecureScope app."""
    page_hero(
        "SIEM MONITORING",
        "SIEM & Wazuh",
        (
            "Collect Wazuh agents, match them with SecureScope assets, store "
            "monitoring status in PostgreSQL, "
            "and generate ISO 27001 A.8.15/A.8.16 evidence."
        ),
        "Wazuh SIEM",
        "ready",
    )

    if not WAZUH_INTEGRATION_AVAILABLE:
        st.error(f"Wazuh integration files are missing or cannot be imported: {WAZUH_IMPORT_ERROR}")
        st.info(
            (
                "Copy wazuh_service.py and db_wazuh_service.py into this folder, "
                "then install requirements_wazuh.txt."
            )
        )
        return

    from securescope.integrations.credential_store import CredentialStoreError
    from securescope.integrations.wazuh_service import restore_wazuh_settings

    try:
        restore_wazuh_settings()
    except CredentialStoreError as exc:
        st.error(str(exc))
        return
    client = get_active_client_name()
    env = _wazuh_env_summary()
    from securescope.ui.integration_presentation import (
        api_configuration_status,
        integration_summary,
    )

    connection_status = api_configuration_status(
        os.getenv("WAZUH_API_URL", ""),
        os.getenv("WAZUH_API_USER", ""),
        os.getenv("WAZUH_API_PASSWORD", ""),
    )
    connection_card = st.empty()
    with connection_card.container():
        integration_summary(
            "Wazuh SIEM",
            connection_status,
            "Configure the API, then test the connection before collecting evidence.",
        )
    with st.expander("Technical details"):
        st.table([{"Setting": label, "Value": value} for label, value in env.items()])

    from securescope.ui.wazuh_settings_ui import render_wazuh_settings

    with st.expander("Wazuh actions · Configuration and asset bindings"):
        render_wazuh_settings(client)
        from securescope.ui.grc_workspace.context import current_actor
        from securescope.ui.wazuh_monitoring_ui import render_monitoring_bindings

        render_monitoring_bindings(client, current_actor())
        from securescope.ui.wazuh_monitoring_ui import render_collection_schedules

        render_collection_schedules(client, current_actor())
    from securescope.ui.evidence_collection_context import (
        current_collection_context,
        render_collection_return,
    )

    render_collection_return(client)

    import hashlib

    from securescope.evidence.wazuh_bridge import ingest_wazuh_evidence
    from securescope.persistence.evidence_repository import get_workspace_role
    from securescope.ui.grc_workspace.context import current_actor

    configured = all(
        os.getenv(name, "").strip()
        for name in ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
    )
    signature = hashlib.sha256(
        "|".join(
            os.getenv(name, "")
            for name in (
                "WAZUH_API_URL",
                "WAZUH_API_USER",
                "WAZUH_API_PASSWORD",
                "WAZUH_VERIFY_TLS",
                "WAZUH_INDEXER_URL",
                "WAZUH_INDEXER_USER",
                "WAZUH_INDEXER_PASSWORD",
                "WAZUH_INDEXER_VERIFY_TLS",
            )
        ).encode("utf-8")
    ).hexdigest()
    verified_key = f"wazuh_verified::{client}"
    connected = st.session_state.get(verified_key) == signature
    if connected:
        with connection_card.container():
            integration_summary(
                "Wazuh SIEM",
                "Connection tested",
                "Last connection test succeeded; collection rechecks source health.",
            )
    if st.session_state.pop(verified_key + "::notice", False):
        st.success("Wazuh API connection verified. Evidence collection is available.")
    can_collect = get_workspace_role(client, current_actor()) in {"Administrator", "Consultant"}
    action_cols = st.columns(2)
    with action_cols[0]:
        test_clicked = st.button(
            "Test Connection",
            width="stretch",
            disabled=not configured,
            type="secondary" if connected else "primary",
        )
    with action_cols[1]:
        collect_clicked = st.button(
            "Collect Wazuh Evidence",
            width="stretch",
            disabled=not (connected and can_collect),
            type="primary" if connected else "secondary",
        )

    if test_clicked:
        try:
            wazuh = WazuhClient()
            wazuh.test_connection()
            st.session_state[verified_key] = signature
            st.session_state[verified_key + "::notice"] = True
            st.rerun()
        except Exception as exc:
            st.session_state.pop(verified_key, None)
            with connection_card.container():
                integration_summary(
                    "Wazuh SIEM",
                    "Connection issue",
                    "Connection test failed. Review the configuration and test again.",
                )
            st.error("Wazuh API connection test failed.")
            with st.expander("Connection diagnostics"):
                st.caption(display_tool_output(str(exc)))

    if collect_clicked:
        from securescope.integrations.wazuh_collection import collect_monitoring
        from securescope.integrations.wazuh_service import WazuhError
        from securescope.persistence.evidence_repository import EvidenceRepositoryError

        try:
            with st.spinner("Verifying bound assets and source telemetry..."):
                result = collect_monitoring(
                    client, current_actor(), current_collection_context(client)
                )
            message = (
                f"Collection {result['outcome']}. "
                f"{len(result['evidence_ids'])} canonical evidence records available."
            )
            if result["outcome"] == "succeeded":
                st.success(message)
            else:
                st.warning(message + " Inspect source health and monitoring reasons below.")
        except (WazuhError, WazuhDatabaseError, EvidenceRepositoryError) as exc:
            st.error(f"Wazuh collection unavailable: {exc}")

    try:
        rows = load_latest_wazuh_status(client)
    except Exception as exc:
        rows = []
        st.warning(f"No Wazuh snapshot is available yet: {exc}")

    section_heading(
        "Asset monitoring status", "Saved monitoring evidence matched to the committed inventory."
    )
    if not rows:
        st.info("No Wazuh data saved yet. Use 'Collect Wazuh Evidence'.")
        return

    df = pd.DataFrame(rows)
    display_cols = [
        "asset_ip",
        "asset_hostname",
        "asset_tag",
        "monitoring_status",
        "monitoring_reason",
        "source_health",
        "last_verified_at",
        "verified_until",
        "match_type",
        "wazuh_agent_id",
        "wazuh_agent_name",
        "wazuh_agent_ip",
        "wazuh_status",
        "wazuh_last_keep_alive",
        "wazuh_os",
        "last_action",
        "last_alert_time",
    ]
    display_cols = [col for col in display_cols if col in df.columns]

    monitored = (
        int((df.get("monitoring_status") == "Monitoring verified").sum())
        if "monitoring_status" in df
        else 0
    )
    inactive = (
        int((df.get("monitoring_status") == "Agent disconnected").sum())
        if "monitoring_status" in df
        else 0
    )

    status_cols = st.columns(4)
    with status_cols[0]:
        dashboard_metric_card("Assets", len(df), "Workspace inventory", "neutral")
    with status_cols[1]:
        dashboard_metric_card("Verified", monitored, "Current authenticated telemetry", "ready")
    with status_cols[2]:
        dashboard_metric_card(
            "Not verified", len(df) - monitored, "Review source state and evidence", "neutral"
        )
    with status_cols[3]:
        dashboard_metric_card(
            "Inactive", inactive, "Disconnected agent", "risk" if inactive else "neutral"
        )

    readable_table(df[display_cols], key=f"wazuh_monitoring::{client}")
    from securescope.ui.wazuh_monitoring_ui import render_monitoring_detail

    render_monitoring_detail(rows, client)

    section_heading(
        "Clock synchronization evidence — ISO A.8.17",
        (
            "Compare endpoint time-service evidence with the Wazuh manager "
            "receipt timestamp for every Nmap asset."
        ),
    )

    clock_actions = st.columns(2)
    with clock_actions[0]:
        collect_clock_clicked = st.button(
            "Collect Wazuh clock evidence",
            type="primary",
            width="stretch",
            key="wazuh_page_collect_clock_evidence",
        )
    with clock_actions[1]:
        clock_guide = WAZUH_ROOT / "README_NTP.md"
        if clock_guide.exists():
            st.download_button(
                "Download clock-evidence deployment guide",
                data=clock_guide.read_bytes(),
                file_name="SecureScope_Wazuh_Clock_Deployment.md",
                mime="text/markdown",
                width="stretch",
            )
        else:
            st.button(
                "Deployment guide unavailable",
                disabled=True,
                width="stretch",
            )

    clock_assets = load_asset_inventory(client)
    if collect_clock_clicked:
        try:
            with st.spinner("Collecting SECURESCOPE_NTP events from Wazuh Indexer…"):
                raw_clock_evidence = collect_wazuh_ntp_evidence(limit=5000)
                clock_assets = match_clock_evidence_to_assets(
                    clock_assets,
                    raw_clock_evidence,
                    agent_rows=rows,
                )
                evidence_to_store = [
                    asset for asset in clock_assets if asset.get("clock_evidence_source")
                ]
                for asset in evidence_to_store:
                    asset["clock_sync_status"] = apply_clock_status(asset)
                saved_clock_rows = save_clock_evidence(
                    client,
                    evidence_to_store,
                )
                ingest_wazuh_evidence(client, current_actor(), current_collection_context(client))
                save_asset_inventory(clock_assets, client)
                if client == get_active_client_name():
                    st.session_state.assets = [normalize_asset(asset) for asset in clock_assets]
            st.success(
                f"Stored fresh clock evidence for "
                f"{saved_clock_rows}/{len(clock_assets)} asset(s)."
            )
            st.rerun()
        except (
            NtpAuditError,
            ClockEvidenceDatabaseError,
            DatabaseError,
        ) as exc:
            st.error(f"Clock evidence collection failed: {exc}")
        except Exception as exc:
            st.error(f"Clock evidence collection failed: " f"{type(exc).__name__}: {exc}")

    try:
        persisted_clock_rows = load_latest_clock_evidence(client)
    except ClockEvidenceDatabaseError as exc:
        persisted_clock_rows = []
        st.warning(f"Clock evidence is unavailable: {exc}")

    clock_assets = match_clock_evidence_to_assets(
        clock_assets,
        persisted_clock_rows,
        agent_rows=rows,
    )
    clock_summary = fleet_clock_summary(clock_assets)
    clock_export_df = pd.DataFrame(clock_evidence_table(clock_assets))

    clock_metrics = st.columns(5)
    clock_values = [
        ("Assets", clock_summary["assets_total"]),
        (
            "With evidence",
            clock_summary["assets_with_endpoint_evidence"],
        ),
        ("Synchronized", clock_summary["synchronized_assets"]),
        ("Clock gaps", clock_summary["gap_assets"]),
        ("Fleet state", clock_summary["status"]),
    ]
    for column, (label, value) in zip(
        clock_metrics,
        clock_values,
    ):
        with column:
            dashboard_metric_card(
                label,
                value,
                "Wazuh endpoint clock assurance",
                ("ready" if label == "Fleet state" and value == "Synchronized" else "neutral"),
            )

    if persisted_clock_rows:
        st.dataframe(
            clock_export_df,
            width="stretch",
            hide_index=True,
            height=340,
        )
    else:
        st.info(
            "No endpoint clock evidence is stored. Deploy the scripts in "
            "the integrations/wazuh/ folder, wait for one collection interval and collect "
            "the evidence again."
        )

    section_heading(
        "ISO 27001 monitoring evidence",
        "Evidence generated from Wazuh coverage for logging and monitoring controls.",
    )
    evidence_rows = [build_iso_evidence_from_wazuh(rows)]
    evidence_df = pd.DataFrame(evidence_rows)
    if not evidence_df.empty:
        evidence_cols = [
            "control_id",
            "control_name",
            "status",
            "evidence",
            "source",
            "collected_at",
        ]
        evidence_cols = [col for col in evidence_cols if col in evidence_df.columns]
        st.dataframe(evidence_df[evidence_cols], width="stretch", hide_index=True, height=260)
    else:
        st.info("No ISO evidence saved yet.")

    export_cols = st.columns(2)
    with export_cols[0]:
        st.download_button(
            "Export Wazuh monitoring CSV",
            data=df[display_cols].to_csv(index=False).encode("utf-8-sig"),
            file_name=f"{client.replace(' ', '_').lower()}_wazuh_monitoring.csv",
            mime="text/csv",
            width="stretch",
        )
    with export_cols[1]:
        st.download_button(
            "Export Wazuh evidence Excel",
            data=_wazuh_excel_bytes(
                client,
                df[display_cols],
                evidence_df,
                clock_export_df,
            ),
            file_name=f"{client.replace(' ', '_').lower()}_wazuh_iso_evidence.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            width="stretch",
        )


def initialize_session_state() -> None:
    """Initialize Streamlit session state values once."""
    clients = load_clients()
    if notice := st.session_state.pop("workspace_deletion_notice", None):
        st.warning(notice)
    if not clients:
        st.title("Create your client workspace")
        st.info("No client workspaces remain. Deleted workspaces are not automatically recreated.")
        with st.form("empty_workspace_create"):
            name = st.text_input("New client name")
            create = st.form_submit_button("Create workspace", type="primary")
        if create and name.strip():
            ensure_client_exists(name)
            st.rerun()
        st.stop()
    if st.session_state.get("active_client_name") not in clients:
        for key in list(st.session_state):
            del st.session_state[key]
        st.session_state.active_client_name = clients[0]

    defaults: dict[str, Any] = {
        "clients": load_clients(),
        "assets": load_asset_inventory(st.session_state.active_client_name),
        "selected_ip": None,
        "last_discovery_ips": [],
        "last_ciso_asset_id": None,
        "last_openvas_report_id": None,
        "last_findings": [],
        "scan_history": load_scan_history(st.session_state.active_client_name),
        "last_openvas_batch_results": [],
        "openvas_selected_parallel_assets": [],
        "openvas_parallel_pending_launch": False,
        "openvas_parallel_sync_ciso": True,
        "scan_engine": default_engine(ENABLED_SCAN_ENGINES),
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    if st.session_state.get("app_navigation") == "3 · OpenVAS Scan Center":
        st.session_state["app_navigation"] = "3 · Scan Center"
    st.session_state["scan_engine"] = persist_engine_selection(
        st.session_state,
        st.session_state.get("scan_engine"),
        ENABLED_SCAN_ENGINES,
    )


initialize_session_state()
apply_securescope_ui_theme()


def _page_renderers() -> dict[str, Any]:
    """Build zero-argument renderers for modern Streamlit page routing.

    Returns:
        Stable SecureScope route keys mapped to page callables.

    Raises:
        No exceptions are raised while constructing the mapping. Page-specific
        failures remain inside their existing UI error boundaries.
    """

    from securescope.ui.policy_workspace import render_policies_page

    return {
        "Risk": lambda: render_risk_page(get_active_client_name()),
        "Calendar": lambda: render_calendar_page(
            get_active_client_name(), on_open_client=switch_client_workspace
        ),
        "Policies": lambda: render_policies_page(get_active_client_name()),
        "ISO Command Center": lambda: render_iso_command_center(get_active_client_name()),
        "Programme Setup": lambda: render_grc_workspace(get_active_client_name()),
        "ISO Evidence Hub": lambda: render_iso_evidence_hub(get_active_client_name()),
        "Overview": render_overview_page,
        "2 · Asset Management": render_asset_management_page,
        "1 · Asset Discovery": render_asset_discovery_page,
        "3 · Scan Center": render_scan_centre_page,
        "4 · Reports & Findings": lambda: render_vulnerabilities_page(
            get_active_client_name(),
            list(st.session_state.scan_history),
        ),
        "Remediation": lambda: render_remediation_page(
            get_active_client_name(),
            list(st.session_state.scan_history),
        ),
        "5 · SIEM & Wazuh": render_siem_wazuh_page,
        "6 · ISO 27001 Assessment": render_iso_mapping_page,
        "Gap Assessment": lambda: render_gap_assessment_page(
            get_active_client_name(),
            list(st.session_state.assets),
        ),
        "Client History": render_client_history_page,
        "Client Workspace": render_client_workspace_page,
    }


page_registry = build_page_registry(_page_renderers())
configure_page_registry(page_registry)
selected_page = run_hidden_navigation(page_registry)
selected_navigation_key = active_navigation_key(selected_page, page_registry)
render_app_sidebar(page_registry, selected_navigation_key)
if selected_navigation_key != "Programme Setup":
    from securescope.ui.grc_workspace.context import render_context_or_error

    render_context_or_error(get_active_client_name())
selected_page.run()
