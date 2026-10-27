"""Render the actual SIEM route with synthetic read-only service boundaries.

Run only for UI validation. No database, Wazuh or clock collector is contacted.
The application route and Components v2 renderer are loaded from current source.
"""

import ast
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

from securescope.integrations import wazuh_collection, wazuh_service
from securescope.integrations.ntp_audit_service import (
    clock_evidence_table,
    fleet_clock_summary,
    match_clock_evidence_to_assets,
)
from securescope.integrations.wazuh_service import build_iso_evidence_from_wazuh
from securescope.paths import WAZUH_ROOT
from securescope.persistence import evidence_repository
from securescope.persistence.db_service import DatabaseError
from securescope.persistence.db_wazuh_service import WazuhDatabaseError
from securescope.ui import evidence_collection_context
from securescope.ui.components.primitives import metric_card, panel_heading
from securescope.ui.grc_workspace import context
from securescope.ui.securescope_ui_theme import apply_securescope_ui_theme

st.set_page_config(page_title="SecureScope · synthetic SIEM validation", layout="wide")
apply_securescope_ui_theme()
st.caption("SYNTHETIC VALIDATION FIXTURES · no live Wazuh or production data")
logger = logging.getLogger("m4-siem-fixture")
WAZUH_INTEGRATION_AVAILABLE = True
WAZUH_IMPORT_ERROR = None
dashboard_metric_card = metric_card
for key, value in {
    "WAZUH_API_URL": "https://manager.example.test",
    "WAZUH_API_USER": "fixture",
    "WAZUH_API_PASSWORD": "fixture-only",
}.items():
    os.environ[key] = value


def get_active_client_name():
    """Return the synthetic test workspace."""
    return "Validation workspace"


context.current_actor = lambda: "fixture@example.invalid"
evidence_repository.get_workspace_role = lambda *args: "Consultant"
wazuh_service.restore_wazuh_settings = lambda: None
evidence_collection_context.render_collection_return = lambda *args: None
wazuh_collection.collect_monitoring = lambda *args: {
    "outcome": "succeeded",
    "evidence_ids": [101, 102],
}


class WazuhClient:
    """Connection fixture; never performs a network request."""

    def test_connection(self):
        """Synthetic connection success for menu state testing only."""
        return None


def load_latest_wazuh_status(client):
    """Return labeled fixtures covering every existing monitoring state."""
    now = datetime.now(timezone.utc)
    states = [
        "verified",
        "verified",
        "active_unverified",
        "disconnected",
        "stale",
        "not_verified",
        "source_unavailable",
    ]
    reasons = [
        "Fresh security telemetry",
        "Fresh positive collection-health observation; zero security alerts",
        "Active heartbeat without qualifying telemetry",
        "Agent disconnected",
        "Verification expired",
        "No approved binding",
        "Source health unavailable",
    ]
    rows = []
    for n, (state, reason) in enumerate(zip(states, reasons), 1):
        rows.append(
            dict(
                asset_id=n,
                asset_tag=f"FIXTURE-{n:02d}",
                asset_ip=f"192.0.2.{n}",
                asset_hostname=f"fixture-{n}.example.test",
                monitoring_state=state,
                monitoring_status=state,
                monitoring_reason=reason,
                identity_verified=n != 6,
                binding_id=n if n != 6 else None,
                wazuh_agent_id=f"{n:03d}",
                wazuh_agent_name=f"Fixture agent {n}",
                wazuh_status="disconnected" if n == 4 else "active",
                source_health="unavailable" if n == 7 else "healthy",
                connector_id=1,
                manager_name="Synthetic manager",
                source_key=f"fixture:observation:{n}",
                payload_sha256=hashlib.sha256(f"synthetic-observation-{n}".encode()).hexdigest(),
                collected_at=now.isoformat(),
                wazuh_last_keep_alive=now.isoformat(),
                last_verified_at=now.isoformat() if n <= 2 else None,
                verified_until=(now + timedelta(minutes=20)).isoformat() if n <= 2 else None,
                last_alert_time=None if n == 2 else now.isoformat(),
                telemetry=(
                    {
                        "kind": "collection_health" if n == 2 else "security_event",
                        "observed_at": now.isoformat(),
                        "collection_verified": True,
                        "healthy": True,
                    }
                    if n <= 2
                    else {}
                ),
            )
        )
    return rows


def load_asset_inventory(*args):
    """Return an empty synthetic clock inventory; no database access or errors."""
    return []


def load_latest_clock_evidence(*args):
    """Return no clock fixtures; A.8.17 identity validation is excluded."""
    return []


source_path = Path(__file__).resolve().parents[2] / "src/securescope/app.py"
source = ast.parse(source_path.read_text())
selected = [
    node
    for node in source.body
    if isinstance(node, ast.FunctionDef)
    and node.name
    in {"render_siem_wazuh_page", "section_heading", "_wazuh_excel_bytes", "_wazuh_env_summary"}
]
namespace = dict(
    globals(),
    BytesIO=BytesIO,
    pd=pd,
    clock_evidence_table=clock_evidence_table,
    fleet_clock_summary=fleet_clock_summary,
    match_clock_evidence_to_assets=match_clock_evidence_to_assets,
    build_iso_evidence_from_wazuh=build_iso_evidence_from_wazuh,
    WAZUH_ROOT=WAZUH_ROOT,
    DatabaseError=DatabaseError,
    WazuhDatabaseError=WazuhDatabaseError,
    panel_heading=panel_heading,
)
exec(compile(ast.Module(body=selected, type_ignores=[]), str(source_path), "exec"), namespace)
namespace["render_siem_wazuh_page"]()
