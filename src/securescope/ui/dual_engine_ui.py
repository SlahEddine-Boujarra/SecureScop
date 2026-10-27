"""OpenVAS and Nuclei dashboard and Nuclei Scan Center for SecureScope.

The mature OpenVAS workflow remains in :mod:`app_ciso_nmap`. This module adds
ProjectDiscovery Nuclei as a local CLI provider. PostgreSQL is the source of
truth; Streamlit never owns the Nuclei process lifecycle.
"""

from __future__ import annotations

import html
import os
import re
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from securescope.core.output_sanitizer import display_tool_output, extract_semantic_version
from securescope.core.scanner_engine_service import (
    ENGINE_NUCLEI,
    ENGINE_OPENVAS,
    enabled_engines,
    engine_description,
    normalize_engine,
    persist_engine_selection,
)
from securescope.persistence.nuclei_persistence import (
    NucleiDatabaseError,
    create_nuclei_batch,
)
from securescope.persistence.nuclei_persistence import get_worker_state as get_nuclei_worker_state
from securescope.persistence.nuclei_persistence import (
    list_nuclei_batches,
    list_nuclei_job_events,
    load_nuclei_batch_jobs,
    request_nuclei_worker_wake,
    retry_nuclei_job,
)
from securescope.persistence.openvas_persistence import get_worker_state as get_openvas_worker_state
from securescope.persistence.openvas_persistence import (
    list_openvas_batches,
    load_openvas_batch_jobs,
)
from securescope.reporting.dual_engine_report import DualEngineReportError, ensure_report_bundle
from securescope.scanners.nuclei.nuclei_client import NucleiClient, NucleiError, profile_options
from securescope.scanners.openvas.openvas_worker_service import probe_gmp_tunnel
from securescope.ui.components.navigation import module_tabs
from securescope.ui.components.primitives import empty_state, metric_card

ACTIVE_NUCLEI_STATUSES = {"Starting", "Running", "Processing", "Finalizing"}
NUCLEI_ATTENTION_STATUSES = {"Failed", "Interrupted", "Stopped", "Abandoned"}
OPENVAS_TERMINAL_STATUSES = {
    "Completed",
    "Recovered report",
    "Done",
    "Failed",
    "Stopped",
    "Interrupted",
    "Submission failed",
    "Submission blocked",
    "Abandoned",
    "Cancelled",
}


def _safe(value: Any) -> str:
    """Escape one value for small HTML fragments."""

    return html.escape(str(value or "—"))


def _slug(value: Any) -> str:
    """Return a stable widget-key fragment."""

    return re.sub(r"[^a-zA-Z0-9_-]+", "_", str(value or "item"))


def _format_datetime(value: Any) -> str:
    """Format a PostgreSQL timestamp for tables."""

    if not value:
        return "—"
    try:
        return pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def report_action_value(engine: str, job: dict[str, Any]) -> str | None:
    """Return the official Material PDF action label when a report is ready."""

    status = str(job.get("ui_status") or job.get("status") or "")
    path_value = str(
        job.get("report_path") or job.get("pdf_path") or job.get("pdf_report_path") or ""
    ).strip()
    if path_value and Path(path_value).is_file():
        return ":material/picture_as_pdf:"
    if engine == ENGINE_NUCLEI and status == "Completed":
        return ":material/picture_as_pdf:"
    if engine == ENGINE_OPENVAS and status in {"Completed", "Recovered report", "Done"}:
        return ":material/picture_as_pdf:"
    return None


def _report_severity_counts(record: dict[str, Any]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in list(record.get("findings") or []):
        severity = str((finding or {}).get("Severity") or "Info")
        counts[severity if severity in counts else "Info"] += 1
    return counts


def render_scan_report_panel(
    client_name: str,
    engine: str,
    job: dict[str, Any],
    *,
    key: str,
    selection_state_key: str | None = None,
) -> None:
    """Render a report preview and PDF-copy downloads for one scan-table row."""

    selection_key = f"scan_report_panel_{_slug(key)}"
    with st.container(border=True):
        heading, close_col = st.columns([8, 1], vertical_alignment="center")
        with heading:
            st.markdown("##### :material/picture_as_pdf: Scan report")
            st.caption(
                f"{engine} · {job.get('asset_tag') or 'Asset'} · "
                f"{job.get('asset_ip') or 'Unknown target'}"
            )
        with close_col:
            if st.button(
                "Close",
                icon=":material/close:",
                type="tertiary",
                key=f"close_{selection_key}",
                help="Close the selected report panel.",
            ):
                st.session_state.pop(selection_state_key or selection_key, None)
                st.rerun(scope="fragment")

        try:
            bundle = ensure_report_bundle(client_name, engine, job)
        except DualEngineReportError as exc:
            st.info(str(exc), icon=":material/hourglass_top:")
            return
        except Exception as exc:
            st.error(
                f"Report preparation failed: {type(exc).__name__}: {exc}",
                icon=":material/error:",
            )
            return

        record = dict(bundle.get("combined_record") or {})
        counts = _report_severity_counts(record)
        metrics = st.columns(5, gap="small")
        metrics[0].metric("Engines", len(bundle.get("engines") or []))
        metrics[1].metric("Findings", len(record.get("findings") or []))
        metrics[2].metric("Critical", counts["Critical"])
        metrics[3].metric("High", counts["High"])
        metrics[4].metric("Medium", counts["Medium"])

        provider_path = Path(bundle["provider_path"])
        combined_path = Path(bundle["combined_path"])
        engines = list(bundle.get("engines") or [])
        download_columns = st.columns(2 if len(engines) > 1 else 1, gap="small")
        with download_columns[0]:
            st.download_button(
                "Download scan PDF copy",
                data=provider_path.read_bytes(),
                file_name=provider_path.name,
                mime="application/pdf",
                icon=":material/download:",
                type="primary",
                width="stretch",
                on_click="ignore",
                key=f"provider_pdf_{selection_key}",
            )
        if len(engines) > 1:
            with download_columns[1]:
                st.download_button(
                    "Download combined OpenVAS + Nuclei PDF",
                    data=combined_path.read_bytes(),
                    file_name=combined_path.name,
                    mime="application/pdf",
                    icon=":material/download:",
                    width="stretch",
                    on_click="ignore",
                    key=f"combined_pdf_{selection_key}",
                )

        preview_path = combined_path if len(engines) > 1 else provider_path
        with st.expander(":material/preview: Preview PDF", expanded=False):
            st.iframe(preview_path, height=680)


def report_pdf_bytes(client_name: str, engine: str, job: dict[str, Any]) -> bytes:
    """Prepare a provider PDF only when its download icon is clicked.

    Args:
        client_name: Active workspace.
        engine: Canonical provider name.
        job: Completed workspace-owned scan job.
    Returns:
        PDF bytes for the selected job.
    Raises:
        DualEngineReportError: If the report is unavailable or outside the workspace.
        OSError: If the prepared PDF cannot be read.
    """
    bundle = ensure_report_bundle(client_name, engine, job)
    return Path(bundle["provider_path"]).read_bytes()


def render_report_downloads(
    client_name: str, engine: str, jobs: list[dict[str, Any]], *, key: str
) -> None:
    """Place one direct download icon beside each completed asset scan.

    Args:
        client_name: Active workspace.
        engine: Canonical provider name.
        jobs: Current batch jobs.
        key: Unique component prefix.
    Returns:
        None.
    Raises:
        No exceptions are raised directly; generation errors appear on download.
    """
    ready = [job for job in jobs if report_action_value(engine, job)]
    if not ready:
        return
    st.markdown("**Completed scan reports**")
    st.caption("Download the prepared PDF directly beside the asset.")
    pages = max(1, (len(ready) + 9) // 10)
    page = int(st.number_input("Report page", 1, pages, 1, key=key + "::page")) if pages > 1 else 1
    for job in ready[(page - 1) * 10 : page * 10]:
        asset, status, download = st.columns([3, 2, 0.5], vertical_alignment="center")
        asset.write(f"**{job.get('asset_tag') or 'Asset'}** · {job.get('asset_ip') or ''}")
        status.caption(f"{job.get('findings_count') or 0} findings · job {job['id']}")
        try:
            # Reuse the provider-generated PDF when it exists. Older jobs may
            # only have a history record, so prepare the provider copy here.
            stored_path = Path(
                str(
                    job.get("report_path")
                    or job.get("pdf_path")
                    or job.get("pdf_report_path")
                    or ""
                )
            )
            data = (
                stored_path.read_bytes()
                if stored_path.is_file()
                else report_pdf_bytes(client_name, engine, dict(job))
            )
        except (DualEngineReportError, OSError, ValueError) as exc:
            download.button(
                "",
                icon=":material/download:",
                disabled=True,
                help=f"Report unavailable: {display_tool_output(str(exc))}",
                key=f"{key}::unavailable::{job['id']}",
            )
            continue
        download.download_button(
            "",
            data=data,
            file_name=f"{_slug(job.get('asset_tag') or job.get('asset_ip'))}"
            f"_{engine}_{job['id']}.pdf",
            mime="application/pdf",
            icon=":material/download:",
            help="Download this asset's scan report",
            on_click="ignore",
            key=f"{key}::pdf::{job['id']}",
        )


def _worker_healthy(worker: dict[str, Any] | None, max_age: int = 35) -> bool:
    """Return whether a persisted worker heartbeat is recent and running."""

    if not worker:
        return False
    try:
        age = int(worker.get("heartbeat_age_seconds") or 999999)
    except (TypeError, ValueError):
        age = 999999
    return str(worker.get("status") or "").lower() == "running" and age <= max_age


@st.cache_data(ttl=15, show_spinner=False)
def nuclei_engine_health() -> dict[str, Any]:
    """Return bounded, redacted Nuclei CLI and template health."""

    try:
        return NucleiClient().health()
    except NucleiError as exc:
        return {
            "ok": False,
            "binary": "Nuclei CLI",
            "version": "",
            "templates_version": "",
            "template_directory": "Configured templates",
            "api_key_required": False,
            "dashboard_upload": False,
            "message": display_tool_output(f"{type(exc).__name__}: {exc}"),
        }
    except Exception as exc:
        return {
            "ok": False,
            "binary": "Nuclei CLI",
            "version": "",
            "templates_version": "",
            "template_directory": "Configured templates",
            "api_key_required": False,
            "dashboard_upload": False,
            "message": display_tool_output(f"{type(exc).__name__}: {exc}"),
        }


def test_nuclei_connection() -> str:
    """Run read-only local Nuclei version and template checks."""

    nuclei_engine_health.clear()
    health = nuclei_engine_health()
    if not health.get("ok"):
        raise NucleiError(str(health.get("message") or "Nuclei health check failed."))
    return (
        f"Nuclei ready · {health.get('version') or 'version not reported'} · "
        f"templates {health.get('templates_version') or 'not reported'}"
    )


def _openvas_health() -> dict[str, Any]:
    """Return non-fatal OpenVAS tunnel and worker health."""

    try:
        tunnel_ok, tunnel_message = probe_gmp_tunnel()
    except Exception as exc:
        tunnel_ok = False
        tunnel_message = display_tool_output(f"{type(exc).__name__}: {exc}")
    try:
        worker = get_openvas_worker_state(os.getenv("OPENVAS_WORKER_NAME", "openvas-monitor"))
    except Exception as exc:
        worker = {}
        tunnel_message = f"{tunnel_message}; worker: {type(exc).__name__}: {exc}"
    return {
        "ready": bool(tunnel_ok),
        "worker_healthy": _worker_healthy(worker),
        "worker": worker or {},
        "message": tunnel_message,
    }


def _nuclei_health() -> dict[str, Any]:
    """Return Nuclei CLI and standalone-worker health."""

    engine = nuclei_engine_health()
    try:
        worker = get_nuclei_worker_state()
    except Exception:
        worker = {}
    return {
        "ready": bool(engine.get("ok")),
        "worker_healthy": _worker_healthy(worker),
        "worker": worker or {},
        "engine": engine,
        "message": str(engine.get("message") or "Nuclei CLI ready"),
    }


def _summarize_nuclei_jobs(jobs: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize current Nuclei attempt states."""

    current = [job for job in jobs if bool(job.get("is_current_attempt", True))]
    return {
        "queued": sum(str(job.get("ui_status")) == "Queued" for job in current),
        "active": sum(str(job.get("ui_status")) in ACTIVE_NUCLEI_STATUSES for job in current),
        "completed": sum(str(job.get("ui_status")) == "Completed" for job in current),
        "attention": sum(str(job.get("ui_status")) in NUCLEI_ATTENTION_STATUSES for job in current),
    }


def _summarize_openvas_jobs(jobs: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize OpenVAS states without changing provider semantics."""

    def status(job: dict[str, Any]) -> str:
        return str(job.get("status") or job.get("ui_status") or "")

    return {
        "queued": sum(status(job) == "Queued" for job in jobs),
        "active": sum(
            status(job) not in OPENVAS_TERMINAL_STATUSES and status(job) != "Queued" for job in jobs
        ),
        "completed": sum(status(job) in {"Completed", "Recovered report", "Done"} for job in jobs),
        "attention": sum(
            status(job) in OPENVAS_TERMINAL_STATUSES
            and status(job) not in {"Completed", "Recovered report", "Done"}
            for job in jobs
        ),
    }


def scanner_fabric_metrics(client_name: str) -> dict[str, Any]:
    """Return non-fatal cross-engine activity and health metrics."""

    result: dict[str, Any] = {
        ENGINE_OPENVAS: {
            "batches": [],
            "jobs": [],
            "counts": {"queued": 0, "active": 0, "completed": 0, "attention": 0},
            "health": _openvas_health(),
            "error": "",
        },
        ENGINE_NUCLEI: {
            "batches": [],
            "jobs": [],
            "counts": {"queued": 0, "active": 0, "completed": 0, "attention": 0},
            "health": _nuclei_health(),
            "error": "",
        },
    }

    if ENGINE_OPENVAS in enabled_engines():
        try:
            batches = list_openvas_batches(client_name, limit=25)
            jobs: list[dict[str, Any]] = []
            for batch in batches:
                try:
                    jobs.extend(load_openvas_batch_jobs(int(batch["id"])))
                except Exception:
                    continue
            result[ENGINE_OPENVAS]["batches"] = batches
            result[ENGINE_OPENVAS]["jobs"] = jobs
            result[ENGINE_OPENVAS]["counts"] = _summarize_openvas_jobs(jobs)
        except Exception as exc:
            result[ENGINE_OPENVAS]["error"] = display_tool_output(f"{type(exc).__name__}: {exc}")

    if ENGINE_NUCLEI in enabled_engines():
        try:
            batches = list_nuclei_batches(client_name, limit=25)
            jobs = []
            for batch in batches:
                try:
                    jobs.extend(load_nuclei_batch_jobs(int(batch["id"])))
                except Exception:
                    continue
            result[ENGINE_NUCLEI]["batches"] = batches
            result[ENGINE_NUCLEI]["jobs"] = jobs
            result[ENGINE_NUCLEI]["counts"] = _summarize_nuclei_jobs(jobs)
        except Exception as exc:
            result[ENGINE_NUCLEI]["error"] = display_tool_output(f"{type(exc).__name__}: {exc}")

    result["totals"] = {
        key: sum(int(result[engine]["counts"][key]) for engine in (ENGINE_OPENVAS, ENGINE_NUCLEI))
        for key in ("queued", "active", "completed", "attention")
    }
    return result


def _provider_card(engine: str, data: dict[str, Any], active_engine: str) -> None:
    """Render one provider health and activity card."""

    health = data.get("health") or {}
    counts = data.get("counts") or {}
    ready = bool(health.get("ready"))
    worker_healthy = bool(health.get("worker_healthy"))
    if ready and worker_healthy:
        status = "Connected"
    elif ready:
        status = "Connection issue"
    else:
        status = "Unavailable"
    with st.container(border=True):
        left, right = st.columns([4, 2], vertical_alignment="center")
        with left:
            st.markdown(f"### {_safe(engine)}")
            st.caption(engine_description(engine))
        with right:
            st.markdown("**ACTIVE ENGINE**" if engine == active_engine else "**AVAILABLE ENGINE**")
        st.markdown(
            f"**{status}** · {int(counts.get('active') or 0)} active · "
            f"{int(counts.get('queued') or 0)} queued"
        )
        cols = st.columns(3)
        with cols[0]:
            st.metric("Campaigns", len(data.get("batches") or []))
        with cols[1]:
            st.metric("Completed", int(counts.get("completed") or 0))
        with cols[2]:
            st.metric("Attention", int(counts.get("attention") or 0))
        with st.expander("Technical details"):
            st.caption(
                str(health.get("message") or data.get("error") or "No provider message.")[:350]
            )


def render_scanner_fabric_overview(
    client_name: str,
    active_engine: str,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render provider cards and consolidated operation metrics."""

    normalized = normalize_engine(active_engine)
    metrics = metrics or scanner_fabric_metrics(client_name)
    st.markdown("### Scanner fabric")
    st.caption(
        "OpenVAS provides broad Greenbone vulnerability assessment. Nuclei "
        "provides fast template-based checks through the local open-source CLI."
    )
    provider_columns = st.columns(2, gap="medium")
    with provider_columns[0]:
        _provider_card(ENGINE_OPENVAS, metrics[ENGINE_OPENVAS], normalized)
    with provider_columns[1]:
        _provider_card(ENGINE_NUCLEI, metrics[ENGINE_NUCLEI], normalized)

    totals = metrics["totals"]
    cols = st.columns(4, gap="small")
    for column, label, key in zip(
        cols,
        ["Queued", "Active", "Completed", "Needs attention"],
        ["queued", "active", "completed", "attention"],
    ):
        with column:
            st.metric(label, int(totals[key]))

    campaigns: list[dict[str, Any]] = []
    for engine in (ENGINE_OPENVAS, ENGINE_NUCLEI):
        for batch in (metrics[engine].get("batches") or [])[:5]:
            campaigns.append(
                {
                    "Engine": engine,
                    "Batch": batch.get("id"),
                    "Campaign": batch.get("label") or batch.get("scan_mode"),
                    "Status": batch.get("status"),
                    "Assets": int(batch.get("submitted_count") or 0),
                    "Completed": int(batch.get("completed_count") or 0),
                    "Attention": int(batch.get("failed_count") or 0),
                    "Created": _format_datetime(batch.get("created_at")),
                }
            )
    if campaigns:
        st.dataframe(
            pd.DataFrame(campaigns).sort_values("Created", ascending=False),
            width="stretch",
            hide_index=True,
            height=min(380, 70 + len(campaigns) * 35),
        )
    return metrics


def _activate_scan_engine(engine: str) -> None:
    """Store an engine button selection before Streamlit reruns."""

    persist_engine_selection(st.session_state, engine, enabled_engines())


def _set_button_choice(state_key: str, value: str) -> None:
    """Store a normal-button choice in session state."""

    st.session_state[state_key] = value


def render_button_choice(
    label: str,
    options: list[str],
    *,
    key: str,
    default: str,
    icons: dict[str, str] | None = None,
) -> str:
    """Render mutually exclusive choices as normal Streamlit buttons."""

    icons = icons or {}
    current = str(st.session_state.get(key) or default)
    if current not in options:
        current = default if default in options else options[0]
        st.session_state[key] = current
    st.markdown(f"**{label}**")
    columns = st.columns(len(options), gap="small")
    for column, option in zip(columns, options):
        with column:
            st.button(
                option,
                icon=icons.get(option),
                type="primary" if option == current else "secondary",
                width="stretch",
                key=f"{key}_{_slug(option)}",
                on_click=_set_button_choice,
                args=(key, option),
            )
    return str(st.session_state.get(key) or current)


def render_engine_command_bar(active_engine: str) -> str:
    """Render the only engine selector inside the Scan Center."""

    engines = enabled_engines()
    normalized = normalize_engine(active_engine, default=engines[0])
    if normalized not in engines:
        normalized = engines[0]
    with st.container(border=True):
        heading, *buttons = st.columns([4] + [2] * len(engines), gap="small")
        with heading:
            st.markdown("**Choose the vulnerability engine**")
            st.caption("The selection applies only to new campaigns.")
        for column, engine in zip(buttons, engines):
            with column:
                st.button(
                    engine,
                    icon=":material/bolt:" if engine == ENGINE_NUCLEI else ":material/security:",
                    type="primary" if engine == normalized else "secondary",
                    width="stretch",
                    key=f"scan_center_engine_button_{_slug(engine)}",
                    on_click=_activate_scan_engine,
                    args=(engine,),
                )
        st.caption(f"Active engine: **{normalized}** · {engine_description(normalized)}")
    return normalize_engine(st.session_state.get("scan_engine"), default=normalized)


def render_nuclei_connection_panel() -> None:
    """Render redacted Nuclei CLI health in the connection dialog."""

    health = nuclei_engine_health()
    st.markdown("#### ProjectDiscovery Nuclei CLI")
    from securescope.ui.integration_presentation import integration_summary

    integration_summary(
        "Nuclei",
        "Connected" if health.get("ok") else "Unavailable",
        "Local installation checked; remote target access is not verified.",
    )
    with st.expander("Technical details"):
        st.code(str(health.get("binary") or "nuclei"))
    st.caption(
        "The check is read-only: executable version and installed community-template version. "
        "Nuclei OSS requires no API key."
    )
    if st.button(
        "Test Nuclei installation",
        icon=":material/terminal:",
        type="primary",
        width="stretch",
        key="dialog_test_nuclei",
    ):
        nuclei_engine_health.clear()
        refreshed = nuclei_engine_health()
        if refreshed.get("ok"):
            st.success(
                f"Ready · {refreshed.get('version')} · templates "
                f"{refreshed.get('templates_version')}"
            )
        else:
            st.error(display_tool_output(refreshed.get("message")))


def _batch_label(batch: dict[str, Any]) -> str:
    """Return one batch selector label."""

    return f"#{batch.get('id')} · {batch.get('label')} · {batch.get('status')}"


def _jobs_frame(jobs: list[dict[str, Any]]) -> pd.DataFrame:
    """Build a stable Nuclei jobs table."""

    rows: list[dict[str, Any]] = []
    for job in jobs:
        stats = job.get("stats_payload") or {}
        rows.append(
            {
                "Job": int(job.get("id") or 0),
                "Attempt": int(job.get("attempt_number") or 1),
                "Current": bool(job.get("is_current_attempt", True)),
                "Asset": job.get("asset_tag") or "Unassigned",
                "IP address": job.get("asset_ip") or "",
                "Status": job.get("ui_status") or job.get("status"),
                "Nuclei state": job.get("provider_status") or "",
                "Stage": job.get("stage") or "",
                "Findings": int(job.get("findings_count") or 0),
                "Critical": int(job.get("critical_count") or 0),
                "High": int(job.get("high_count") or 0),
                "Requests": stats.get("requests") or stats.get("total") or None,
                "Runner PID": job.get("runner_pid"),
                "Updated": _format_datetime(job.get("updated_at")),
                "Error": job.get("error") or "",
                "Report": report_action_value(ENGINE_NUCLEI, job),
            }
        )
    frame = pd.DataFrame(rows)
    if not frame.empty:
        # Pandas nullable integers prevent PyArrow from mixing integers with
        # empty strings while queued jobs have no runner PID or request count.
        frame["Runner PID"] = pd.to_numeric(frame["Runner PID"], errors="coerce").astype("Int64")
        frame["Requests"] = pd.to_numeric(frame["Requests"], errors="coerce").astype("Int64")
    return frame


@st.fragment(run_every="5s")
def _render_nuclei_live_batch(batch_id: int, client_name: str) -> None:
    """Refresh one durable Nuclei batch from PostgreSQL."""

    jobs = load_nuclei_batch_jobs(batch_id)
    if not jobs:
        empty_state("No scan jobs", "Select inventory assets and launch a campaign to create jobs.")
        return
    counts = _summarize_nuclei_jobs(jobs)
    current_jobs = [job for job in jobs if bool(job.get("is_current_attempt", True))]
    total = len(current_jobs)
    columns = st.columns(5)
    values = [
        ("Total", total),
        ("Queued", counts["queued"]),
        ("Active", counts["active"]),
        ("Completed", counts["completed"]),
        ("Needs attention", counts["attention"]),
    ]
    for column, (label, value) in zip(columns, values):
        with column:
            st.metric(label, value)
    st.progress(counts["completed"] / total if total else 0.0)
    frame = _jobs_frame(jobs)
    st.dataframe(
        frame,
        width="stretch",
        hide_index=True,
        height=min(520, 90 + len(frame) * 35),
        column_config={
            "Requests": st.column_config.NumberColumn("Requests", width="small"),
            "Runner PID": st.column_config.NumberColumn("Runner PID", width="small"),
            "Report": st.column_config.TextColumn(
                "Report",
                width="small",
                help="A PDF action is available when the job is complete.",
            ),
        },
    )

    render_report_downloads(
        client_name, ENGINE_NUCLEI, jobs, key=f"nuclei_reports::{client_name}::{batch_id}"
    )


def render_nuclei_scan_center(client_name: str, assets: list[dict[str, Any]]) -> None:
    """Render the workspace-scoped Nuclei operations center."""

    st.markdown("## Scan Center")
    st.caption("Nuclei vulnerability assessments")

    from securescope.ui.evidence_collection_context import render_collection_return
    from securescope.ui.grc_workspace.context import current_actor

    collection_context = render_collection_return(client_name)
    if collection_context.get("asset_ids"):
        from securescope.persistence.evidence_repository import resolve_nuclei_asset

        assets = [
            a
            for a in assets
            if resolve_nuclei_asset(client_name, a["ip"])["id"] in collection_context["asset_ids"]
        ]
    engine = nuclei_engine_health()
    try:
        worker = get_nuclei_worker_state()
    except Exception as exc:
        worker = {"message": display_tool_output(f"{type(exc).__name__}: {exc}")}
    worker_ok = _worker_healthy(worker)

    from securescope.ui.integration_presentation import integration_summary

    integration_summary(
        "Nuclei",
        (
            "Connected"
            if engine.get("ok") and worker_ok
            else "Connection issue" if engine.get("ok") else "Unavailable"
        ),
        (
            "Local installation and worker are available."
            if engine.get("ok") and worker_ok
            else "Check the local installation and worker before starting an assessment."
        ),
    )
    with st.expander("Technical details · Engine and worker"):
        cards = st.columns(4, gap="small")
        card_values = [
            (
                "Worker",
                "Healthy" if worker_ok else "Attention",
                str(worker.get("message") or "No heartbeat")[:180],
            ),
            (
                "Nuclei CLI",
                "Ready" if engine.get("ok") else "Error",
                str(engine.get("message") or engine.get("binary"))[:180],
            ),
            (
                "Templates",
                extract_semantic_version(engine.get("templates_version")),
                engine.get("template_directory") or "Nuclei default",
            ),
            (
                "Concurrency",
                os.getenv("NUCLEI_MAX_CONCURRENT_SCANS", "2"),
                "Maximum active SecureScope Nuclei jobs",
            ),
        ]
        for column, (label, value, detail) in zip(cards, card_values):
            with column:
                metric_card(label, display_tool_output(value), display_tool_output(detail))

    if not engine.get("ok") or not worker_ok:
        with st.expander("How to fix"):
            if not engine.get("ok"):
                st.write("Install the Nuclei CLI and its community templates on the scanner host.")
            if not worker_ok:
                st.write(
                    "The standalone Nuclei worker is missing or stale. "
                    "Start the configured Nuclei worker on the scanner host."
                )

    new_tab, live_tab, health_tab = module_tabs(
        ["New assessment", "Live operations", "Engine health"]
    )
    client_key = _slug(client_name)

    with new_tab:
        if not assets:
            st.info("No assets are available. Run Asset Discovery first.")
        else:
            selection_col, policy_col = st.columns(2, gap="large")
            with selection_col:
                mode = render_button_choice(
                    "Target selection",
                    ["Single asset", "Multiple assets"],
                    key=f"nuclei_target_mode_{client_key}",
                    default="Single asset",
                    icons={
                        "Single asset": ":material/dns:",
                        "Multiple assets": ":material/view_list:",
                    },
                )
                labels = {
                    f"{asset.get('asset_tag') or 'Asset'} · {asset.get('ip')}": asset
                    for asset in assets
                    if str(asset.get("ip") or "").strip()
                }
                selected_assets: list[dict[str, Any]] = []
                if not labels:
                    st.warning("No inventory record has a usable IP address.")
                elif mode == "Multiple assets":
                    scope = render_button_choice(
                        "Batch scope",
                        ["Choose assets", "All discovered assets"],
                        key=f"nuclei_scope_{client_key}",
                        default="Choose assets",
                    )
                    if scope == "All discovered assets":
                        selected_assets = list(labels.values())
                        st.info(f"All {len(selected_assets)} assets will be queued.")
                    else:
                        selected_labels = st.multiselect(
                            "Assets",
                            list(labels),
                            default=list(labels)[: min(5, len(labels))],
                            key=f"nuclei_assets_{client_key}",
                        )
                        selected_assets = [labels[label] for label in selected_labels]
                else:
                    selected_label = st.selectbox(
                        "Asset",
                        list(labels),
                        key=f"nuclei_single_asset_{client_key}",
                    )
                    selected_assets = [labels[selected_label]]

            with policy_col:
                profiles = profile_options()
                labels_by_key = {item["key"]: item["label"] for item in profiles}
                key_by_label = {item["label"]: item["key"] for item in profiles}
                default_profile = os.getenv("NUCLEI_DEFAULT_PROFILE", "standard")
                default_label = labels_by_key.get(default_profile, profiles[0]["label"])
                profile_label = st.selectbox(
                    "Nuclei profile",
                    list(key_by_label),
                    index=list(key_by_label).index(default_label),
                    key=f"nuclei_profile_{client_key}",
                )
                profile_name = key_by_label[profile_label]
                description = next(
                    item["description"] for item in profiles if item["key"] == profile_name
                )
                st.caption(description)
                sync_to_ciso = st.checkbox(
                    "Synchronize findings to CISO Assistant",
                    value=False,
                    key=f"nuclei_ciso_{client_key}",
                )
                authorized = st.checkbox(
                    "I am authorized to scan these targets",
                    value=False,
                    key=f"nuclei_authorized_{client_key}",
                )
                st.caption(
                    "Default safety limits: official templates, excluded unsafe tags, "
                    f"{os.getenv('NUCLEI_RATE_LIMIT', '50')} requests/second."
                )

            if st.button(
                "Create Nuclei campaign",
                type="primary",
                icon=":material/play_arrow:",
                width="stretch",
                disabled=(not engine.get("ok") or not selected_assets or not authorized),
                key=f"create_nuclei_batch_{client_key}",
            ):
                try:
                    batch = create_nuclei_batch(
                        client_name=client_name,
                        assets=selected_assets,
                        collection_context=collection_context or None,
                        actor=current_actor(),
                        scan_mode=(
                            "Single asset" if len(selected_assets) == 1 else "Multiple assets"
                        ),
                        profile_name=profile_name,
                        sync_to_ciso=sync_to_ciso,
                    )
                    request_nuclei_worker_wake(
                        batch_id=int(batch["id"]),
                        reason="Campaign created from Nuclei Scan Center.",
                    )
                    st.session_state[f"nuclei_active_batch_{client_key}"] = int(batch["id"])
                    st.success(
                        f"Batch #{batch['id']} saved with {len(selected_assets)} exact job(s)."
                    )
                    st.rerun()
                except NucleiDatabaseError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(display_tool_output(f"{type(exc).__name__}: {exc}"))

    with live_tab:
        batches = list_nuclei_batches(client_name, limit=50)
        if not batches:
            st.info("No Nuclei campaign exists for this workspace.")
        else:
            options = {_batch_label(batch): int(batch["id"]) for batch in batches}
            stored_batch_id = st.session_state.get(f"nuclei_active_batch_{client_key}")
            labels = list(options)
            default_index = 0
            if stored_batch_id:
                for index, label in enumerate(labels):
                    if options[label] == int(stored_batch_id):
                        default_index = index
                        break
            selected_label = st.selectbox(
                "Nuclei campaign",
                labels,
                index=default_index,
                key=f"nuclei_batch_selector_{client_key}",
            )
            batch_id = options[selected_label]
            st.session_state[f"nuclei_active_batch_{client_key}"] = batch_id
            button_cols = st.columns(2)
            with button_cols[0]:
                if st.button(
                    "Wake Nuclei worker",
                    icon=":material/refresh:",
                    width="stretch",
                    key=f"nuclei_wake_{batch_id}",
                ):
                    request_nuclei_worker_wake(
                        batch_id=batch_id,
                        reason="Manual wake from Nuclei Scan Center.",
                    )
                    st.success("Wake request saved.")
            with button_cols[1]:
                st.caption("The live table refreshes every five seconds from PostgreSQL.")
            _render_nuclei_live_batch(batch_id, client_name)

            jobs = load_nuclei_batch_jobs(batch_id)
            retryable = [
                job
                for job in jobs
                if bool(job.get("is_current_attempt", True))
                and str(job.get("ui_status")) in NUCLEI_ATTENTION_STATUSES
            ]
            if retryable:
                retry_labels = {
                    f"Job #{job['id']} · {job.get('asset_ip')} · {job.get('ui_status')}": job
                    for job in retryable
                }
                selected_retry = st.selectbox(
                    "Retry failed or interrupted job",
                    list(retry_labels),
                    key=f"nuclei_retry_job_{batch_id}",
                )
                if st.button(
                    "Create retry attempt",
                    key=f"nuclei_retry_button_{batch_id}",
                ):
                    source = retry_labels[selected_retry]
                    new_job = retry_nuclei_job(
                        int(source["id"]),
                        "Analyst requested a new Nuclei attempt.",
                    )
                    request_nuclei_worker_wake(
                        batch_id=batch_id,
                        reason=f"Retry attempt {new_job.get('attempt_number')} created.",
                    )
                    st.success(f"Created job #{new_job['id']} attempt {new_job['attempt_number']}.")
                    st.rerun()

            if jobs:
                event_job_labels = {
                    f"Job #{job['id']} · attempt {job.get('attempt_number')}"
                    f" · {job.get('asset_ip')}": int(job["id"])
                    for job in jobs
                }
                event_label = st.selectbox(
                    "Job event timeline",
                    list(event_job_labels),
                    key=f"nuclei_event_job_{batch_id}",
                )
                events = list_nuclei_job_events(event_job_labels[event_label], limit=100)
                if events:
                    st.dataframe(
                        pd.DataFrame(
                            [
                                {
                                    "Time": _format_datetime(event.get("created_at")),
                                    "Event": event.get("event_type"),
                                    "Status": event.get("ui_status"),
                                    "Stage": event.get("stage"),
                                    "Message": event.get("message"),
                                    "Error": event.get("error"),
                                }
                                for event in events
                            ]
                        ),
                        width="stretch",
                        hide_index=True,
                    )

    with health_tab:
        st.json(
            {
                "engine": engine,
                "worker": worker,
                "runtime_limits": {
                    "max_concurrent_jobs": os.getenv("NUCLEI_MAX_CONCURRENT_SCANS", "2"),
                    "rate_limit": os.getenv("NUCLEI_RATE_LIMIT", "50"),
                    "bulk_size": os.getenv("NUCLEI_BULK_SIZE", "10"),
                    "template_concurrency": os.getenv("NUCLEI_CONCURRENCY", "10"),
                    "unsigned_templates_disabled": os.getenv(
                        "NUCLEI_DISABLE_UNSIGNED_TEMPLATES", "true"
                    ),
                },
            }
        )
        st.caption(
            "Optional ProjectDiscovery Cloud upload is configured outside SecureScope with "
            "`nuclei -auth`; local open-source scanning does not require an API key."
        )
