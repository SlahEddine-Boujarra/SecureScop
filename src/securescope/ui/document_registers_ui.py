"""Editable ISMS registers with saved revisions, import previews and Excel exports."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from securescope.grc.document_registers import (
    CALCULATED_FIELDS,
    DATE_FIELDS,
    REGISTER_SCHEMAS,
    SCORE_FIELDS,
    normalize_register_rows,
)
from securescope.grc.risk_register import (
    ASSET_GROUPS,
    RISK_TYPES,
    TREATMENT_OPTIONS,
    TREATMENT_STATUSES,
)
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.migration_service import MigrationError
from securescope.persistence.risk_register_repository import (
    list_risk_register,
    save_risk_records,
    seed_starter_risks,
)
from securescope.persistence.working_register_repository import (
    load_register,
    register_history,
    save_register,
)
from securescope.reporting.register_exchange import (
    build_register_workbook,
    import_register_workbook,
)
from securescope.ui.workspace_inputs import working_actor

ERRORS = (GrcRepositoryError, DatabaseConfigurationError, MigrationError, ValueError)


def render_populated_toolkit_download(
    kind: str,
    rows: list[dict[str, Any]],
    *,
    client_name: str,
    key: str,
) -> None:
    """Retain the retired toolkit hook without exposing an unsupported UI action.

    Args:
        kind: Toolkit document kind.
        rows: Current client rows to write into the source template.
        client_name: Workspace name used in the filename only.
        key: Stable widget/session key prefix.
    Returns:
        None.
    Raises:
        No exceptions are raised; expected preparation failures are shown inline.
    """
    return


def _column_config(fields: dict[str, str]) -> dict[str, Any]:
    """Build supported Streamlit columns from the document schema.

    Args:
        fields: Stable field names and template labels.
    Returns:
        Streamlit column configuration.
    Raises:
        No exceptions are raised directly.
    """
    config = {
        key: st.column_config.TextColumn(
            label,
            width=(
                "large"
                if key in {"threat", "vulnerability", "asset", "comments"}
                or key.endswith("rationale")
                else "medium"
            ),
        )
        for key, label in fields.items()
    }
    for key in SCORE_FIELDS.intersection(fields):
        config[key] = st.column_config.NumberColumn(fields[key], min_value=1, max_value=5, step=1)
    for key in {
        "risk_ref",
        "treatment_cost",
        "pre_risk_score",
        "post_risk_score",
        "score",
    }.intersection(fields):
        config[key] = st.column_config.NumberColumn(
            fields[key], min_value=0, step=1 if key != "treatment_cost" else 0.01
        )
    for key in DATE_FIELDS.intersection(fields):
        config[key] = st.column_config.DateColumn(fields[key], format="DD MMM YYYY")
    for key, options in {
        "asset_group": ASSET_GROUPS,
        "risk_type": RISK_TYPES,
        "treatment_option": TREATMENT_OPTIONS,
        "treatment_action_status": TREATMENT_STATUSES,
    }.items():
        if key in fields:
            config[key] = st.column_config.SelectboxColumn(fields[key], options=list(options))
    if "residual_verified" in fields:
        config["residual_verified"] = st.column_config.CheckboxColumn(fields["residual_verified"])
    return config


def render_document_registers(client_name: str, *, key_suffix: str = "main") -> None:
    """Render the four editable registers beside the existing Gap and SoA tabs.

    Args:
        client_name: Active workspace.
        key_suffix: Unique location of this register browser.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected storage or input errors.
    """
    kind = st.selectbox(
        "Working document",
        list(REGISTER_SCHEMAS),
        format_func=lambda value: REGISTER_SCHEMAS[value][0],
        key=f"document_kind::{client_name}::{key_suffix}",
    )
    render_register(client_name, kind, key_suffix=key_suffix)


def render_register(client_name: str, kind: str, *, key_suffix: str = "main") -> None:
    """Edit all rows in one table and save a reviewable, versioned batch.

    Args:
        client_name: Active workspace.
        kind: Document schema identifier.
        key_suffix: Unique UI location.
    Returns:
        None.
    Raises:
        No exceptions are raised for expected storage or input errors.
    """
    title, fields = REGISTER_SCHEMAS[kind]
    prefix = f"register::{client_name}::{kind}::{key_suffix}"
    st.subheader(title)
    st.caption(
        (
            "Edit or paste several rows, then save once. Use the Gap dashboard"
            " and Statement of Applicability tabs for those two documents."
        )
    )
    if kind in {"scenario_risks", "opportunities"}:
        st.info(
            "This is a saved draft worksheet. Its rows do not change the formal "
            "risk register or live control-assessment results."
        )
    try:
        if kind == "asset_risks":
            saved_rows = list_risk_register(client_name)
            saved = {
                "rows": saved_rows,
                "revision": sum(int(row["revision"]) for row in saved_rows),
            }
        else:
            saved = load_register(client_name, kind)
    except ERRORS as exc:
        st.error(str(exc))
        return
    if kind == "asset_risks" and saved["rows"]:
        from securescope.ui.security_visuals import risk_matrix

        with st.expander("Risk distribution", expanded=True):
            risk_matrix(saved["rows"], key=prefix + "::matrix")
    if kind == "asset_risks" and not saved["rows"]:
        st.info(
            (
                "No risks are recorded yet. Start with the reviewed ISO examples "
                "or import a completed risk workbook."
            )
        )
        if st.button(
            "Load ISO starter risks", icon=":material/playlist_add:", key=prefix + "::seed"
        ):
            try:
                seeded = seed_starter_risks(client_name, actor=working_actor(client_name, prefix))
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.success(
                    (
                        "Loaded "
                        f"{seeded}"
                        " starter risk records. Review every field before relying on "
                        "them."
                    )
                )
                st.rerun()
    st.session_state.setdefault(prefix + "::snapshot", saved)
    snapshot = st.session_state[prefix + "::snapshot"]
    # Toolkit imports cannot enter persistence before the requested live-schema
    # review. Previously staged, unsaved preview state must not bypass that gate.
    st.session_state.pop(prefix + "::import", None)
    working_rows = snapshot["rows"]
    preview_key = prefix + "::import_preview"
    actor = working_actor(client_name, prefix)
    if saved["revision"] != snapshot["revision"]:
        st.warning("A newer saved version exists. Reload before saving this draft.")
    with st.expander("Import an existing Excel register"):
        uploaded = st.file_uploader(
            "Completed template or SecureScope export", type=["xlsx"], key=prefix + "::upload"
        )
        st.caption(
            "Preview the proposed rows and matching references. Import preview only — "
            "applying imports is not enabled in this version."
        )
        if st.button(
            "Preview imported rows", disabled=uploaded is None, key=prefix + "::import_button"
        ):
            try:
                imported = import_register_workbook(uploaded.getvalue(), kind)
                if not imported:
                    st.info(
                        (
                            "The workbook is a valid template, but it contains no populated "
                            "records yet."
                        )
                    )
                else:
                    ref_key = "risk_ref" if kind.endswith("risks") else "ref"
                    existing = {str(row[ref_key]): dict(row) for row in snapshot["rows"]}
                    merged = dict(existing)
                    merged.update({str(row[ref_key]): row for row in imported})
                    imported_by_ref = {str(row[ref_key]): row for row in imported}
                    updated = sorted(set(existing).intersection(imported_by_ref))
                    added = sorted(set(merged) - set(existing))
                    st.session_state[preview_key] = {
                        "rows": imported,
                        "merged": list(merged.values()),
                        "updated": updated,
                        "added": added,
                    }
                    st.rerun()
            except (ValueError, TypeError) as exc:
                st.error(str(exc))
        preview = st.session_state.get(preview_key)
        if preview:
            st.markdown("#### Import preview")
            st.caption(
                f"{len(preview['added'])} new record(s) and {len(preview['updated'])} "
                "matching record(s) are present in this file. The preview has "
                "not changed the editor or saved records."
            )
            st.dataframe(
                pd.DataFrame(preview["rows"]),
                width="stretch",
                hide_index=True,
                height=min(280, 82 + len(preview["rows"]) * 32),
            )
            preview_apply, preview_discard = st.columns(2)
            preview_apply.button(
                "Apply preview to editor",
                disabled=True,
                help="The live database mapping must be reviewed first.",
                key=prefix + "::apply_preview",
            )
            if preview_discard.button("Discard preview", key=prefix + "::discard_preview"):
                st.session_state.pop(preview_key, None)
                st.rerun()
    if kind.endswith("risks"):
        st.caption(
            (
                "Scoring: likelihood × impact (1–5 each). Post-treatment values "
                "are planned estimates until verification evidence and a verifier "
                "are recorded."
            )
        )
    else:
        st.caption(
            (
                "Blank ratings remain Not assessed. Save changes to update the "
                "dashboard and exported workbook."
            )
        )
    prepared = []
    for original in working_rows:
        row = {field: original.get(field) for field in fields}
        if isinstance(row.get("control_references"), list):
            row["control_references"] = ", ".join(row["control_references"])
        prepared.append(row)
    frame = pd.DataFrame(prepared, columns=list(fields))
    for field in DATE_FIELDS.intersection(fields):
        frame[field] = pd.to_datetime(frame[field]).dt.date
    for field in SCORE_FIELDS.union(
        {"risk_ref", "treatment_cost", "pre_risk_score", "post_risk_score", "score"}
    ).intersection(fields):
        frame[field] = pd.to_numeric(frame[field])
    if "residual_verified" in fields:
        frame["residual_verified"] = frame["residual_verified"].fillna(False).astype(bool)
    generation = st.session_state.get(prefix + "::generation", 0)
    edited = st.data_editor(
        frame,
        width="stretch",
        hide_index=True,
        num_rows="dynamic",
        height=520,
        disabled=list(CALCULATED_FIELDS.intersection(fields)),
        column_config=_column_config(fields),
        key=f"{prefix}::editor::{generation}",
    )
    save_column, reload_column, export_column = st.columns(3)
    if reload_column.button("Reload saved records", key=prefix + "::reload"):
        st.session_state.pop(prefix + "::snapshot", None)
        st.session_state.pop(prefix + "::import", None)
        st.session_state[prefix + "::generation"] = generation + 1
        st.rerun()
    if save_column.button("Save register", type="primary", key=prefix + "::save"):
        try:
            records = normalize_register_rows(kind, edited.to_dict("records"))
            if kind == "asset_risks":
                existing = {int(row["risk_ref"]): int(row["revision"]) for row in snapshot["rows"]}
                if set(existing) - {row["risk_ref"] for row in records}:
                    raise ValueError(
                        (
                            "Existing asset risks cannot be removed here. Keep the row and "
                            "record its treatment outcome."
                        )
                    )
                save_risk_records(
                    client_name,
                    records,
                    actor=actor,
                    expected_revisions={
                        row["risk_ref"]: existing.get(row["risk_ref"], 0) for row in records
                    },
                )
            else:
                save_register(
                    client_name, kind, records, actor=actor, expected_revision=snapshot["revision"]
                )
        except ERRORS as exc:
            st.error(str(exc))
        else:
            st.session_state.pop(prefix + "::snapshot", None)
            st.session_state.pop(prefix + "::import", None)
            st.session_state[prefix + "::generation"] = generation + 1
            st.session_state[prefix + "::success"] = f"Saved {len(records)} records."
            st.rerun()
    if message := st.session_state.pop(prefix + "::success", None):
        st.success(message)
    try:
        workbook = build_register_workbook(kind, saved["rows"], client_name)
    except (ValueError, TypeError) as exc:
        export_column.warning(f"Export needs corrected values: {exc}")
    else:
        export_column.download_button(
            "Export saved Excel + chart",
            workbook,
            f"{kind}.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key=prefix + "::export",
            on_click="ignore",
        )
    if kind in {"asset_risks", "scenario_risks", "opportunities"}:
        render_populated_toolkit_download(
            kind,
            [dict(row) for row in saved["rows"]],
            client_name=client_name,
            key=prefix,
        )
    level_key = (
        "pre_risk_level"
        if kind.endswith("risks")
        else "level" if kind == "opportunities" else "status"
    )
    if saved["rows"]:
        summary = pd.Series(
            [row.get(level_key) or "Not assessed" for row in saved["rows"]]
        ).value_counts()
        st.bar_chart(summary, color="#00685f", height=230)
    if kind != "asset_risks":
        with st.expander("Saved versions"):
            try:
                history = register_history(client_name, kind)
            except ERRORS as exc:
                st.error(str(exc))
            else:
                st.dataframe(
                    [
                        {key: row[key] for key in ("revision", "recorded_by", "created_at")}
                        for row in history
                    ],
                    hide_index=True,
                    width="stretch",
                )
