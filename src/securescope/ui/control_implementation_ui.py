"""Implementation requirements and evidence explanations inside Control Assurance."""

from __future__ import annotations

import logging

import streamlit as st
from securescope.ui.components.primitives import identity_context

from securescope.integrations.credential_store import CredentialStoreError
from securescope.persistence.control_implementation_repository import (
    REVIEWERS,
    document_choices,
    implementation_view,
    save_implementation_evaluation,
    save_implementation_requirements,
)
from securescope.persistence.foundation_repository import FoundationError
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.ui.grc_workspace.context import current_actor, workspace_state_keys
from securescope.ui.workflow_sections import workflow_section

LOGGER = logging.getLogger(__name__)
ERRORS = (FoundationError, GrcRepositoryError, CredentialStoreError, ValueError)


def render_implementation(client: str, control_id: str, role: str) -> None:
    """Render current checks, explicit saves and immutable evaluation history.

    Args:
        client: Active workspace name.
        control_id: Existing selected control reference.
        role: Display role; repository services authorize every operation independently.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected service errors display and log.
    """
    actor = current_actor()
    key = f"implementation::{client}::{control_id}"
    try:
        view = implementation_view(client, control_id, actor)
        profile, result = view["bundle"]["profile"], view["current"]
        st.subheader(f"Implementation evidence · {control_id}")
        st.caption(
            "Evaluation of saved records. Assessment answers alone do not prove implementation."
        )
        if key + "::notice" in st.session_state:
            st.success(st.session_state.pop(key + "::notice"))
        st.markdown(f"**Current result: {result['status']}**")
        bundle = view["bundle"]
        requirements = (profile.get("assessment_scope") or {}).get(
            "implementation_requirements"
        ) or {}
        documents = {str(d["policy_id"]): d for d in bundle.get("documents", [])}
        summary_rows = [
            {
                "Requirement": "Owner",
                "Saved information": profile.get("control_owner") or "Unassigned",
            }
        ]
        for kind in ("policy", "procedure"):
            links = requirements.get(kind + "_links", [])
            names = []
            for link in links:
                document = documents.get(str(link["id"]), {})
                names.append(
                    f"{document.get('title', link['id'])} · "
                    f"{document.get('status', 'Unavailable')} · linked v{link.get('version', '—')}"
                )
            summary_rows.append(
                {
                    "Requirement": kind.title(),
                    "Saved information": "; ".join(names)
                    or requirements.get(kind + "_rationale")
                    or "Not linked — needs review",
                }
            )
        summary_rows.extend(
            [
                {
                    "Requirement": "Evidence",
                    "Saved information": (
                        f"{len(bundle.get('evidence', []))} references; "
                        "validity is evaluated below"
                    ),
                },
                {"Requirement": "Verification", "Saved information": str(result["status"])},
            ]
        )
        st.table(summary_rows)

        st.dataframe(
            [
                {
                    "Check": c["name"],
                    "Result": "Satisfied" if c["passed"] else "Needs attention",
                    "Reason": c["explanation"],
                }
                for c in result["checks"]
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Automated verification: Coming Soon. Manual evidence and "
            "effectiveness tests are supported now."
        )
        if st.button(
            "Save implementation evaluation",
            key=key + "::save",
            type="primary",
            disabled=role not in REVIEWERS,
        ):
            saved = save_implementation_evaluation(
                client, control_id, actor, result["input_fingerprint"]
            )
            st.session_state[key + "::notice"] = f"Evaluation recorded: {saved['status']}."
            st.rerun()
        if view["previous"]:
            with st.expander("Last recorded evaluation"):
                previous = view["previous"]
                st.write(previous["result"]["status"])
                st.caption(str(previous["result"]["evaluated_at"]))
                identity_context(previous["recorded_by"], "Recorded by")
                if view["inputs_changed"]:
                    st.warning(
                        "Review required: inputs, evidence currency or evaluation rules changed."
                    )
                st.table(
                    [
                        {"Check": c["name"], "Satisfied": c["passed"], "Reason": c["explanation"]}
                        for c in previous["result"].get("checks", [])
                    ]
                )
        with workflow_section(
            "Implementation requirements and document links",
            "Review the documents and criteria required for this control.",
            status="Completed" if requirements.get("reviewed") else "Not started",
            step=2,
        ):
            st.caption(
                "Saving creates a new profile version. Approve its target and "
                "assess that version before a positive evaluation."
            )
            engagement_key, scope_key = workspace_state_keys(client)
            engagement, scope = st.session_state.get(engagement_key), st.session_state.get(
                scope_key
            )
            if not engagement or not scope:
                st.info(
                    "Select an engagement and ISMS scope in Programme Foundation to "
                    "configure document links."
                )
                return
            config = (profile.get("assessment_scope") or {}).get(
                "implementation_requirements"
            ) or {}
            if config and (config.get("engagement_id"), config.get("scope_id")) != (
                int(engagement),
                int(scope),
            ):
                st.warning(
                    "Select the profile's original ISMS context before editing requirements."
                )
                return
            options = {
                d["policy_id"]: d
                for d in document_choices(client, actor, int(engagement), int(scope))
                if control_id in (d.get("controls") or [])
            }
            st.caption(
                "Choose existing policy-library documents. Assign a document's "
                "Procedure role here; this reuses its existing approval and "
                "version history."
            )
            for doc in options.values():
                st.write(f"{doc['title']} · {doc['status']} · v{doc['policy_version']}")
            with st.form(key + f"::requirements::{profile['profile_version']}"):
                selected, rationales = {}, {}
                for kind in ("policy", "procedure"):
                    defaults = [
                        link["id"]
                        for link in config.get(kind + "_links", [])
                        if link["id"] in options
                    ]
                    selected[kind] = st.multiselect(
                        f"Required {kind} documents",
                        list(options),
                        default=defaults,
                        format_func=lambda identity: str(options[identity]["title"]),
                        disabled=role not in REVIEWERS,
                    )
                    rationales[kind] = st.text_area(
                        f"Why no separate {kind} is required (if none selected)",
                        value=config.get(kind + "_rationale", ""),
                        max_chars=2000,
                        disabled=role not in REVIEWERS,
                    )
                criteria_text = st.text_area(
                    "Required implementation criteria · one per line",
                    value="\n".join(config.get("criteria", [])),
                    disabled=role not in REVIEWERS,
                )
                interval = st.number_input(
                    "Maximum assessment and evidence age (days)",
                    min_value=1,
                    max_value=3650,
                    value=config.get("review_days", 90),
                    disabled=role not in REVIEWERS,
                )
                confirmed = st.checkbox(
                    "I reviewed these requirements and the evidence review interval.",
                    disabled=role not in REVIEWERS,
                )
                submit = st.form_submit_button(
                    "Save requirements as profile version", disabled=role not in REVIEWERS
                )
            if submit:
                if not confirmed:
                    st.error("Confirm that you reviewed the requirements before saving.")
                else:
                    version = save_implementation_requirements(
                        client,
                        control_id,
                        actor,
                        int(profile["profile_version"]),
                        engagement=int(engagement),
                        scope=int(scope),
                        policy_ids=selected["policy"],
                        procedure_ids=selected["procedure"],
                        policy_rationale=rationales["policy"],
                        procedure_rationale=rationales["procedure"],
                        review_days=int(interval),
                        criteria=criteria_text.splitlines(),
                    )
                    st.session_state[key + "::notice"] = (
                        f"Requirements saved in profile version {version}."
                    )
                    st.rerun()
    except ERRORS as exc:
        LOGGER.warning("Implementation workflow failed: %s", type(exc).__name__)
        st.error(str(exc))
