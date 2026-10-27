"""Full-page Control Profile workspace composed from existing canonical services."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import date, timedelta

import streamlit as st

from securescope.grc.assurance_requirements import GROUPS, REQUIREMENT_TYPES, RULE_PROVIDERS
from securescope.integrations.credential_store import CredentialStoreError
from securescope.persistence.assurance_workspace_repository import (
    collect_inventory_evidence,
    configured_profiles,
    create_requirement_action,
    evidence_choices,
    link_evidence_scope,
    load_workspace,
    record_evaluation,
    save_requirements,
)
from securescope.persistence.db_service import DatabaseConfigurationError
from securescope.persistence.evidence_repository import EvidenceRepositoryError
from securescope.persistence.foundation_repository import FoundationError
from securescope.persistence.grc_repository import GrcRepositoryError
from securescope.persistence.migration_service import MigrationError
from securescope.policies.repository import PolicyError, load_policies, save_policy
from securescope.ui.assurance_workbench import _event
from securescope.ui.components_v2.assurance_workbench import assurance_workbench
from securescope.ui.grc_workspace.context import current_actor, selected_context_ids
from securescope.ui.navigation_runtime import navigate_to
from securescope.ui.risk_management import open_risk_management
from securescope.ui.workflow_sections import back_link

LOGGER = logging.getLogger(__name__)
ERRORS = (
    DatabaseConfigurationError,
    MigrationError,
    EvidenceRepositoryError,
    FoundationError,
    GrcRepositoryError,
    PolicyError,
    CredentialStoreError,
    ValueError,
)
PROFILE_TAB = ":material/table_view: Control profiles"


def open_control_workspace(client: str, control_id: str) -> None:
    """Navigate to an existing control while retaining the current client and scope.

    Args:
        client: Current workspace name.
        control_id: Canonical control reference.
    Returns:
        None; updates existing navigation state.
    Raises:
        StreamlitAPIException: If route switching is unavailable.
    """
    st.session_state[f"control_drawers::{client}::implementation"] = control_id
    st.session_state[f"assurance_pending_tab::{client}"] = PROFILE_TAB
    navigate_to("Gap Assessment")


def _navigate(client: str, control_id: str, destination: str, identifier=None) -> None:
    """Open a canonical module without changing selected workspace context.

    Args:
        client: Current workspace.
        control_id: Origin control ID.
        destination: Allowlisted module action.
        identifier: Optional canonical record ID.
    Returns:
        None.
    Raises:
        ValueError: For an unsupported destination.
    """
    engagement, scope = selected_context_ids(client)
    st.session_state[f"control_return::{client}"] = control_id
    if destination == "risk":
        open_risk_management(client, stage="Treatment plan", risk_ref=identifier)
    elif destination == "policy":
        st.session_state[f"policies::{client}::{engagement}::{scope}::selected"] = identifier
        navigate_to("Policies")
    elif destination == "remediation":
        st.session_state[f"requirement_remediation_selected::{client}::{engagement}::{scope}"] = (
            identifier
        )
        navigate_to("Remediation")
    elif destination in {"evidence", "assessment", "soa"}:
        if destination == "evidence":
            st.session_state[f"evidence_control_pending::{client}"] = control_id
            st.session_state[f"evidence_scope_view::{client}::{engagement}::{scope}"] = (
                "Current ISMS Scope"
            )
            st.session_state[f"evidence_section::{client}"] = "Evidence Register"
        tab = {
            "evidence": ":material/folder_open: Evidence",
            "assessment": ":material/fact_check: Assess control",
            "soa": ":material/description: Statement of Applicability",
            "remediation": ":material/assignment_late: Gap actions",
        }[destination]
        st.session_state[f"assurance_pending_tab::{client}"] = tab
        st.session_state[f"manual_control_pending::{client}"] = control_id
        st.rerun()
    elif destination == "assets":
        navigate_to("2 · Asset Management")
    else:
        raise ValueError("Unknown control navigation destination.")


def _save(client, control_id, view, requirements, auto, owner):
    """Persist editor changes through canonical profile versioning.

    Args:
        client: Workspace name.
        control_id: Existing control reference.
        view: Loaded authorized inputs.
        requirements: Updated structured criteria.
        auto: Configured automatic verification preference.
        owner: Accountable control owner.
    Returns:
        New profile version number.
    Raises:
        FoundationError: If authorization or links fail validation.
        GrcRepositoryError: If concurrent edits or persistence fail.
    """
    bundle = view["bundle"]
    return save_requirements(
        client,
        control_id,
        current_actor(),
        bundle["engagement_id"],
        bundle["scope_id"],
        int(bundle["profile"]["profile_version"]),
        requirements,
        auto=auto,
        owner=owner,
    )


def _profile_editor(client, view, key):
    """Edit organization-specific profile fields using the existing version service.

    Args:
        client: Authorized workspace name.
        view: Current authorized profile and context.
        key: Scoped widget namespace.
    Returns:
        None.
    Raises:
        ValueError: If submitted values are invalid.
        GrcRepositoryError: If saving fails or the version is stale.
    """
    from securescope.core.gap_assessment_domain import ASSESSMENT_MODELS
    from securescope.ui.control_profiles_workbench import profile_values, save_profile_edit

    profile = view["bundle"]["profile"]
    values = profile_values(profile)

    @st.dialog("Edit Control Configuration", width="large")
    def edit_dialog():
        """Render the focused versioned configuration form."""
        st.caption(
            (
                "Reference control names remain fixed. Customize your "
                "organization’s implementation below."
            )
        )
        with st.form(key + f"::profile::{profile['profile_version']}"):
            fields = {}
            for name, label in [
                ("organization_name", "Organization control name"),
                ("control_owner", "Control owner"),
                ("assessment_owner", "Assessment owner"),
            ]:
                fields[name] = st.text_input(label, values[name])
            for name, label in [
                ("implementation_description", "Implementation description"),
                ("scope", "Assessment scope"),
            ]:
                fields[name] = st.text_area(label, values[name])
            with st.expander("Advanced Settings"):
                for name, label in [
                    ("assessment_methods", "Assessment methods — one per line"),
                    ("evidence_requirements", "Evidence expectations — one per line"),
                ]:
                    fields[name] = st.text_area(label, values[name])
                models = list(ASSESSMENT_MODELS)
                fields["measurement_model"] = st.selectbox(
                    "Measurement model", models, index=models.index(values["measurement_model"])
                )
            levels = ["Manual", "Partial", "Automated"]
            fields["automation_level"] = st.selectbox(
                "Collection automation level",
                levels,
                index=levels.index(values["automation_level"]),
            )
            st.caption(
                (
                    "Collection automation is separate from permission to verify "
                    "control assurance automatically."
                )
            )
            if st.form_submit_button("Save implementation profile"):
                try:
                    save_profile_edit(
                        client,
                        profile,
                        dict(fields=fields, expected_version=profile["profile_version"]),
                        current_actor(),
                    )
                except ERRORS as exc:
                    LOGGER.warning("Profile save failed: %s", type(exc).__name__)
                    st.error(f"Implementation profile could not be saved: {exc}")
                    return
                st.session_state[key + "::notice"] = (
                    "Implementation profile saved as a new version."
                )
                st.rerun()

    if st.session_state.pop(key + "::configure_requested", False):
        edit_dialog()


def _requirement_editor(client, control_id, view, key, requirement_id):
    """Edit a criterion and explicit canonical links, retaining old profile versions.

    Args:
        client: Workspace name.
        control_id: Existing control reference.
        view: Authorized current workspace data.
        key: Scoped widget namespace.
        requirement_id: Existing criterion ID or new.
    Returns:
        None.
    Raises:
        ValueError: On malformed requirement values.
        FoundationError: On invalid scoped links.
    """
    bundle = view["bundle"]
    config = bundle["profile"]["assessment_scope"].get("implementation_requirements") or {}
    requirements = list(config.get("requirements", []))
    existing = next((r for r in requirements if r["id"] == requirement_id), {})
    documents = {r["policy_id"]: r for r in bundle["documents"]}
    evidence = {r["id"]: r for r in bundle["requirement_evidence"]}
    parties = {r["id"]: r for r in bundle["party_requirements"]}
    assets = {r["id"]: r for r in bundle["assets"]}
    st.subheader("Edit requirement" if existing else "Add requirement")
    st.caption(
        (
            "Links retain canonical identities. Accepted evidence and "
            "approved policies are evaluated on refresh."
        )
    )
    with st.form(key + f'::requirement::{requirement_id}::{bundle["profile"]["profile_version"]}'):
        title = st.text_input("Requirement title", existing.get("title", ""), max_chars=200)
        description = st.text_area("Description", existing.get("description", ""), max_chars=4000)
        left, right = st.columns(2)
        kind = left.selectbox(
            "Type",
            REQUIREMENT_TYPES,
            index=REQUIREMENT_TYPES.index(existing.get("type", "Technical")),
        )
        group = right.selectbox(
            "Requirement group", GROUPS, index=GROUPS.index(existing.get("group", GROUPS[0]))
        )
        expected_result = st.text_area(
            "Expected result", existing.get("expected_result", ""), max_chars=4000
        )
        rule = st.selectbox(
            "Assessment method",
            list(RULE_PROVIDERS),
            index=list(RULE_PROVIDERS).index(existing.get("rule", "Manual validation")),
        )
        mandatory = st.checkbox("Mandatory requirement", existing.get("mandatory", True))
        policy_ids = st.multiselect(
            "Supporting policies",
            list(documents),
            default=[i for i in existing.get("policy_ids", []) if i in documents],
            format_func=lambda i: f"{documents[i]['title']} · {documents[i]['status']}",
        )
        evidence_ids = st.multiselect(
            "Scoped evidence",
            list(evidence),
            default=[
                r["evidence_id"]
                for r in existing.get("evidence_links", [])
                if r["evidence_id"] in evidence
            ],
            format_func=lambda i: (
                f"EV-{i} · {evidence[i]['title']} · " f"{evidence[i]['validation_status']}"
            ),
        )
        conclusion = st.selectbox(
            "Manual evidence conclusion",
            ["UNKNOWN", "PASS", "PARTIAL", "FAIL"],
            help="Used only with Manual validation; automated rules ignore this selection.",
        )
        rationale = st.text_area("Manual validation rationale", max_chars=4000)
        asset_ids = st.multiselect(
            "Applicable assets in this scope",
            list(assets),
            default=[i for i in existing.get("asset_ids", []) if i in assets],
            format_func=lambda i: str(assets[i].get("asset_tag") or assets[i]["ip"]),
        )
        st.caption(
            (
                "Select only assets inside the approved boundary. Inventory "
                "membership alone does not prove scope."
            )
        )
        party_id = st.selectbox(
            "Related Interested Party requirement",
            [None, *parties],
            index=(
                [None, *parties].index(existing.get("party_requirement_id"))
                if existing.get("party_requirement_id") in parties
                else 0
            ),
            format_func=lambda i: "None" if i is None else f"REQ-{i} · {parties[i]['requirement']}",
        )
        source_kinds = [
            "Organization-Specific",
            "Imported",
            "Risk-Driven",
            "Policy-Driven",
            "Interested-Party Requirement",
            "SecureScope Baseline",
        ]
        original_kind = existing.get("source_kind", "Organization-Specific")
        source_kind = st.selectbox(
            "Requirement source",
            source_kinds,
            index=source_kinds.index(original_kind) if original_kind in source_kinds else 0,
            disabled=original_kind == "SecureScope Baseline",
            help="Baseline provenance remains attached when you customize its wording.",
        )
        source = st.text_input(
            "Source / obligation reference", existing.get("source", ""), max_chars=1000
        )
        with st.expander("Advanced Verification Settings"):
            from securescope.evidence.nuclei_assurance import RULE_VERSION, RULES

            nuclei_check = RULES.get(rule)
            nuclei_templates = (
                st.multiselect(
                    "Reviewed Nuclei template predicates",
                    list(nuclei_check.template_ids),
                    default=[
                        t
                        for t in existing.get("nuclei_template_ids", [])
                        if t in nuclei_check.template_ids
                    ],
                    help="Select only tests that match your approved baseline. Findings can identify gaps; absence of findings cannot prove a pass.",
                )
                if nuclei_check and nuclei_check.template_ids
                else None
            )
            machine_verifiable = st.checkbox(
                "Allow supported machine evidence to verify this requirement",
                value=existing.get("machine_verifiable", False),
                help=(
                    "Only configured trusted sources with scoped, fresh and "
                    "validated proof qualify."
                ),
            )
            follow_provider = st.checkbox(
                "Follow latest validated scoped provider evidence",
                existing.get("follow_provider", False),
                help=(
                    "Automatic rules only; explicit manual evidence references "
                    "remain individually selected."
                ),
            )
            allow_collection_health = (
                st.checkbox(
                    "Accept collection-path health proof for this monitoring requirement",
                    value=bool(existing.get("allow_collection_health")),
                    disabled=rule != "Monitoring coverage",
                    help="Verifies only the approved source channel, not detection effectiveness.",
                )
                if rule == "Monitoring coverage"
                else False
            )
            test_key = st.text_input(
                "Provider configuration test key",
                existing.get("test_key", ""),
                help=(
                    "Exact named test exposed by a configured provider; never an "
                    "executable expression."
                ),
            )
            days = st.number_input(
                "Maximum evidence age (days)", 1, 3650, int(existing.get("max_age_days", 90))
            )
            threshold = st.number_input(
                "Required asset coverage (%)", 1, 100, int(existing.get("threshold", 100))
            )
        save = st.form_submit_button("Save requirement", type="primary")
        remove = st.form_submit_button("Remove from current profile", disabled=not existing)
    if save or remove:
        updated = [r for r in requirements if r["id"] != requirement_id]
        if save:
            old_links = {r["evidence_id"]: r for r in existing.get("evidence_links", [])}
            links = [
                (
                    dict(evidence_id=i, conclusion=conclusion, rationale=rationale)
                    if rationale
                    else old_links.get(i, dict(evidence_id=i, conclusion="UNKNOWN", rationale=""))
                )
                for i in evidence_ids
            ]
            existing["source_kind"] = source_kind
            if nuclei_templates is not None:
                existing.update(
                    nuclei_rule_version=RULE_VERSION, nuclei_template_ids=nuclei_templates
                )
            else:
                existing.pop("nuclei_rule_version", None)
                existing.pop("nuclei_template_ids", None)
            updated.append(
                dict(
                    **{
                        k: v
                        for k, v in existing.items()
                        if k
                        not in {
                            "id",
                            "title",
                            "description",
                            "type",
                            "group",
                            "expected_result",
                            "mandatory",
                            "rule",
                            "follow_provider",
                            "allow_collection_health",
                            "policy_ids",
                            "evidence_links",
                            "asset_ids",
                            "party_requirement_id",
                            "source",
                            "test_key",
                            "max_age_days",
                            "threshold",
                            "machine_verifiable",
                            "human_review_required",
                        }
                    },
                    id=existing.get("id") or str(uuid.uuid4()),
                    title=title,
                    description=description,
                    type=kind,
                    group=group,
                    expected_result=expected_result,
                    mandatory=mandatory,
                    machine_verifiable=machine_verifiable,
                    human_review_required=not machine_verifiable,
                    rule=rule,
                    follow_provider=follow_provider,
                    allow_collection_health=allow_collection_health,
                    policy_ids=policy_ids,
                    evidence_links=links,
                    asset_ids=asset_ids,
                    party_requirement_id=party_id,
                    source=source,
                    test_key=test_key,
                    max_age_days=int(days),
                    threshold=int(threshold),
                )
            )
        if save and existing:
            saved_requirement = updated.pop()
            updated.insert(
                next(i for i, r in enumerate(requirements) if r["id"] == requirement_id),
                saved_requirement,
            )
        version = _save(
            client,
            control_id,
            view,
            updated,
            bool(config.get("continuous_auto_assurance")),
            bundle["profile"].get("control_owner") or current_actor(),
        )
        st.session_state.pop(key + "::editor", None)
        st.session_state[key + "::notice"] = (
            "No changes to save."
            if version == bundle["profile"]["profile_version"]
            else "Control requirement updated."
        )
        st.rerun()


def _policy_draft(client, control_id, view, key, requirement):
    """Create a context-prefilled draft in the canonical policy service.

    Args:
        client: Workspace name.
        control_id: Originating control reference.
        view: Authorized workspace inputs.
        key: Scoped widget namespace.
        requirement: Requirement motivating this draft.
    Returns:
        None.
    Raises:
        PolicyError: If draft creation is denied or invalid.
        FoundationError: If scoped profile linking fails.
    """
    bundle = view["bundle"]
    st.subheader("Create Policy from Control Gap")
    st.caption(
        f"Triggered by {control_id} · {requirement['title']} · ISMS Scope #{bundle['scope_id']}"
    )
    with st.form(key + "::policy"):
        title = st.text_input("Policy title", requirement["title"] + " Policy")
        owner = st.text_input(
            "Policy owner", bundle["profile"].get("control_owner") or current_actor()
        )
        content = st.text_area("Draft policy statement", requirement["expected_result"], height=160)
        st.caption(
            (
                "Starter wording requires human review. Creating a Draft does "
                "not satisfy this requirement."
            )
        )
        submit = st.form_submit_button("Create Draft", type="primary")
    if submit:
        _, history = load_policies(client, bundle["engagement_id"], bundle["scope_id"])
        identity = str(uuid.uuid4())
        save_policy(
            client,
            bundle["engagement_id"],
            bundle["scope_id"],
            actor=current_actor(),
            policy_id=identity,
            expected_version=int(history[0]["version"]) if history else 0,
            status="Draft",
            note=f"Created from {control_id}, requirement {requirement['id']}",
            metadata=dict(title=title, owner=owner, controls=[control_id]),
            blocks=[dict(kind="p", runs=[dict(text=content)])],
        )
        config = bundle["profile"]["assessment_scope"]["implementation_requirements"]
        updated = [
            (
                dict(r, policy_ids=list(dict.fromkeys([*r.get("policy_ids", []), identity])))
                if r["id"] == requirement["id"]
                else r
            )
            for r in config["requirements"]
        ]
        try:
            _save(
                client,
                control_id,
                view,
                updated,
                bool(config.get("continuous_auto_assurance")),
                bundle["profile"].get("control_owner") or current_actor(),
            )
        except ERRORS:
            st.warning(
                (
                    "Policy draft created. The profile changed; reload and link the "
                    "existing draft to this requirement."
                )
            )
        st.session_state.pop(
            f"policy_requirement_create::{client}::{bundle['engagement_id']}::{bundle['scope_id']}",
            None,
        )
        _navigate(client, control_id, "policy", identity)


def render_control_workspace(client: str, control_id: str, role: str) -> None:
    """Render the complete assurance workspace and authorized explicit actions.

    Args:
        client: Current tenant name.
        control_id: Canonical control identifier.
        role: UI role hint; repositories independently authorize writes.
    Returns:
        None.
    Raises:
        Unexpected programming errors propagate; expected workflow errors are logged and shown.
    """
    engagement, scope = selected_context_ids(client)
    if not engagement or not scope:
        st.info("Select an engagement and ISMS Scope to open Control Assurance.")
        return
    key = f"control_workspace::{client}::{engagement}::{scope}::{control_id}"
    if back_link("Control Profiles", key=key + "::back"):
        st.session_state.pop(f"control_drawers::{client}::implementation", None)
        st.rerun()
    try:
        view = load_workspace(client, control_id, current_actor(), engagement, scope)
        bundle, result = view["bundle"], view["result"]
        from securescope.persistence.assurance_workspace_repository import seed_control_baseline

        if seed_control_baseline(client, control_id, current_actor(), engagement, scope, view):
            st.session_state[key + "::notice"] = (
                "SecureScope baseline criteria prepared. Review them for this "
                "scope; existing records are preserved."
            )
            st.rerun()
        profile = bundle["profile"]
        if result.get("baseline_preview"):
            st.caption(
                (
                    "SecureScope baseline preview — a Consultant can prepare these "
                    "criteria for the selected scope."
                )
            )
        can_edit = view["role"] in {"Administrator", "Consultant"}
        config = (profile.get("assessment_scope") or {}).get("implementation_requirements") or {}
        if key + "::notice" in st.session_state:
            st.success(st.session_state.pop(key + "::notice"))
        data = dict(
            mode="control_workspace",
            baseline_review_pending=bool(config.get("baseline_review_pending")),
            control_id=control_id,
            title=profile["control_name"],
            owner=profile.get("control_owner") or "Unassigned",
            scope=scope,
            assessment_date=(bundle.get("assessment") or {}).get("created_at"),
            result=result,
            documents=bundle["documents"],
            evidence=bundle["requirement_evidence"],
            asset_labels={
                str(a["id"]): a.get("asset_tag") or a["ip"] for a in bundle.get("assets", [])
            },
            risks=bundle["risks"],
            actions=bundle["actions"],
            history=view["history"],
            can_edit=can_edit,
            is_admin=view["role"] == "Administrator",
            response={"nonce": st.session_state.get(key + ":handled")},
        )
        event = _event(assurance_workbench(json.loads(json.dumps(data, default=str)), key=key), key)
        if any(r.get("rule_version") == 3 for r in result["requirements"]):
            st.download_button(
                "Download technical check trace (JSON)",
                json.dumps(
                    dict(
                        client=client,
                        control_id=control_id,
                        engagement_id=engagement,
                        scope_id=scope,
                        result=result,
                    ),
                    default=str,
                    indent=2,
                ),
                file_name=f"SecureScope_{control_id}_scope_{scope}_technical_trace.json",
                mime="application/json",
                key=key + "::technical_trace",
            )
        if event:
            action, payload = event["action"], event.get("payload") or {}
            requirement = next(
                (r for r in result["requirements"] if r["id"] == payload.get("id")), None
            )
            if action == "confirm_requirements" and can_edit:
                _save(
                    client,
                    control_id,
                    view,
                    config.get("requirements", []),
                    bool(config.get("continuous_auto_assurance")),
                    profile.get("control_owner") or current_actor(),
                )
                st.session_state[key + "::notice"] = "Requirements reviewed for the current scope."
                st.rerun()
            elif action == "requirement_link" and can_edit and requirement:
                from securescope.ui.evidence_collection_context import begin_existing_link

                begin_existing_link(client, control_id, requirement)
            elif (
                action in {"requirement_manual", "requirement_request"} and can_edit and requirement
            ):
                from securescope.ui.evidence_collection_context import begin_collection

                begin_collection(
                    client,
                    control_id,
                    requirement,
                    "manual" if action == "requirement_manual" else "request",
                )
            elif action == "requirement_collect" and can_edit and requirement:
                from securescope.ui.evidence_collection_context import begin_collection

                providers = RULE_PROVIDERS[requirement["rule"]]
                from securescope.evidence.tool_catalog import TOOLS, IntegrationMode

                executable = {
                    tool.tool_id
                    for tool in TOOLS
                    if tool.integration_mode is IntegrationMode.LOCAL_CLI
                }
                supported = providers.intersection(executable | {"nuclei", "wazuh"})
                preferred = requirement.get("provider")
                provider = (
                    preferred
                    if preferred in supported
                    else next(
                        (
                            candidate
                            for candidate in ["nuclei", "wazuh", *sorted(executable)]
                            if candidate in supported
                        ),
                        None,
                    )
                )

                if provider:
                    begin_collection(client, control_id, requirement, provider)
                else:
                    st.session_state[key + "::notice"] = (
                        "No automatic collector supports this requirement. Use Link Existing "
                        "Evidence, "
                        "Manual Evidence or Request Evidence."
                    )
            elif action == "requirement_scope_assets" and can_edit and requirement:
                profiles = configured_profiles(client, current_actor(), engagement, scope)
                asset_ids = sorted(
                    {
                        a
                        for p in profiles
                        for r in (p.get("assessment_scope") or {})
                        .get("implementation_requirements", {})
                        .get("requirements", [])
                        for a in r.get("asset_ids", [])
                    }
                )
                if not asset_ids:
                    st.session_state[key + "::notice"] = (
                        "No canonical in-scope asset assignments exist. Choose assets in Edit "
                        "Requirement."
                    )
                else:
                    requirements = [
                        dict(r, asset_ids=asset_ids) if r["id"] == requirement["id"] else r
                        for r in config.get("requirements", [])
                    ]
                    _save(
                        client,
                        control_id,
                        view,
                        requirements,
                        bool(config.get("continuous_auto_assurance")),
                        profile.get("control_owner"),
                    )
                    st.session_state[key + "::notice"] = (
                        "In-scope assets assigned to this requirement."
                    )
            elif action == "requirement_edit" and can_edit:
                st.session_state[key + "::editor"] = payload.get("id") or "new"
            elif action == "requirement_policy" and can_edit and requirement:
                st.session_state[f"policy_requirement_create::{client}::{engagement}::{scope}"] = (
                    dict(control_id=control_id, requirement_id=requirement["id"])
                )
                navigate_to("Policies")
            elif action == "requirement_remediation" and can_edit and requirement:
                st.session_state[key + "::remediation"] = requirement["id"]
            elif action == "refresh_assurance" and can_edit:
                record_evaluation(client, control_id, current_actor(), engagement, scope)
                st.session_state[key + "::notice"] = "Control evidence re-evaluated and recorded."
                st.rerun()
            elif action == "collect_inventory" and can_edit:
                identity = collect_inventory_evidence(
                    client, control_id, current_actor(), engagement, scope
                )
                st.session_state[key + "::notice"] = (
                    f"Inventory evidence EV-{identity} collected. Map it to the requirement."
                )
                st.rerun()
            elif action == "control_configure" and can_edit:
                st.session_state[key + "::configure_requested"] = True
            elif action == "control_navigate":
                _navigate(client, control_id, payload.get("destination"), payload.get("id"))
            st.rerun()
        if can_edit:
            _profile_editor(client, view, key)
            with st.expander("Link Existing Evidence to this Scope"):
                search = st.text_input("Search evidence titles", key=key + "::evidence_search")
                choices = {
                    e["id"]: e
                    for e in evidence_choices(client, current_actor(), engagement, scope, search)
                }
                if choices:
                    with st.form(key + "::link_evidence"):
                        evidence_id = st.selectbox(
                            "Existing evidence",
                            list(choices),
                            format_func=lambda i: (
                                f"EV-{i} · {choices[i]['title']} · "
                                f"{choices[i]['validation_status']}"
                            ),
                        )
                        rationale = st.text_area("Scope and control coverage rationale")
                        confirmed = st.checkbox(
                            "I verified this evidence covers the selected control and ISMS Scope."
                        )
                        if st.form_submit_button("Link Evidence"):
                            if not confirmed:
                                st.error("Confirm scope coverage before linking evidence.")
                            else:
                                link_evidence_scope(
                                    client,
                                    control_id,
                                    current_actor(),
                                    engagement,
                                    scope,
                                    evidence_id,
                                    rationale,
                                )
                                st.session_state[key + "::notice"] = (
                                    "Evidence linked. Select the requirement to map this evidence."
                                )
                                st.rerun()
                else:
                    st.caption("No matching evidence. Collect or upload it in Evidence first.")
            config = profile["assessment_scope"].get("implementation_requirements") or {}
            if config.get("criteria") and not config.get("requirements"):
                st.info(
                    "Existing profile criteria are preserved. Review them before "
                    "enabling individual requirement tests."
                )
                if st.button(
                    "Prepare requirements from existing criteria", key=key + "::legacy_criteria"
                ):
                    proposed = [
                        dict(
                            id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{control_id}:{index}:{title}")),
                            title=str(title)[:200],
                            expected_result=str(title)[:4000],
                            type="Operational",
                            group=GROUPS[0],
                            mandatory=True,
                            rule="Manual validation",
                            max_age_days=90,
                            threshold=100,
                            evidence_links=[],
                            policy_ids=[],
                            asset_ids=[],
                        )
                        for index, title in enumerate(config["criteria"])
                        if str(title).strip()
                    ]
                    _save(
                        client,
                        control_id,
                        view,
                        proposed,
                        False,
                        profile.get("control_owner") or current_actor(),
                    )
                    st.session_state[key + "::notice"] = (
                        "Requirements prepared. Review each criterion and link its evidence. "
                        "Previous assessments remain unchanged."
                    )
                    st.rerun()
            with st.expander("Owner and Continuous Auto-Assurance settings"):
                with st.form(key + "::settings"):
                    owner = st.text_input("Accountable owner", profile.get("control_owner") or "")
                    auto = st.checkbox(
                        "Continuous Auto-Assurance",
                        bool(config.get("continuous_auto_assurance")),
                        disabled=view["role"] != "Administrator",
                    )
                    st.caption(
                        (
                            "Requires current approved scope, formal applicability, all "
                            "mandatory machine checks passing and complete safety signals. "
                            "Governance approvals stay human-controlled."
                        )
                    )
                    if st.form_submit_button("Save assurance settings"):
                        _save(client, control_id, view, config.get("requirements", []), auto, owner)
                        st.session_state[key + "::notice"] = "Control assurance settings saved."
                        st.rerun()
            editor = st.session_state.get(key + "::editor")
            if editor:

                def dismiss_requirement():
                    """Clear the dialog request when the user dismisses it."""
                    st.session_state.pop(key + "::editor", None)

                @st.dialog("Control Requirement", width="large", on_dismiss=dismiss_requirement)
                def edit_requirement_dialog():
                    """Keep save failures visible inside the focused requirement editor."""
                    try:
                        _requirement_editor(client, control_id, view, key, editor)
                    except ERRORS as exc:
                        LOGGER.warning("Requirement save failed: %s", type(exc).__name__)
                        st.error(f"Requirement could not be saved: {exc}")

                edit_requirement_dialog()
            remediation = next(
                (
                    r
                    for r in result["requirements"]
                    if r["id"] == st.session_state.get(key + "::remediation")
                ),
                None,
            )
            if remediation:
                with st.form(key + "::remediation_form"):
                    st.subheader("Create Remediation")
                    st.write(remediation["title"])
                    owner = st.text_input(
                        "Action owner", profile.get("control_owner") or current_actor()
                    )
                    priority = st.selectbox("Priority", ["High", "Medium", "Low", "Critical"])
                    due = st.date_input("Due date", date.today() + timedelta(days=30))
                    if st.form_submit_button("Create Remediation", type="primary"):
                        identity = create_requirement_action(
                            client,
                            control_id,
                            current_actor(),
                            engagement,
                            scope,
                            remediation["id"],
                            owner=owner,
                            due_date=due,
                            priority=priority,
                        )
                        st.session_state.pop(key + "::remediation", None)
                        st.session_state[key + "::notice"] = (
                            f"Remediation #{identity} is ready in Remediation and Gap Actions. "
                            "Existing open work is reused."
                        )
                        st.rerun()
    except ERRORS as exc:
        LOGGER.warning("Control workspace operation failed: %s", type(exc).__name__)
        st.error(f"Control workspace operation failed: {exc}")
