"""Editable document schemas grounded in the supplied ISMS workbooks."""

from __future__ import annotations

import math
import re
from datetime import date, datetime
from typing import Any

from securescope.grc.risk_register import risk_level, risk_score

RISK_FIELDS = {
    "risk_ref": "Ref",
    "risk_type": "Risk Type",
    "risk_owner": "Risk Owner",
    "existing_controls": "Existing Controls",
    "pre_likelihood": "Likelihood",
    "pre_likelihood_rationale": "Likelihood Rationale",
    "pre_impact": "Impact",
    "pre_impact_rationale": "Impact Rationale",
    "pre_risk_score": "Risk Score",
    "pre_risk_level": "Risk Level",
    "treatment_option": "Treatment Option Chosen",
    "treatment_action": "Proposed Treatment Action",
    "control_references": "Annex A/Control Reference",
    "treatment_cost": "Treatment Cost",
    "treatment_action_owner": "Treatment Action Owner",
    "treatment_action_timescale": "Treatment Action Timescale",
    "treatment_action_progress": "Treatment Action Progress",
    "treatment_action_status": "Treatment Action Status",
    "post_likelihood": "Post-Treatment Likelihood",
    "post_likelihood_rationale": "Post-Treatment Likelihood Rationale",
    "post_impact": "Post-Treatment Impact",
    "post_impact_rationale": "Post-Treatment Impact Rationale",
    "post_risk_score": "Post-Treatment Risk Score",
    "post_risk_level": "Post-Treatment Risk Level",
    "residual_verified": "Residual verified",
    "residual_evidence": "Verification evidence",
    "residual_verified_by": "Verified by",
    "comments": "Comments",
}
ASSET_FIELDS = {
    "risk_ref": "Ref",
    "asset_group": "Asset Group",
    "asset_subcategory": "Asset subcategory",
    "asset": "Asset",
    "threat": "Threat",
    "vulnerability": "Vulnerability",
    **RISK_FIELDS,
}
SCENARIO_FIELDS = {
    "risk_ref": "Ref",
    "risk_summary": "Risk Summary",
    "risk_description": "Risk Description",
    **RISK_FIELDS,
}
OPPORTUNITY_FIELDS = {
    "ref": "Ref",
    "summary": "Opportunity Summary",
    "description": "Opportunity Description",
    "type": "Opportunity Type",
    "owner": "Opportunity Owner",
    "likelihood": "Likelihood",
    "likelihood_rationale": "Likelihood Rationale",
    "impact": "Impact",
    "impact_rationale": "Impact Rationale",
    "score": "Opportunity Score",
    "level": "Opportunity Level",
    "action": "Action",
    "action_owner": "Action Owner",
    "due_date": "Due date",
    "status": "Status",
    "comments": "Comments",
}
CHANGE_FIELDS = {
    "ref": "Change ref",
    "logged_date": "Date logged",
    "proposer": "Name of proposer",
    "contact": "Contact details",
    "description": "Change description",
    "reason": "Reason for change",
    "impact_description": "Change impact description",
    "urgency": "Change urgency",
    "type": "Change type",
    "status": "Change status",
    "narrative": "Change narrative",
    "review_date": "Review date",
    "comments": "Comments",
}
REGISTER_SCHEMAS = {
    "asset_risks": ("Asset-based risk register", ASSET_FIELDS),
    "scenario_risks": ("Scenario-based risk register", SCENARIO_FIELDS),
    "opportunities": ("Opportunity assessment", OPPORTUNITY_FIELDS),
    "changes": ("ISMS change log", CHANGE_FIELDS),
}
CALCULATED_FIELDS = {
    "pre_risk_score",
    "pre_risk_level",
    "post_risk_score",
    "post_risk_level",
    "score",
    "level",
}
SCORE_FIELDS = {
    "pre_likelihood",
    "pre_impact",
    "post_likelihood",
    "post_impact",
    "likelihood",
    "impact",
}
DATE_FIELDS = {"logged_date", "review_date", "due_date"}


def clean_cell(value: Any) -> Any:
    """Normalize an editor/import cell without converting missing inputs to zero.

    Args:
        value: Cell value.
    Returns:
        JSON-safe value, or None for a blank or template placeholder.
    Raises:
        No exceptions are raised directly.
    """
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()[:10]
    if isinstance(value, str) and value.strip() in {"", "Select…", "Select...", "Calculated"}:
        return None
    return value


def normalize_register_rows(
    kind: str, rows: list[dict[str, Any]], *, preserve_incomplete: bool = False
) -> list[dict[str, Any]]:
    """Validate and calculate draft records before preview, saving or export.

    Args:
        kind: Registered document kind.
        rows: Records containing schema field names.
        preserve_incomplete: Keep identified incomplete canonical draft rows.
    Returns:
        Complete rows with stable unique references and derived scores.
    Raises:
        ValueError: On duplicate references, invalid scores, dates or verification.
    """
    schema = REGISTER_SCHEMAS[kind][1]
    result = []
    references = set()
    ref_key = "risk_ref" if kind.endswith("risks") else "ref"
    for original in rows:
        row = {key: clean_cell(original.get(key)) for key in schema}
        descriptive = ("threat", "risk_summary", "risk_description", "description", "summary")
        if not any(row.get(key) for key in descriptive) and not (
            preserve_incomplete and kind == "asset_risks" and row.get("risk_ref")
        ):
            if any(
                row.get(key) for key in ("asset", "vulnerability", "risk_description", "reason")
            ):
                raise ValueError("Each record needs a threat, risk summary or description.")
            continue
        raw_ref = row.get(ref_key)
        if raw_ref is None:
            raise ValueError("Every populated row needs a unique reference.")
        reference = str(raw_ref).strip()
        if kind.endswith("risks"):
            if isinstance(raw_ref, bool) or not float(raw_ref).is_integer() or int(raw_ref) < 1:
                raise ValueError("Risk references must be positive whole numbers.")
            row[ref_key] = int(raw_ref)
            reference = str(row[ref_key])
            if isinstance(row.get("control_references"), str):
                row["control_references"] = [
                    item.strip()
                    for item in str(row["control_references"]).replace("\n", ",").split(",")
                    if item.strip()
                ]
            option = str(row.get("treatment_option") or "").strip().casefold()
            if option in {"share", "transfer", "transfer/share", "transfer or share"}:
                row["treatment_option"] = "Transfer / Share"
        if reference in references:
            raise ValueError(f"Duplicate reference: {reference}.")
        references.add(reference)
        for key in SCORE_FIELDS.intersection(schema):
            value = row.get(key)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not float(value).is_integer()
                    or not 1 <= int(value) <= 5
                ):
                    raise ValueError(
                        f"{reference}: {schema[key]} must be a whole number from 1 to 5."
                    )
                row[key] = int(value)
        for key in DATE_FIELDS.intersection(schema):
            if row.get(key):
                date.fromisoformat(str(row[key]))
        if (
            row.get("review_date")
            and row.get("logged_date")
            and row["review_date"] < row["logged_date"]
        ):
            raise ValueError(f"{reference}: review date cannot precede the logged date.")
        if "treatment_cost" in row and row["treatment_cost"] is not None:
            row["treatment_cost"] = float(row["treatment_cost"])
            if not math.isfinite(row["treatment_cost"]) or row["treatment_cost"] < 0:
                raise ValueError("Treatment cost must be a nonnegative number.")
        if kind.endswith("risks"):
            for prefix in ("pre", "post"):
                row[f"{prefix}_risk_score"] = risk_score(
                    row.get(f"{prefix}_likelihood"), row.get(f"{prefix}_impact")
                )
                row[f"{prefix}_risk_level"] = risk_level(row[f"{prefix}_risk_score"])
            row["residual_verified"] = bool(row.get("residual_verified"))
            if row["residual_verified"] and not all(
                (
                    row.get("post_risk_score"),
                    row.get("residual_evidence"),
                    row.get("residual_verified_by"),
                )
            ):
                raise ValueError(
                    f"{reference}: verified residual risk needs scores, evidence and a verifier."
                )
        elif kind == "opportunities":
            row["score"] = risk_score(row.get("likelihood"), row.get("impact"))
            row["level"] = risk_level(row["score"])
        result.append(row)
    return result


def header_key(value: Any) -> str:
    """Normalize template labels for exact, punctuation-insensitive matching.

    Args:
        value: Uploaded header text.
    Returns:
        Lowercase alphanumeric header key.
    Raises:
        No exceptions are raised directly.
    """
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())
