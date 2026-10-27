"""Completion rules and presentation metadata for the existing canonical risk."""

from datetime import date

from securescope.grc.risk_register import risk_level

EXTRA_FIELDS = (
    "category",
    "risk_summary",
    "risk_description",
    "existing_control_references",
    "treatment_progress_percent",
    "treatment_due_date",
    "assessment_conclusion",
    "residual_decision",
)
DECISIONS = ("Accept residual risk", "Additional treatment required", "Escalate for approval")


def workflow_fields(record: dict, *, complete: bool = False) -> dict:
    """Validate extra inputs without deriving approval or residual verification.

    Args:
        record: Inputs for the existing risk record.
        complete: Whether all assessment requirements must be present.
    Returns:
        Whitelisted lifecycle metadata, with normalized numeric progress.
    Raises:
        ValueError: For invalid values or incomplete completion requests.
    """
    result = {key: record.get(key) for key in EXTRA_FIELDS if key in record}
    progress = result.get("treatment_progress_percent")
    if progress not in (None, ""):
        if (
            isinstance(progress, bool)
            or not float(progress).is_integer()
            or not 0 <= float(progress) <= 100
        ):
            raise ValueError("Treatment progress must be a whole percentage from 0 to 100.")
        result["treatment_progress_percent"] = int(progress)
    elif "treatment_progress_percent" in record:
        result["treatment_progress_percent"] = None
    if result.get("treatment_due_date"):
        date.fromisoformat(str(result["treatment_due_date"]))
    if result.get("residual_decision") and result["residual_decision"] not in DECISIONS:
        raise ValueError("Choose a supported residual risk decision.")
    refs = result.get("existing_control_references", [])
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        raise ValueError("Choose existing controls from Control Profiles.")
    for key in ("category", "risk_summary", "risk_description", "assessment_conclusion"):
        if key in result and (not isinstance(result[key], str) or len(result[key]) > 20000):
            raise ValueError(
                f"{key.replace('_', ' ').title()} must contain at most 20,000 characters."
            )
    if complete:
        required = {
            "risk_summary": "Risk summary",
            "risk_description": "Risk description",
            "asset_group": "Asset group",
            "asset": "Asset",
            "threat": "Threat",
            "vulnerability": "Vulnerability",
            "risk_type": "Risk type",
            "risk_owner": "Risk owner",
            "pre_likelihood": "Pre-treatment likelihood",
            "pre_impact": "Pre-treatment impact",
            "pre_likelihood_rationale": "Likelihood rationale",
            "pre_impact_rationale": "Impact rationale",
            "treatment_option": "Treatment option",
            "treatment_action_owner": "Treatment owner",
            "treatment_due_date": "Treatment / review due date",
            "post_likelihood": "Residual likelihood",
            "post_impact": "Residual impact",
            "post_likelihood_rationale": "Residual likelihood rationale",
            "post_impact_rationale": "Residual impact rationale",
            "assessment_conclusion": "Assessment conclusion",
            "residual_decision": "Residual decision",
        }
        missing = [
            label for key, label in required.items() if not str(record.get(key) or "").strip()
        ]
        if (
            record.get("treatment_option") != "Accept"
            and not str(record.get("treatment_action") or "").strip()
        ):
            missing.append("Proposed treatment action")
        if record.get("treatment_option") == "Modify" and not record.get("control_references"):
            missing.append("Treatment control references")
        if result.get("treatment_progress_percent") is None:
            missing.append("Treatment progress")
        if missing:
            raise ValueError("Complete these fields: " + ", ".join(missing) + ".")
    return result


def scoring_view() -> dict:
    """Expose the current canonical scoring rules to the browser.

    Returns:
        Per-score levels and predefined 1–5 labels. No risk appetite is invented.
    Raises:
        No exceptions are raised directly.
    """
    return {
        "levels": {str(n): risk_level(n) for n in range(1, 26)},
        "likelihood": ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"],
        "impact": ["Insignificant", "Minor", "Moderate", "Major", "Severe"],
        "appetite": None,
    }
