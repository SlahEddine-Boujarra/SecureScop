"""Versioned SecureScope-authored criteria; never verbatim ISO requirements."""

from copy import deepcopy
from uuid import NAMESPACE_URL, uuid5

from securescope.grc.control_catalog import ANNEX_A_LABELS, CLAUSE_LABELS

TEMPLATE_VERSION = 2
M3_TEMPLATE_VERSION = 3
LABELS = dict((*CLAUSE_LABELS, *ANNEX_A_LABELS))
NOTICE = "SecureScope-authored assurance criteria. Review for your organization and scope."
SPECIAL = {
    "A.8.15": [
        (
            "Logging enabled",
            "Relevant systems generate security events.",
            "Technical",
            "Manual validation",
        ),
        (
            "Centralized log collection",
            "In-scope systems send logs to the designated collection service.",
            "Technical",
            "Log source coverage",
        ),
        (
            "Retention configured",
            "Configured retention meets the organization's agreed retention period.",
            "Technical",
            "Manual validation",
        ),
        (
            "Security-event review",
            "Review records show events are examined and significant events escalated.",
            "Operational",
            "Manual validation",
        ),
        (
            "Logging governance",
            "An approved supporting policy defines logging responsibilities and expectations.",
            "Governance",
            "Approved policy",
        ),
    ],
    "A.8.16": [
        (
            "Monitoring coverage",
            "Defined systems and services are covered by monitoring.",
            "Technical",
            "Monitoring coverage",
        ),
        (
            "Alert triage",
            "Sample alerts demonstrate timely triage by an assigned owner.",
            "Operational",
            "Manual validation",
        ),
        (
            "Monitoring review",
            "Periodic reviews assess monitoring effectiveness and unresolved exceptions.",
            "Process",
            "Manual validation",
        ),
    ],
    "A.5.9": [
        (
            "Asset inventory coverage",
            "The configured asset set is recorded in the canonical inventory.",
            "Technical",
            "Asset discovery",
        ),
        (
            "Asset ownership",
            "Sampled assets have accountable owners and an agreed review process.",
            "Governance",
            "Manual validation",
        ),
        (
            "Inventory reconciliation",
            "Discovery and business records are reconciled and exceptions tracked.",
            "Operational",
            "Manual validation",
        ),
    ],
    "A.5.12": [
        (
            "Classification coverage",
            "The configured information assets have an assigned classification.",
            "Technical",
            "Classification coverage",
        ),
        (
            "Classification scheme",
            "The organization has defined classification criteria and handling expectations.",
            "Documentary",
            "Manual validation",
        ),
        (
            "Classification review",
            "Owners review classification against business and stakeholder needs.",
            "Operational",
            "Manual validation",
        ),
    ],
    "A.8.8": [
        (
            "Current vulnerability assessment",
            "A completed vulnerability assessment covers the configured assets.",
            "Technical",
            "Recent vulnerability scan",
        ),
        (
            "Vulnerability triage",
            "Identified vulnerabilities are prioritized and assigned to owners.",
            "Operational",
            "Manual validation",
        ),
        (
            "Remediation verification",
            "Evidence verifies completed remediation and documents remaining exposure.",
            "Technical",
            "Manual validation",
        ),
    ],
    "A.5.1": [
        (
            "Approved security policies",
            "Approved policies address the organization's security objectives and obligations.",
            "Governance",
            "Approved policy",
        ),
        (
            "Policy communication",
            "Relevant people can access and understand the policies that apply to them.",
            "Human",
            "Manual validation",
        ),
        (
            "Policy review",
            "Policy reviews address changes and record accountable decisions.",
            "Process",
            "Manual validation",
        ),
    ],
}


def item_type(reference: str) -> str:
    """Return the display type for a canonical reference.

    Args:
        reference: ISO entry ID.
    Returns:
        Annex A Control or ISO Requirement.
    Raises:
        No exceptions for string references.
    """
    return "Annex A Control" if reference.startswith("A.") else "ISO Requirement"


def template_version_for(reference: str) -> int:
    """Return authored version for a control; other controls including clock retain v2.

    Args:
        reference: Canonical control ID.
    Returns:
        Version 3 for M3 controls, otherwise the unchanged version 2.
    Raises:
        No expected exceptions.
    """
    return (
        M3_TEMPLATE_VERSION
        if reference in {"A.8.8", "A.8.9", "A.8.24", "A.8.5"}
        else TEMPLATE_VERSION
    )


def baseline_requirements(reference: str) -> list[dict]:
    """Build independent criterion values from an immutable template definition.

    Args:
        reference: Supported canonical entry ID.
    Returns:
        New criterion dictionaries, or an empty list for unsupported references.
    Raises:
        No exceptions for string references.
    """
    title = LABELS.get(reference)
    if not title:
        return []
    checks = SPECIAL.get(reference) or [
        (
            f"Defined approach — {title}",
            f"The organization defines its approach to {title.lower()}, "
            "with accountable ownership and scope.",
            "Governance",
            "Manual validation",
        ),
        (
            f"Implementation — {title}",
            f"Scoped records, inspection or interviews demonstrate the agreed {title.lower()} "
            "arrangements are implemented.",
            "Operational",
            "Manual validation",
        ),
        (
            f"Operating review — {title}",
            f"Dated operating records and reviews demonstrate that {title.lower()} "
            "arrangements work and exceptions are addressed.",
            "Process",
            "Manual validation",
        ),
    ]
    technical = {
        "A.8.9": "Secure web configuration baseline",
        "A.8.24": "Transport encryption configuration",
        "A.8.5": "No default credentials on in-scope services",
        "A.8.17": "Clock synchronization",
    }
    if reference in technical:
        rule = technical[reference]
        checks = [
            *checks,
            (rule, "Explicit technical results cover the configured assets.", "Technical", rule),
        ]
    result = []
    for index, (name, expected, kind, rule) in enumerate(checks, 1):
        template_id = f"{reference}:baseline:{index}"
        machine = rule not in {"Manual validation", "Approved policy"}
        result.append(
            dict(
                id=str(uuid5(NAMESPACE_URL, template_id)),
                template_id=template_id,
                template_version=template_version_for(reference),
                source_kind="SecureScope Baseline",
                source=NOTICE,
                title=name[:200],
                description=expected,
                expected_result=expected,
                type=kind,
                mandatory=True,
                rule=rule,
                group="Control Implementation",
                policy_required="Required" if rule == "Approved policy" else "Not Required",
                evidence_required=True,
                machine_verifiable=machine,
                human_review_required=not machine,
                suggested_sources=(
                    ["Validated scoped provider evidence"]
                    if machine
                    else ["Records", "Interview", "Observation"]
                ),
                guidance=(
                    "Confirm applicability, expected result and scope before assessing"
                    " this criterion."
                ),
                max_age_days=90,
                threshold=100,
                asset_ids=[],
                policy_ids=[],
                evidence_links=[],
                follow_provider=machine,
            )
        )
        if reference in {"A.8.9", "A.8.24", "A.8.5"} and rule != "Manual validation":
            from securescope.evidence.nuclei_assurance import RULE_VERSION, RULES

            result[-1].update(
                nuclei_rule_version=RULE_VERSION,
                nuclei_template_ids=list(RULES[rule].template_ids),
                guidance="Review the exact template predicates against your baseline. "
                "Supported positive findings identify gaps. Empty JSONL cannot prove this criterion passed.",
            )
    return result


def merge_baseline(reference: str, config: dict) -> tuple[list[dict], bool]:
    """Seed once without overwriting custom or previously edited criteria.

    Args:
        reference: Canonical entry ID.
        config: Existing profile requirement configuration.
    Returns:
        Pair of merged requirements and whether a baseline seed is needed.
    Raises:
        No exceptions for valid profile dictionaries.
    """
    current = supersede_seeded_requirements(config.get("requirements", []))
    baseline = baseline_requirements(reference)
    if not baseline or config.get("baseline_template_version", 0) >= template_version_for(
        reference
    ):
        return current, False
    if config.get("baseline_template_version", 0) >= 2 and template_version_for(reference) == 3:
        # A v3 review must not resurrect requirements the reviewer deliberately removed.
        return current, True
    for proposed in baseline:
        existing = next(
            (
                r
                for r in current
                if r.get("template_id") == proposed["template_id"] or r["id"] == proposed["id"]
            ),
            None,
        )
        if existing:
            if (
                reference == "A.8.16"
                and proposed["template_id"] == "A.8.16:baseline:1"
                and existing.get("rule") == "Log source coverage"
                and existing.get("title") == proposed["title"]
                and existing.get("template_version", 1) < 2
            ):
                existing["rule"] = proposed["rule"]
                existing["template_version"] = TEMPLATE_VERSION
            continue
        equivalent = next(
            (
                r
                for r in current
                if r.get("rule") == proposed["rule"]
                and r.get("title", "").strip().casefold() == proposed["title"].casefold()
            ),
            None,
        )
        if equivalent:
            equivalent.setdefault("template_id", proposed["template_id"])
            equivalent.setdefault("template_version", TEMPLATE_VERSION)
            equivalent.setdefault("source", NOTICE)
        else:
            current.append(proposed)
    return current, True


def supersede_seeded_requirements(requirements):
    """Keep a customized technical criterion in place of its exact seeded equivalent.

    Args:
        requirements: Current submitted requirement dictionaries.
    Returns:
        New list preserving custom identifiers and baseline provenance.
    Raises:
        No expected exceptions for validated dictionaries.
    """
    rows = deepcopy(requirements)
    removed = set()
    for seeded in rows:
        if not seeded.get("template_id") or seeded.get("asset_ids"):
            continue
        customized = next(
            (
                r
                for r in rows
                if r["id"] != seeded["id"]
                and r.get("rule") != "Manual validation"
                and r.get("rule") == seeded.get("rule")
                and r.get("title", "").strip().casefold()
                == seeded.get("title", "").strip().casefold()
                and r.get("asset_ids")
            ),
            None,
        )
        if customized:
            customized.setdefault("template_id", seeded["template_id"])
            customized.setdefault(
                "template_version", seeded.get("template_version", TEMPLATE_VERSION)
            )
            customized.setdefault("baseline_source", seeded.get("source", NOTICE))
            removed.add(seeded["id"])
    return [r for r in rows if r["id"] not in removed]
