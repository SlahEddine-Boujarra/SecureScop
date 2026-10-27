"""Optional starter documents; this set is guidance, not an ISO-mandated list."""

from __future__ import annotations

import uuid

from securescope.policies.repository import load_policies, save_policy

STARTERS = (
    ("Information Security", "A.5.1"),
    ("Access Control", "A.5.15"),
    ("Asset Management", "A.5.9"),
    ("Acceptable Use", "A.5.10"),
    ("Cryptography", "A.8.24"),
    ("Physical Security", "A.7.1"),
    ("Operations Security", "A.5.37"),
    ("Change Management", "A.8.32"),
    ("Backup", "A.8.13"),
    ("Logging and Monitoring", "A.8.15"),
    ("Network Security", "A.8.20"),
    ("Data Management and Classification", "A.5.12"),
    ("Data Retention and Disposal", "A.8.10"),
    ("Human Resources Security", "A.6.2"),
    ("Third-Party and Supplier Security", "A.5.19"),
    ("Business Continuity and Disaster Recovery", "A.5.30"),
    ("Incident Response", "A.5.24"),
    ("Risk Management", "A.5.1"),
    ("Vulnerability Management", "A.8.8"),
    ("Secure Development", "A.8.25"),
    ("Remote Working", "A.6.7"),
    ("Mobile Devices and BYOD", "A.8.1"),
    ("Password", "A.5.17"),
    ("Code of Conduct", "A.5.4"),
    ("Information Security Roles and Responsibilities", "A.5.2"),
)
SECTIONS = (
    "Purpose and scope",
    "Responsibilities",
    "Policy requirements",
    "Exceptions and escalation",
    "Review and maintenance",
)


def starter_blocks(title: str) -> list[dict]:
    """Return clearly unfinished, editable guidance rather than an approved policy."""
    blocks = []
    for section in SECTIONS:
        blocks.extend(
            [
                {"kind": "h2", "runs": [{"text": section}]},
                {
                    "kind": "p",
                    "runs": [
                        {
                            ("text"): (
                                "[Draft guidance] Describe "
                                f"{section.lower()}"
                                " for your "
                                f"{title.lower()}"
                                " policy. Tailor this section to your organization before "
                                "review."
                            )
                        }
                    ],
                },
            ]
        )
    return blocks


def add_starter_policies(
    client: str, engagement: int, scope: int, *, actor: str, known_controls: set[str]
) -> int:
    """Add missing starters without replacing client policies; each write is versioned."""
    rows, history = load_policies(client, engagement, scope)
    titles = {row.get("title", "").casefold() for row in rows}
    revision = int(history[0]["version"]) if history else 0
    count = 0
    for name, control in STARTERS:
        title = name + " Policy"
        if title.casefold() in titles:
            continue
        revision = save_policy(
            client,
            engagement,
            scope,
            actor=actor,
            policy_id=str(uuid.uuid4()),
            expected_version=revision,
            status="Draft",
            note="Added unfinished starter guidance; human tailoring required.",
            metadata={
                "title": title,
                "owner": actor,
                "controls": [control] if control in known_controls else [],
                "purpose": f"Define organization-specific expectations for {name.lower()}.",
                "renewal_cadence": "Annual",
            },
            blocks=starter_blocks(name),
        )
        count += 1
    return count
