"""Editable policy suggestions, scoped to the organization's own decisions."""

from __future__ import annotations

from securescope.policies.catalog import STARTERS

TOPICS = {
    "Information Security": (
        "Security governance",
        (
            "Management assigns accountable security owners and reviews "
            "information security objectives."
        ),
        "Security exceptions are documented, assessed and approved by an authorized owner.",
    ),
    "Access Control": (
        "Access authorization",
        (
            "Access is granted according to documented business need and "
            "approved by the information owner."
        ),
        "Access rights are reviewed at defined intervals and removed when no longer required.",
    ),
    "Asset Management": (
        "Asset ownership",
        (
            "Information and associated assets are recorded in the inventory "
            "with an accountable owner."
        ),
        "Owners review classification, location and lifecycle information when assets change.",
    ),
    "Acceptable Use": (
        "Acceptable use",
        "Personnel use organizational information and systems only for authorized purposes.",
        "Suspected misuse or loss of an asset is reported through the incident reporting process.",
    ),
    "Cryptography": (
        "Cryptographic protection",
        (
            "Information owners identify where encryption is required "
            "according to classification and risk."
        ),
        (
            "Cryptographic keys have assigned custodians and documented "
            "generation, storage, rotation and revocation procedures."
        ),
    ),
    "Physical Security": (
        "Physical access",
        "Access to restricted facilities is authorized, recorded and reviewed.",
        "Visitors are identified and supervised according to the sensitivity of the area.",
    ),
    "Operations Security": (
        "Operating procedures",
        "Operational procedures identify responsibilities, dependencies and escalation routes.",
        "Operational changes and exceptions are recorded and reviewed by the responsible owner.",
    ),
    "Change Management": (
        "Change approval",
        "Changes are assessed for security impact, tested and authorized before implementation.",
        "Emergency changes include a rollback approach and receive a retrospective review.",
    ),
    "Backup": (
        "Backup and recovery",
        "Backup scope, frequency and retention reflect documented recovery requirements.",
        (
            "Restoration tests verify that protected information can be "
            "recovered within agreed objectives."
        ),
    ),
    "Logging and Monitoring": (
        "Security logging",
        (
            "Relevant security events are collected with timestamps and "
            "protected against unauthorized modification."
        ),
        (
            "Assigned personnel review alerts and investigate suspicious "
            "activity using the incident process."
        ),
    ),
    "Network Security": (
        "Network boundaries",
        (
            "Network access and segmentation reflect information sensitivity "
            "and approved service requirements."
        ),
        "Network rule changes are authorized and unused services and connections are removed.",
    ),
    "Data Management and Classification": (
        "Information classification",
        "Information is classified by its owner and handled according to its sensitivity.",
        (
            "Sharing and transfer methods are selected according to "
            "classification and recipient authorization."
        ),
    ),
    "Data Retention and Disposal": (
        "Retention and disposal",
        (
            "Retention periods are documented for each information category "
            "using business and applicable obligations."
        ),
        (
            "Information is securely disposed of when retention expires, "
            "unless a documented hold applies."
        ),
    ),
    "Human Resources Security": (
        "Personnel lifecycle",
        (
            "Security responsibilities are communicated before access is "
            "granted and when roles change."
        ),
        (
            "Joiner, mover and leaver actions coordinate access, assets and "
            "confidentiality obligations."
        ),
    ),
    "Third-Party and Supplier Security": (
        "Supplier assurance",
        (
            "Supplier risk is assessed before engagement and security "
            "expectations are recorded in agreements."
        ),
        (
            "Supplier access and assurance evidence are reviewed during the "
            "relationship and at termination."
        ),
    ),
    "Business Continuity and Disaster Recovery": (
        "Continuity planning",
        (
            "Critical activities have documented recovery objectives, "
            "dependencies and accountable recovery owners."
        ),
        (
            "Continuity plans are exercised and updated following significant "
            "changes or lessons learned."
        ),
    ),
    "Incident Response": (
        "Incident handling",
        "Personnel report suspected security events using documented reporting channels.",
        (
            "Incident responders assess, contain and recover from incidents "
            "while preserving appropriate evidence."
        ),
    ),
    "Risk Management": (
        "Risk assessment",
        (
            "Risk owners record scenarios, existing controls, likelihood and "
            "impact using the approved methodology."
        ),
        (
            "Treatment and acceptance decisions are authorized and reviewed "
            "when assumptions or conditions change."
        ),
    ),
    "Vulnerability Management": (
        "Vulnerability handling",
        (
            "Vulnerabilities are identified from approved technical and "
            "advisory sources and assessed for business impact."
        ),
        "Remediation owners track treatment through verification and record authorized exceptions.",
    ),
    "Secure Development": (
        "Development lifecycle",
        (
            "Security requirements and threat considerations are incorporated "
            "into system design and change planning."
        ),
        (
            "Code and dependencies are reviewed and tested before release "
            "using proportionate security checks."
        ),
    ),
    "Remote Working": (
        "Remote access",
        (
            "Remote access uses approved devices and authentication "
            "appropriate to the information accessed."
        ),
        (
            "Personnel protect information from unauthorized viewing, storage "
            "and disclosure while working remotely."
        ),
    ),
    "Mobile Devices and BYOD": (
        "Mobile device use",
        (
            "Devices accessing organizational information meet defined "
            "protection and enrollment requirements."
        ),
        "Loss, theft and departure procedures address removal of organizational access and data.",
    ),
    "Password": (
        "Password policy",
        (
            "Authentication secrets are protected against disclosure and are "
            "unique to their intended accounts."
        ),
        (
            "Compromised authentication secrets are changed promptly using an "
            "identity-verified recovery process."
        ),
    ),
    "Code of Conduct": (
        "Expected conduct",
        (
            "Personnel act responsibly when handling information and report "
            "suspected policy violations."
        ),
        (
            "Conflicts of interest and exceptions are disclosed through an "
            "established escalation process."
        ),
    ),
    "Information Security Roles and Responsibilities": (
        "Accountability",
        "Security responsibilities, authority and deputies are documented and communicated.",
        (
            "Conflicting duties are identified and separated or addressed "
            "through documented compensating measures."
        ),
    ),
}
PASSWORD_CHOICES = [
    {
        "id": "password_unique",
        "group": "Password strength",
        "text": "Use unique passwords for organizational accounts.",
    },
    {
        "id": "password_blocklist",
        "group": "Password strength",
        "text": (
            "Check newly chosen passwords against a list of commonly used or "
            "compromised passwords."
        ),
    },
    {
        "id": "password_manager",
        "group": "Password strength",
        "text": "Allow approved password managers and long passphrases.",
    },
    {
        "id": "password_reset",
        "group": "Password updates",
        "text": "Verify identity before completing an account recovery or manual password reset.",
    },
    {
        "id": "password_compromised",
        "group": "Password updates",
        "text": "Change authentication secrets when compromise is suspected or confirmed.",
    },
    {
        "id": "password_storage",
        "group": "Password protection",
        "text": (
            "Store passwords using an approved salted, computationally "
            "expensive password-hashing method."
        ),
    },
    {
        "id": "password_rate",
        "group": "Password protection",
        "text": "Apply approved rate limits or other controls against automated guessing.",
    },
    {
        "id": "password_mfa",
        "group": "Password protection",
        "text": (
            "Require multi-factor authentication where specified by the "
            "access-control risk assessment."
        ),
    },
]


def policy_template(name: str, client: str) -> dict:
    """Return a substantive draft plus optional choices, without asserting adoption.

    Args:
        name: Known starter policy name.
        client: Organization label used in draft wording.
    Returns:
        Title, structured blocks, suggested controls and guidance.
    Raises:
        ValueError: If the starter name is unknown.
    """
    if name not in TOPICS:
        raise ValueError("Select a known policy template.")
    heading, first, second = TOPICS[name]
    title = name + (
        " Plan"
        if name in {"Incident Response", "Business Continuity and Disaster Recovery"}
        else " Policy"
    )
    sections = [
        (
            "Purpose and scope",
            (
                "This draft defines "
                f"{name.lower()}"
                " expectations for "
                f"{client}"
                ". The policy owner must confirm the covered people, "
                "information, systems and locations before "
                "approval."
            ),
        ),
        (
            "Responsibilities",
            (
                "The policy owner maintains this document, assigns operating "
                "responsibilities and escalates exceptions. Personnel and relevant"
                " third parties follow approved requirements applicable to their "
                "work."
            ),
        ),
        (heading, first + "\n" + second),
        (
            "Exceptions and escalation",
            (
                "Exceptions require a documented reason, risk assessment, "
                "accountable approver and review date. Suspected noncompliance or "
                "security incidents are reported through the agreed channels."
            ),
        ),
        (
            "Review and maintenance",
            (
                "The policy owner reviews this policy at the agreed renewal date "
                "and following material changes, incidents or new obligations. "
                "Approved revisions are communicated to affected personnel."
            ),
        ),
    ]
    if name == "Access Control":
        sections[3:3] = [
            (
                "Password policy",
                (
                    "Authentication requirements are selected according to business "
                    "risk and the approved authentication standard."
                ),
            ),
            (
                "Information access restriction",
                (
                    "Information owners authorize access based on role, business need "
                    "and information sensitivity. Permissions are reviewed and revoked"
                    " through the access lifecycle."
                ),
            ),
            (
                "Secure log-on procedures",
                (
                    "Log-on controls protect authentication data, limit unauthorized "
                    "attempts and provide appropriate authentication assurance for the"
                    " system."
                ),
            ),
        ]
    blocks = []
    for label, text in sections:
        blocks.append({"kind": "h2", "runs": [{"text": label}]})
        blocks.extend({"kind": "p", "runs": [{"text": line}]} for line in text.splitlines())
    control = dict(STARTERS)[name]
    return {
        "title": title,
        "blocks": blocks,
        "controls": [control],
        "purpose": f"Define and communicate {name.lower()} responsibilities and requirements.",
    }


def section_choices(title: str) -> list[dict]:
    """Return optional, clearly labeled suggestions for a policy section.

    Args:
        title: Section heading.
    Returns:
        Choice identifiers, categories and editable wording.
    Raises:
        No exceptions are raised.
    """
    if "password" in title.casefold():
        return PASSWORD_CHOICES
    return [
        {
            "id": "owner",
            "group": "Responsibilities",
            "text": "Assign an accountable owner and a deputy for this activity.",
        },
        {
            "id": "evidence",
            "group": "Review and evidence",
            "text": "Keep records demonstrating how these requirements are carried out.",
        },
        {
            "id": "exceptions",
            "group": "Review and evidence",
            "text": "Document exceptions, their approval and a date for reassessment.",
        },
    ]
