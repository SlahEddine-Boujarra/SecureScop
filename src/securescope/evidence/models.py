"""Domain objects for normalized, reviewable ISO evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CollectionMethod(str, Enum):
    """How an evidence item entered SecureScope."""

    EXISTING_WORKER = "Existing worker"
    DEFENSIVE_CLI = "Defensive local CLI"
    AUTHENTICATED_API = "Authenticated API"
    REPORT_IMPORT = "Report import"
    MANUAL = "Manual evidence"


class ReviewDecision(str, Enum):
    """Consultant review outcomes."""

    VALIDATED = "Validated"
    REJECTED = "Rejected"
    MORE_EVIDENCE = "More evidence required"


class WorkspaceRole(str, Enum):
    """Workspace roles used by the evidence service and API."""

    ADMINISTRATOR = "Administrator"
    CLIENT_CONTRIBUTOR = "Client contributor"
    CONSULTANT = "Consultant"
    AUDITOR = "Auditor"


@dataclass(frozen=True)
class NormalizedObservation:
    """A conservative observation extracted from a source report."""

    observation_id: str
    title: str
    severity: str = "Unknown"
    asset: str = ""
    description: str = ""
    references: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        result = asdict(self)
        result["references"] = list(self.references)
        return result


@dataclass(frozen=True)
class NormalizedEvidence:
    """Report metadata and observations safe for assessment services."""

    tool_id: str
    format_name: str
    source_filename: str
    parsed_at: datetime
    observations: tuple[NormalizedObservation, ...]
    metadata: dict[str, Any] = field(default_factory=dict)
    parser_warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        parsed_at = self.parsed_at
        if parsed_at.tzinfo is None:
            parsed_at = parsed_at.replace(tzinfo=timezone.utc)
        return {
            "tool_id": self.tool_id,
            "format_name": self.format_name,
            "source_filename": self.source_filename,
            "parsed_at": parsed_at.isoformat(),
            "observations": [item.to_dict() for item in self.observations],
            "metadata": self.metadata,
            "parser_warnings": list(self.parser_warnings),
        }


ROLE_CAPABILITIES: dict[WorkspaceRole, frozenset[str]] = {
    WorkspaceRole.ADMINISTRATOR: frozenset(
        {"configure", "collect", "import", "submit", "review", "export", "read"}
    ),
    WorkspaceRole.CLIENT_CONTRIBUTOR: frozenset({"import", "submit", "read"}),
    WorkspaceRole.CONSULTANT: frozenset(
        {"collect", "import", "submit", "review", "export", "read"}
    ),
    WorkspaceRole.AUDITOR: frozenset({"export", "read"}),
}


def role_can(role: WorkspaceRole | str, capability: str) -> bool:
    """Return whether one workspace role may perform a capability."""

    try:
        resolved = role if isinstance(role, WorkspaceRole) else WorkspaceRole(str(role))
    except ValueError:
        return False
    return capability in ROLE_CAPABILITIES[resolved]
