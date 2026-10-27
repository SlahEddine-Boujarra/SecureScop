"""Periodic explainable control evaluation in the existing evidence worker."""

import logging

from securescope.integrations.credential_store import CredentialStoreError
from securescope.persistence.assurance_workspace_repository import (
    automated_candidates,
    collect_inventory_evidence,
    load_workspace,
    record_evaluation,
)
from securescope.persistence.db_service import DatabaseError
from securescope.persistence.evidence_repository import EvidenceRepositoryError
from securescope.persistence.foundation_repository import FoundationError

LOGGER = logging.getLogger(__name__)


_CANDIDATE_PASS = None


def _bounded_candidates(limit):
    """Resume a bounded candidate pass between worker ticks; return an iterator."""
    global _CANDIDATE_PASS
    if _CANDIDATE_PASS is None:
        _CANDIDATE_PASS = iter(automated_candidates())
    for _ in range(limit):
        row = next(_CANDIDATE_PASS, None)
        if row is None:
            _CANDIDATE_PASS = None
            break
        yield row


def refresh_continuous_assurance(*, max_profiles: int | None = None) -> int:
    """Re-evaluate enabled profiles without approving policies, scopes or risk acceptance.

    Args:
        None.
    Returns:
        Number of scoped configurations successfully evaluated.
    Raises:
        DatabaseError: If the initial candidate read fails.
    """
    count = 0
    for row in (_bounded_candidates(max_profiles) if max_profiles else automated_candidates()):
        config = row["assessment_scope"]["implementation_requirements"]
        try:
            view = load_workspace(
                row["client_name"],
                row["control_id"],
                config.get("auto_enabled_by") or "",
                int(config["engagement_id"]),
                int(config["scope_id"]),
            )
            if view["role"] != "Administrator":
                LOGGER.warning(
                    "Continuous assurance paused: enabling administrator is no longer authorized."
                )
                continue
            from datetime import datetime, timedelta, timezone

            from securescope.grc.control_implementation import as_datetime

            inventory = [
                e
                for e in view["bundle"]["requirement_evidence"]
                if e["tool_id"] == "asset_inventory"
            ]
            timestamps = [as_datetime(e["collected_at"]) for e in inventory]
            latest = max((stamp for stamp in timestamps if stamp), default=None)
            if any(
                r.get("follow_provider")
                and r["rule"] in {"Classification coverage", "Asset discovery"}
                for r in config.get("requirements", [])
            ) and (not latest or latest < datetime.now(timezone.utc) - timedelta(days=1)):
                collect_inventory_evidence(
                    row["client_name"],
                    row["control_id"],
                    config["auto_enabled_by"],
                    int(config["engagement_id"]),
                    int(config["scope_id"]),
                )
            record_evaluation(
                row["client_name"],
                row["control_id"],
                config.get("auto_enabled_by") or "",
                int(config["engagement_id"]),
                int(config["scope_id"]),
            )
            count += 1
        except (
            FoundationError,
            EvidenceRepositoryError,
            CredentialStoreError,
            DatabaseError,
            ValueError,
        ) as exc:
            LOGGER.warning("Continuous assurance evaluation unavailable: %s", type(exc).__name__)
    return count
