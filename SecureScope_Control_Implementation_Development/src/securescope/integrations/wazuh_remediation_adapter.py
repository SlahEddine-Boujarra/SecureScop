"""Guarded Wazuh Active Response adapter for approved remediation recipes."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from securescope.compliance.remediation_recipe_service import (
    RemediationRecipe,
    RemediationRecipeError,
)
from securescope.core.output_sanitizer import concise_output
from securescope.integrations.wazuh_service import WazuhClient, WazuhError


class RemediationExecutionError(RuntimeError):
    """Raised when an approved execution fails a safety prerequisite."""


def _env_true(name: str, default: bool = False) -> bool:
    """Read one strict Boolean environment value.

    Args:
        name: Environment variable name.
        default: Value used when the variable is absent.

    Returns:
        Parsed Boolean.

    Raises:
        ValueError: Never raised for normal environment text.
    """

    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def configured_command_allowlist() -> frozenset[str]:
    """Return the explicit Active Response command allow-list.

    Returns:
        Exact command identifiers configured by the administrator.

    Raises:
        ValueError: Never raised for normal configuration text.
    """

    return frozenset(
        token.strip()
        for token in os.getenv("WAZUH_REMEDIATION_COMMAND_ALLOWLIST", "")
        .replace(";", ",")
        .split(",")
        if token.strip()
    )


@dataclass(frozen=True)
class ApprovedExecutionRequest:
    """Safety context required before one Active Response dispatch.

    Args:
        workspace_name: Exact active SecureScope workspace.
        confirmed_workspace_name: Workspace text explicitly confirmed by approver.
        asset_identity: Canonical asset identity from the finding.
        confirmed_asset_identity: Asset identity explicitly confirmed by approver.
        wazuh_agent_id: Exact synchronized Wazuh agent ID.
        wazuh_agent_status: Current Wazuh agent state.
        approver: Person approving the execution.
        approval_recorded: Whether explicit UI approval was recorded.
        recipe: Integrity-checked recipe.

    Returns:
        Immutable execution request.

    Raises:
        RemediationExecutionError: If required safety context is missing.
    """

    workspace_name: str
    confirmed_workspace_name: str
    asset_identity: str
    confirmed_asset_identity: str
    wazuh_agent_id: str
    wazuh_agent_status: str
    approver: str
    approval_recorded: bool
    recipe: RemediationRecipe

    def validate(self) -> None:
        """Validate scope, approval, agent state, and recipe integrity.

        Returns:
            None when all prerequisites pass.

        Raises:
            RemediationExecutionError: If any prerequisite is not satisfied.
        """

        if not self.workspace_name.strip() or (
            self.workspace_name.strip() != self.confirmed_workspace_name.strip()
        ):
            raise RemediationExecutionError(
                "Workspace confirmation does not match the execution workspace."
            )
        if not self.asset_identity.strip() or (
            self.asset_identity.strip() != self.confirmed_asset_identity.strip()
        ):
            raise RemediationExecutionError(
                "Asset confirmation does not match the execution target."
            )
        if not self.approval_recorded or not self.approver.strip():
            raise RemediationExecutionError("Approved execution requires an identified approver.")
        if self.wazuh_agent_status.strip().casefold() not in (self.recipe.compatible_wazuh_states):
            raise RemediationExecutionError("The Wazuh agent is not active and synchronized.")
        try:
            self.recipe.verify_integrity()
        except RemediationRecipeError as exc:
            raise RemediationExecutionError(str(exc)) from exc


class WazuhRemediationAdapter:
    """Dispatch only integrity-checked, administrator-allow-listed recipes.

    Args:
        client: Optional Wazuh client used for dependency injection in tests.

    Returns:
        Adapter that honors the global default-off kill switch.

    Raises:
        WazuhError: Propagated when the Wazuh client cannot be configured.
    """

    def __init__(self, client: WazuhClient | None = None) -> None:
        """Initialize the adapter without executing any remote action.

        Args:
            client: Optional Wazuh client.

        Raises:
            WazuhError: If a default client is requested with invalid config.
        """

        self.client = client

    @staticmethod
    def execution_enabled() -> bool:
        """Return whether the global remediation kill switch is enabled.

        Returns:
            ``True`` only for explicit enabled configuration.

        Raises:
            ValueError: Never raised.
        """

        return _env_true("WAZUH_REMEDIATION_EXECUTION_ENABLED", False)

    def dispatch(self, request: ApprovedExecutionRequest) -> dict[str, Any]:
        """Dispatch one fixed command to one exact synchronized agent.

        Args:
            request: Validated approval and scope context.

        Returns:
            Sanitized Wazuh dispatch result for persistence and audit.

        Raises:
            RemediationExecutionError: If execution is disabled or unsafe.
        """

        if not self.execution_enabled():
            raise RemediationExecutionError(
                "Approved remediation execution is disabled by configuration."
            )
        request.validate()
        if request.recipe.execution_level != "Approved execution":
            raise RemediationExecutionError("This recipe is not approved for remote execution.")
        if request.recipe.command_id not in configured_command_allowlist():
            raise RemediationExecutionError(
                "The recipe command is not in the administrator allow-list."
            )
        client = self.client or WazuhClient()
        try:
            result = client.run_active_response(
                command_id=request.recipe.command_id,
                agent_id=request.wazuh_agent_id,
            )
        except WazuhError as exc:
            raise RemediationExecutionError(str(exc)) from exc
        return _sanitize_dispatch_result(result)


def _sanitize_dispatch_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only bounded Wazuh dispatch fields without tokens or raw secrets.

    Args:
        value: Wazuh API response mapping.

    Returns:
        Sanitized audit-safe dispatch result.

    Raises:
        RemediationExecutionError: If the response is not a mapping.
    """

    if not isinstance(value, Mapping):
        raise RemediationExecutionError("Wazuh dispatch result is invalid.")
    data = value.get("data")
    affected: list[str] = []
    failed_count = 0
    if isinstance(data, Mapping):
        raw_affected = data.get("affected_items")
        if isinstance(raw_affected, list):
            for item in raw_affected[:20]:
                if isinstance(item, Mapping):
                    identity = item.get("id") or item.get("agent")
                else:
                    identity = item
                if identity not in (None, ""):
                    affected.append(str(identity)[:64])
        try:
            failed_count = int(data.get("total_failed_items") or 0)
        except (TypeError, ValueError):
            failed_count = 0
    return {
        "error": value.get("error"),
        "message": concise_output(value.get("message"), 500),
        "affected_items": affected,
        "failed_count": failed_count,
        "accepted": bool(affected) and failed_count == 0,
    }
