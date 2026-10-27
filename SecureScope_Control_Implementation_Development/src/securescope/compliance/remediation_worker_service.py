"""Asynchronous worker for strictly approved Wazuh remediation recipes."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from securescope.compliance.remediation_recipe_service import RemediationRecipeRegistry
from securescope.core.output_sanitizer import concise_output
from securescope.integrations.wazuh_remediation_adapter import (
    ApprovedExecutionRequest,
    RemediationExecutionError,
    WazuhRemediationAdapter,
)
from securescope.persistence.nuclei_persistence import (
    create_nuclei_batch,
    request_nuclei_worker_wake,
)
from securescope.persistence.remediation_execution_repository import (
    claim_approved_execution,
    claim_due_verification,
    update_execution_status,
)

LOGGER = logging.getLogger(__name__)


def run_remediation_worker_cycle() -> dict[str, Any]:
    """Dispatch at most one approved execution and queue verification.

    Returns:
        Cycle outcome with no credential-bearing response data.

    Raises:
        ValueError: Never raised for expected execution failures; failures are
            persisted against the claimed request.
    """

    adapter = WazuhRemediationAdapter()
    if not adapter.execution_enabled():
        return {"status": "Disabled", "processed": 0}
    due_verification = claim_due_verification()
    if due_verification:
        return _queue_verification(due_verification)
    execution = claim_approved_execution()
    if not execution:
        return {"status": "Idle", "processed": 0}
    execution_id = int(execution["id"])
    client_name = str(execution["client_name"])
    try:
        registry = RemediationRecipeRegistry.load()
        recipe = registry.get(str(execution["recipe_id"]))
        if recipe.version != str(execution["recipe_version"]):
            raise RemediationExecutionError(
                "Approved recipe version no longer matches the registry."
            )
        if recipe.artifact_sha256 != str(execution["recipe_checksum"]):
            raise RemediationExecutionError(
                "Approved recipe checksum no longer matches the registry."
            )
        request = ApprovedExecutionRequest(
            workspace_name=client_name,
            confirmed_workspace_name=client_name,
            asset_identity=str(execution["asset_identity"]),
            confirmed_asset_identity=str(execution["asset_identity"]),
            wazuh_agent_id=str(execution["wazuh_agent_id"]),
            wazuh_agent_status=str(execution["wazuh_agent_status"]),
            approver=str(execution["approved_by"]),
            approval_recorded=True,
            recipe=recipe,
        )
        dispatch = adapter.dispatch(request)
        if not dispatch.get("accepted"):
            raise RemediationExecutionError(
                "Wazuh did not accept the reviewed remediation command."
            )
        try:
            delay_seconds = max(
                60,
                int(os.getenv("REMEDIATION_VERIFICATION_DELAY_SECONDS", "3600")),
            )
        except ValueError:
            delay_seconds = 3600
        verification_not_before = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
        update_execution_status(
            client_name,
            execution_id,
            "Running",
            actor=os.getenv("REMEDIATION_WORKER_NAME", "remediation-worker"),
            reason=(
                "Allow-listed command accepted; delayed verification window "
                "scheduled so endpoint work is not scanned immediately."
            ),
            values={
                "dispatch_result": dispatch,
                "sanitized_log": concise_output(dispatch.get("message"), 2000),
                "verification_not_before": verification_not_before,
            },
        )
        return {
            "status": "Running",
            "processed": 1,
            "execution_id": execution_id,
            "verification_not_before": verification_not_before.isoformat(),
        }
    except Exception as exc:
        message = concise_output(f"{type(exc).__name__}: {exc}", 2000)
        LOGGER.exception("Remediation execution %s failed", execution_id)
        update_execution_status(
            client_name,
            execution_id,
            "Failed",
            actor=os.getenv("REMEDIATION_WORKER_NAME", "remediation-worker"),
            reason="Approved execution or verification queueing failed.",
            values={"failure_reason": message, "sanitized_log": message},
        )
        return {
            "status": "Failed",
            "processed": 1,
            "execution_id": execution_id,
            "error": message,
        }


def _queue_verification(execution: dict[str, Any]) -> dict[str, Any]:
    """Queue a single-asset Nuclei campaign after the execution delay.

    Args:
        execution: Claimed dispatched execution with exact workspace and asset.

    Returns:
        Cycle result containing the verification batch identifier.

    Raises:
        ValueError: Never raised for expected queue failures; failures are
            persisted against the execution.
    """

    execution_id = int(execution["id"])
    client_name = str(execution["client_name"])
    try:
        batch = create_nuclei_batch(
            client_name=client_name,
            assets=[
                {
                    "asset_tag": str(execution.get("asset_tag") or "Asset"),
                    "ip": str(execution["asset_ip"]),
                }
            ],
            scan_mode="Single asset",
            profile_name=os.getenv(
                "REMEDIATION_VERIFICATION_PROFILE",
                "standard",
            ),
            sync_to_ciso=False,
        )
        batch_id = int(batch["id"])
        request_nuclei_worker_wake(
            batch_id=batch_id,
            reason=f"Verification for remediation execution #{execution_id}.",
        )
        update_execution_status(
            client_name,
            execution_id,
            "Pending verification",
            actor=os.getenv("REMEDIATION_WORKER_NAME", "remediation-worker"),
            reason="Fresh targeted verification campaign queued after delay.",
            values={
                "verification_batch_id": batch_id,
                "verification_reference": f"Nuclei batch #{batch_id}",
            },
        )
        return {
            "status": "Pending verification",
            "processed": 1,
            "execution_id": execution_id,
            "verification_batch_id": batch_id,
        }
    except Exception as exc:
        message = concise_output(f"{type(exc).__name__}: {exc}", 2000)
        LOGGER.exception("Verification queue for execution %s failed", execution_id)
        update_execution_status(
            client_name,
            execution_id,
            "Failed",
            actor=os.getenv("REMEDIATION_WORKER_NAME", "remediation-worker"),
            reason="Targeted verification queueing failed.",
            values={"failure_reason": message, "sanitized_log": message},
        )
        return {
            "status": "Failed",
            "processed": 1,
            "execution_id": execution_id,
            "error": message,
        }
