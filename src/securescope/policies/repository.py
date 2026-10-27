"""Per-policy lifecycle using the existing immutable Foundation version store."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import date, datetime, timezone

from cryptography.fernet import InvalidToken
from psycopg2.extras import Json

from securescope.integrations.credential_store import credential_cipher
from securescope.persistence.foundation_repository import (
    member_role,
    versions,
    workspace_cursor,
)
from securescope.policies.documents import MAX_BYTES, validate_blocks


class PolicyError(ValueError):
    """Policy validation, encryption or lifecycle failure."""


def policy_rows(snapshot: dict, scope_id: int) -> list[dict]:
    """Adapt legacy rows without replacing stored historical versions.

    Args:
        snapshot: Existing Foundation version.
        scope_id: Selected scope identifier.
    Returns:
        Policy rows with stable identities and individual states.
    Raises:
        ValueError: For malformed stored records.
    """
    rows = []
    for index, record in enumerate(snapshot.get("records", [])):
        row = dict(record)
        row.setdefault(
            "policy_id", str(uuid.uuid5(uuid.NAMESPACE_URL, f"scope:{scope_id}:policy:{index}"))
        )
        row.setdefault("policy_version", int(snapshot.get("version", 1)))
        row.setdefault("status", snapshot.get("status", "Draft"))
        row.setdefault("controls", [])
        rows.append(row)
    return rows


def document_payload(row: dict) -> dict:
    """Decrypt document content only on demand; adapt legacy plain text.

    Args:
        row: Stored policy metadata.
    Returns:
        Blocks and optional original source bytes encoded as base64.
    Raises:
        PolicyError: If ciphertext is invalid.
        CredentialStoreError: If the host encryption key is unavailable.
    """
    if not row.get("document_ciphertext"):
        return {"blocks": [{"kind": "p", "runs": [{"text": str(row.get("policy_text", ""))}]}]}
    try:
        return json.loads(credential_cipher().decrypt(row["document_ciphertext"].encode()))
    except (InvalidToken, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(
            "Policy content cannot be decrypted with this installation's key."
        ) from exc


def load_policies(client: str, engagement: int, scope: int) -> tuple[list[dict], list[dict]]:
    """Read policies and register snapshots for one context.

    Args:
        client: Workspace name.
        engagement: Engagement identifier.
        scope: Scope identifier.
    Returns:
        Current policy rows and immutable history.
    Raises:
        FoundationError: On persistence failure.
    """
    history = versions(client, engagement, scope, "policy")
    return policy_rows(history[0], scope) if history else [], history


def save_policy(
    client: str,
    engagement: int,
    scope: int,
    *,
    actor: str,
    policy_id: str,
    expected_version: int,
    status: str,
    note: str,
    metadata: dict,
    blocks: list[dict] | None = None,
    source: bytes | None = None,
) -> int:
    """Append one policy transition while preserving all other policies.

    Args:
        client: Workspace name.
        engagement: Engagement identifier.
        scope: Scope identifier.
        actor: Trusted authenticated principal.
        policy_id: Existing UUID or new UUID for a draft.
        expected_version: Last observed register revision.
        status: Draft, In review, Approved or Archived.
        note: Human change/review rationale.
        metadata: Title, owner, reviewer, review date and control IDs.
        blocks: Structured draft content; omitted for approval.
        source: Optional original uploaded bytes for an encrypted draft.
    Returns:
        New register version number.
    Raises:
        PolicyError: For invalid input, denied actions or stale changes.
        FoundationError: If database operations fail.
        CredentialStoreError: If encryption is unavailable.
    """
    try:
        uuid.UUID(policy_id)
    except ValueError as exc:
        raise PolicyError("Invalid policy identity.") from exc
    if status not in {"Draft", "In review", "Approved", "Archived"}:
        raise PolicyError("Invalid policy status.")
    if not note.strip():
        raise PolicyError("A change or review summary is required.")
    with workspace_cursor(client) as (cursor, client_id):
        role = member_role(cursor, client_id, actor)
        if role not in {"Administrator", "Consultant", "Client contributor"}:
            raise PolicyError("An active contributor membership is required.")
        cursor.execute(
            (
                "SELECT 1 FROM securescope_scope_definitions WHERE client_id=%s "
                "AND engagement_id=%s AND id=%s"
            ),
            (client_id, engagement, scope),
        )
        if not cursor.fetchone():
            raise PolicyError("Scope does not belong to this engagement.")
        cursor.execute(
            (
                "SELECT * FROM securescope_foundation_versions WHERE client_id=%s "
                "AND engagement_id=%s AND scope_id=%s AND register_key='policy' "
                "ORDER BY version DESC LIMIT 1"
            ),
            (client_id, engagement, scope),
        )
        snapshot = cursor.fetchone() or {}
        revision = int(snapshot.get("version", 0))
        if revision != expected_version:
            raise PolicyError("Policies changed in another session. Reload before saving.")
        rows = policy_rows(snapshot, scope)
        old = next((row for row in rows if row["policy_id"] == policy_id), None)
        row = dict(old or {})
        prior = row.get("status", "Not started")
        if status == "Draft":
            title = str(metadata.get("title", "")).strip()
            owner = str(metadata.get("owner", "")).strip()
            if not title or not owner or len(title) > 160:
                raise PolicyError("A title (up to 160 characters) and owner are required.")
            clean = validate_blocks(blocks)
            if not any(run["text"].strip() for block in clean for run in block["runs"]):
                raise PolicyError("Add document content before saving.")
            controls = metadata.get("controls", [])
            if (
                not isinstance(controls, list)
                or len(controls) > 123
                or not all(isinstance(cid, str) for cid in controls)
            ):
                raise PolicyError("Invalid control selection.")
            cursor.execute(
                "SELECT control_id FROM securescope_control_assessment_profiles WHERE client_id=%s",
                (client_id,),
            )
            known = {item["control_id"] for item in cursor.fetchall()}
            if not set(controls).issubset(known):
                raise PolicyError("Select controls from this workspace's control catalog.")
            review_date = str(metadata.get("review_date", ""))
            if review_date:
                date.fromisoformat(review_date)
            payload = document_payload(row) if old else {}
            payload["blocks"] = clean
            reviewed = metadata.get("reviewed_sections", {})
            if (
                not isinstance(reviewed, dict)
                or len(reviewed) > 1000
                or not all(
                    isinstance(k, str) and len(k) <= 1000 and isinstance(v, bool)
                    for k, v in reviewed.items()
                )
            ):
                raise PolicyError("Invalid section review state.")
            payload["reviewed_sections"] = reviewed
            if source is not None:
                if len(source) > MAX_BYTES:
                    raise PolicyError("Source exceeds 2 MiB.")
                payload["source_base64"] = base64.b64encode(source).decode()
            row.update(
                {
                    field: str(metadata.get(field, ""))
                    for field in ("title", "owner", "reviewer", "review_date")
                }
            )
            for field in ("purpose", "renewal_cadence"):
                row[field] = str(metadata.get(field, row.get(field, "")))[:2000]
            row["controls"] = list(dict.fromkeys(controls))
            if source is not None:
                row["source_name"] = str(metadata.get("source_name", "document"))
                row["source_size"] = len(source)
                row["uploaded_by"] = actor
                row["uploaded_at"] = datetime.now(timezone.utc).isoformat()
            row["document_ciphertext"] = (
                credential_cipher().encrypt(json.dumps(payload).encode()).decode()
            )
            row.pop("policy_text", None)
            row.pop("approved_by", None)
            row.pop("approved_at", None)
            row["approvals"] = {}
        else:
            if blocks is not None or source is not None:
                raise PolicyError("Save content as a draft before changing its review state.")
            if status == "In review" and prior not in {"Draft", "Suggested"}:
                raise PolicyError("Save a draft before requesting review.")
            if status == "In review" and "approvers" in metadata:
                names = metadata["approvers"]
                if (
                    not isinstance(names, list)
                    or not names
                    or len(names) > 50
                    or not all(isinstance(n, str) for n in names)
                ):
                    raise PolicyError("Select at least one Administrator approver.")
                names = list(dict.fromkeys(n.strip().lower() for n in names))
                if any(member_role(cursor, client_id, n) != "Administrator" for n in names):
                    raise PolicyError("Approvers must be active workspace Administrators.")
                review_date = str(metadata.get("review_date", ""))
                date.fromisoformat(review_date)
                row.update(
                    approvers=names, reviewer=names[0], review_date=review_date, approvals={}
                )
            if status == "In review" and (not row.get("reviewer") or not row.get("review_date")):
                raise PolicyError("Set a reviewer and review date before submitting.")
            if status == "Approved":
                if role != "Administrator" or prior != "In review":
                    raise PolicyError("An Administrator may approve only a submitted version.")
                approvers = row.get("approvers", [])
                approvals = dict(row.get("approvals", {}))
                if approvers and (actor not in approvers or actor in approvals):
                    raise PolicyError(
                        "Only an assigned approver with a pending decision may approve."
                    )
                stamp = datetime.now(timezone.utc).isoformat()
                approvals[actor] = {"at": stamp, "note": note.strip()}
                row["approvals"] = approvals
                if approvers and not all(name in approvals for name in approvers):
                    status = "In review"
                else:
                    row["approved_by"] = actor
                    row["approved_at"] = stamp
            if status == "Archived" and (role != "Administrator" or old is None):
                raise PolicyError("Only an Administrator may archive a policy.")
        row.update(
            policy_id=policy_id,
            policy_version=int(row.get("policy_version", 0)) + 1,
            status=status,
            updated_by=actor,
            updated_at=datetime.now(timezone.utc).isoformat(),
            change_summary=note.strip(),
        )
        rows = [row if item["policy_id"] == policy_id else item for item in rows]
        if old is None:
            rows.append(row)
        active = [item for item in rows if item.get("status") != "Archived"]
        aggregate = (
            "Approved"
            if active and all(item.get("status") == "Approved" for item in active)
            else "Draft"
        )
        if any(item.get("status") == "In review" for item in active):
            aggregate = "In review"
        cursor.execute(
            (
                (
                    "INSERT INTO securescope_foundation_versions "
                    "(client_id,engagement_id,scope_id,register_key,version,statu"
                    "s,records,owner,recorded_by,review_note,approved_by) VALUES "
                    "(%s,%s,%s,'policy',%s,%s,%s,%s,%s,%s,%s)"
                )
            ),
            (
                client_id,
                engagement,
                scope,
                revision + 1,
                aggregate,
                Json(rows),
                row.get("owner", actor),
                actor,
                note.strip(),
                actor if aggregate == "Approved" else None,
            ),
        )
        return revision + 1


def upload_policy(
    client: str,
    engagement: int,
    scope: int,
    *,
    actor: str,
    expected_version: int,
    filename: str,
    content: bytes,
) -> str:
    """Extract and persist an encrypted draft; never imply an upload is approved."""
    from securescope.policies.documents import extract_document

    extracted = extract_document(filename, content)
    policy_id = str(uuid.uuid4())
    save_policy(
        client,
        engagement,
        scope,
        actor=actor,
        policy_id=policy_id,
        expected_version=expected_version,
        status="Draft",
        note="Uploaded document; extracted content awaits human review.",
        metadata={
            "title": extracted["title"][:160],
            "owner": actor,
            "source_name": extracted["filename"],
            "controls": [],
        },
        blocks=extracted["blocks"],
        source=content,
    )
    return policy_id
