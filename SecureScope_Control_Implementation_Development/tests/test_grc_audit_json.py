"""Regression coverage for date-safe, deterministic GRC audit payloads."""

import hashlib
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock

from securescope.persistence.grc_workspace_repository import _append_audit_event


def test_audit_hash_matches_stored_date_payload():
    """Stored dates/decimals reproduce the hash and preserve the prior chain link."""
    cursor = MagicMock()
    cursor.fetchone.return_value = {"event_hash": "previous-hash"}
    payload = {
        "due_date": date(2026, 11, 1),
        "nested": {"at": datetime(2026, 10, 4, tzinfo=timezone.utc), "amount": Decimal("1.25")},
    }
    _append_audit_event(
        cursor,
        1,
        2,
        event_type="milestone.created",
        entity_type="milestone",
        entity_id="3",
        actor="reviewer",
        summary="Milestone created",
        payload=payload,
    )
    values = cursor.execute.call_args.args[1]
    stored = json.loads(values[8].dumps(values[8].adapted))
    canonical = json.dumps(
        dict(
            previous=values[9],
            client_id=values[0],
            engagement_id=values[1],
            event_type=values[3],
            entity_type=values[4],
            entity_id=values[5],
            actor=values[6],
            summary=values[7],
            payload=stored,
        ),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    assert hashlib.sha256(canonical.encode()).hexdigest() == values[10]
    assert stored["due_date"] == "2026-11-01"
    assert stored["nested"]["amount"] == "1.25"
    assert isinstance(payload["due_date"], date)
