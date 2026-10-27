"""Readable risk summaries with full-value shared detail drawers."""

import json

from securescope.grc.document_registers import ASSET_FIELDS
from securescope.grc.risk_register import risk_row_with_scores
from securescope.ui.components_v2.assurance_workbench import assurance_workbench


def render_risk_register_table(rows: list[dict], *, key: str) -> None:
    """Show business risk columns and retain every assessment field in a drawer.

    Args:
        rows: Authorized client risk records from the existing repository.
        key: Unique workspace-scoped component key.
    Returns:
        None. No write or approval is performed by this reading view.
    Raises:
        StreamlitAPIException: If component registration fails.
    """
    data = dict(
        mode="risk_reading", rows=[risk_row_with_scores(row) for row in rows], fields=ASSET_FIELDS
    )
    assurance_workbench(json.loads(json.dumps(data, default=str)), key=key)
