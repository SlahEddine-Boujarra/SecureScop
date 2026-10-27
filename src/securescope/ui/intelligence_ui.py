"""Explicit enrichment coverage and read-through of the existing CVE cache."""

from typing import Any

import streamlit as st

from securescope.integrations.vulnerability_intelligence_service import (
    VulnerabilityIntelligenceError,
    attach_canonical_intelligence,
    collect_intelligence,
    extract_cves,
)


def enrich_priority_rows(client_name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join cached intelligence to findings and allow an explicit feed refresh.

    Args:
        client_name: Active workspace, used to isolate widget state.
        rows: Canonical findings in this workspace.
    Returns:
        Enriched copies, retaining unknown values on collection failure.
    Raises:
        Unexpected rendering errors propagate.
    """
    ids = sorted({cve for row in rows for cve in extract_cves(row.get("vulnerability_identity"))})
    if not rows:
        return rows
    if not ids:
        st.caption(
            "KEV/EPSS: not applicable to these findings because they have no CVE identifier."
        )
        return attach_canonical_intelligence(rows, {})
    refresh = st.button("Refresh KEV / EPSS", key=f"intelligence::{client_name}")
    try:
        records = collect_intelligence(
            ids, refresh=refresh, allow_network=refresh, include_nvd=False
        )
    except VulnerabilityIntelligenceError:
        st.warning(
            (
                "Enrichment unavailable: the intelligence cache could not be read."
                " Check database and feed connectivity. Findings remain available."
            )
        )
        return attach_canonical_intelligence(rows, {})
    result = attach_canonical_intelligence(rows, records)
    missing = sum(
        bool(extract_cves(row.get("vulnerability_identity")))
        and (row.get("epss_score") is None or row.get("kev_known_exploited") is None)
        for row in result
    )
    errors = sorted(
        {error for record in records.values() for error in record.get("collection_errors", [])}
    )
    if errors:
        st.warning("Enrichment is incomplete: " + "; ".join(errors))
    if missing:
        st.info(
            (
                "KEV/EPSS coverage is incomplete for "
                f"{missing}"
                " finding(s). Refresh the public CISA and FIRST feeds. "
                "NVD_API_KEY is optional for NVD metadata and is not "
                "required for KEV/EPSS."
            )
        )
    else:
        st.caption(
            "KEV/EPSS values use the saved CISA/FIRST feed snapshot. Refresh to check for updates."
        )
    return result
