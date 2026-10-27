"""Reusable Streamlit presentation components for SecureScope."""

from securescope.ui.components.attention_queue import render_attention_queue
from securescope.ui.components.context_bar import render_context_bar
from securescope.ui.components.dashboard import (
    DashboardMetric,
    render_control_assurance_card,
    render_dashboard_metrics,
    render_evidence_coverage_card,
    render_foundation_work,
)
from securescope.ui.components.html_renderer import render_html
from securescope.ui.components.progress_card import (
    render_dimension_grid,
    render_program_progress_card,
)
from securescope.ui.components.register_header import render_register_header
from securescope.ui.components.register_table import (
    prepare_register_frame,
    render_register_table,
)
from securescope.ui.components.status_badge import render_status_badge
from securescope.ui.components.stitch import (
    StitchMetric,
    render_assurance_distribution,
    render_attention_panel,
    render_certification_journey,
    render_coverage_gaps,
    render_foundation_review_cards,
    render_programme_workflow,
    render_severity_bars,
    render_stitch_metrics,
    render_technical_coverage,
)

__all__ = [
    "render_attention_queue",
    "DashboardMetric",
    "render_context_bar",
    "render_control_assurance_card",
    "render_dashboard_metrics",
    "render_evidence_coverage_card",
    "render_foundation_work",
    "render_html",
    "render_dimension_grid",
    "render_program_progress_card",
    "render_register_header",
    "prepare_register_frame",
    "render_register_table",
    "render_status_badge",
    "StitchMetric",
    "render_assurance_distribution",
    "render_attention_panel",
    "render_certification_journey",
    "render_coverage_gaps",
    "render_foundation_review_cards",
    "render_programme_workflow",
    "render_severity_bars",
    "render_stitch_metrics",
    "render_technical_coverage",
]
