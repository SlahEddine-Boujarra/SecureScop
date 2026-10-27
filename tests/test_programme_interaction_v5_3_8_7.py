"""Regression contracts for the v5.3.8.7 programme interaction system."""

from pathlib import Path

import pandas as pd

from securescope.ui.components.register_table import prepare_register_frame

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def test_register_table_normalizes_empty_values_and_booleans() -> None:
    """Keep consultant-facing registers free of raw None/NaN/boolean values."""

    frame = pd.DataFrame(
        {
            "Name": ["Server", ""],
            "In scope": [True, False],
            "Owner": [None, float("nan")],
        }
    )
    prepared = prepare_register_frame(frame)

    assert list(prepared["Name"]) == ["Server", "—"]
    assert list(prepared["In scope"]) == ["Yes", "No"]
    assert list(prepared["Owner"]) == ["—", "—"]


def test_discovery_uses_one_task_selector_and_batch_review() -> None:
    """Discovery should prepare one work area at a time and avoid button-per-card UX."""

    source = (SOURCE_ROOT / "ui/grc_workspace/discovery.py").read_text(encoding="utf-8")
    assert "Discovery task" in source
    assert "section_navigation(" in source
    assert "Add selected context issues" in source
    assert "Add selected parties" in source
    assert 'key=f"discovery_add_context_' not in source
    assert 'key=f"discovery_add_party_' not in source


def test_context_and_parties_are_recommendation_first() -> None:
    """Direct users to prepared suggestions before manual register entry."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    assert source.count("Review suggestions") >= 2
    assert source.count("Add manually") >= 2
    assert "programme_context_review_suggestions" in source
    assert "programme_parties_review_suggestions" in source


def test_scope_separates_preparation_editing_and_approval() -> None:
    """Keep scope preparation, editing, and human approval visibly distinct."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    assert "Prepare from Discovery" in source
    assert "Edit scope version" in source
    assert "Approval decision" in source
    assert "Approve reviewed version" in source


def test_roles_prioritize_isms_responsibility_over_engagement_admin() -> None:
    """Make the formal RACI task primary and engagement-role maintenance secondary."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    raci_position = source.index('"ISMS responsibility matrix"')
    engagement_position = source.index('"Engagement team"', raci_position)
    assert raci_position < engagement_position
    assert "Assign responsibility" in source
    assert "Assign engagement role" in source


def test_programme_registers_put_business_identity_first() -> None:
    """Protect identity-first column order for the formal programme registers."""

    source = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    assert '"title": "Issue",\n                "issue_type": "Type"' in source
    requirement_order = '"requirement": "Requirement",\n                "requirement_type": "Type"'
    assert requirement_order in source
    assert '"name": "Name",\n                "unit_type": "Type"' in source
