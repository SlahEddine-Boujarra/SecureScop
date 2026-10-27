"""Regression contracts for v5.3.8.4 programme-foundation discovery."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

from securescope.grc.organization_knowledge_service import OrganizationKnowledgeService
from securescope.grc.organization_models import OrganizationProfileDraft
from securescope.ui.components.html_renderer import render_html

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "securescope"


def test_trusted_html_uses_streamlit_html_not_markdown() -> None:
    """Prevent Markdown from exposing indented dashboard HTML as source text."""

    with patch("securescope.ui.components.html_renderer.st.html") as mocked:
        render_html(
            """
            <section>
                <strong>Foundation</strong>
            </section>
            """
        )
    rendered = mocked.call_args.args[0]
    assert rendered.startswith("<section>")
    assert "<strong>Foundation</strong>" in rendered


def test_dashboard_components_use_safe_html_renderer() -> None:
    """Keep custom dashboard HTML outside the Markdown parser."""

    source = (SOURCE_ROOT / "ui/components/dashboard.py").read_text(encoding="utf-8")
    assert "render_html(" in source
    assert "unsafe_allow_html=True" not in source


def test_organization_profile_normalizes_lists() -> None:
    """Normalize duplicate quick-profile values before they become facts."""

    profile = OrganizationProfileDraft(
        industry="Software / SaaS",
        main_activity="Operate a B2B SaaS platform.",
        employee_band="26-50",
        infrastructure_model="Cloud",
        locations=("Tunis", "tunis", ""),
        technologies=("AWS", "AWS", "GitHub"),
    ).validate()
    assert profile.locations == ("Tunis",)
    assert profile.technologies == ("AWS", "GitHub")


def test_saas_profile_generates_reviewable_context_and_parties() -> None:
    """Seed useful ISO proposals without pretending they are approved records."""

    profile = {
        "industry": "Software / SaaS",
        "employee_band": "26-50",
        "infrastructure_model": "Cloud",
        "technologies": ["AWS", "GitHub", "Microsoft 365"],
        "customer_markets": ["European Union / Europe"],
        "certification_drivers": ["Customer requirement"],
        "products_and_services": ["ERP SaaS"],
        "departments": ["Engineering / Development", "IT"],
        "locations": ["Tunis HQ"],
        "main_activity": "Develop and operate a B2B ERP SaaS platform.",
    }
    contexts = OrganizationKnowledgeService.context_recommendations(profile)
    parties = OrganizationKnowledgeService.party_recommendations(profile)
    context_titles = {item.title for item in contexts}
    party_names = {item.name for item in parties}

    assert "Dependence on cloud and SaaS providers" in context_titles
    assert "Software development and change velocity" in context_titles
    assert "Customer-driven security assurance" in context_titles
    assert {"Customers", "Employees", "Certification body", "AWS"} <= party_names


def test_scope_composer_uses_confirmed_organization_facts() -> None:
    """Build a scope draft from selected facts instead of a blank text box."""

    profile = {
        "main_activity": "Operate an ERP SaaS platform.",
        "products_and_services": ["ERP SaaS"],
        "departments": ["Engineering / Development", "IT"],
        "locations": ["Tunis HQ"],
        "technologies": ["AWS", "GitHub"],
    }
    scope = OrganizationKnowledgeService.compose_scope(profile)

    assert "ERP SaaS" in scope.statement
    assert "Engineering / Development" in scope.statement
    assert "Tunis HQ" in scope.statement
    assert "AWS" in scope.statement
    assert "Confirm exclusions" in scope.assumptions[-1]


def test_migration_six_is_additive_and_client_scoped() -> None:
    """Protect the new organization-knowledge migration from destructive changes."""

    migration = (PROJECT_ROOT / "database/migrations/006_organization_knowledge.sql").read_text(
        encoding="utf-8"
    )
    assert "securescope_organization_profiles" in migration
    assert "securescope_organization_facts" in migration
    assert "REFERENCES securescope_clients(id)" in migration
    assert "DROP TABLE" not in migration.upper()
    assert "TRUNCATE" not in migration.upper()


def test_programme_router_exposes_discovery_before_advanced_registers() -> None:
    """Make discovery a first-class Programme Setup destination."""

    router = (SOURCE_ROOT / "ui/grc_workspace/router.py").read_text(encoding="utf-8")
    sections = (SOURCE_ROOT / "ui/grc_workspace/sections.py").read_text(encoding="utf-8")
    assert '("discovery", "Discovery")' in router
    assert "render_discovery_section(" in router
    assert "Programme Foundation" in sections
    assert "Continue Discovery" in sections
    assert "Needs Information" in sections


def test_migration_six_compatibility_alias_preserves_original_release() -> None:
    """Prefer the compatibility migration without rewriting published migration 006."""

    from securescope.persistence.migration_service import discover_migrations

    migrations = discover_migrations(PROJECT_ROOT / "database/migrations")
    migration_six = next(item for item in migrations if item.version == 6)
    assert migration_six.name == "organization_knowledge_compat"
    original = PROJECT_ROOT / "database/migrations/006_organization_knowledge.sql"
    assert (
        hashlib.sha256(original.read_bytes()).hexdigest()
        == "33b692a189316647f40f8332477a2f98581aacf251cf06d1296e06c8b176fbe2"
    )
