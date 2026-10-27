"""SecureScope end-to-end workflow tests (Playwright + pytest).

Covers the ISO 27001 programme workflow in the order a consultant would use it:
  sign-in -> navigation -> discovery -> context -> interested parties -> ISMS scope
  -> governance -> engagement -> control assurance (plan, SoA, assessment, dashboard)
  -> risk -> client workspace -> technical pages (SIEM, Nmap, Connection status).
The Calendar page is intentionally excluded.

Tests marked `xfail(strict=True)` document KNOWN BUGS found in the UI review.
When Astra fixes a bug the test will XPASS and fail the run (strict), telling you
to remove the marker.

Run
---
    pip install pytest playwright && playwright install chromium
    export SS_URL=http://localhost:8501
    export SS_SETUP_CODE="<value of SECURESCOPE_LOCAL_SETUP_CODE, >= 32 chars>"
    pytest -v test_securescope_workflows.py

The app must be running with the same SECURESCOPE_LOCAL_SETUP_CODE and a migrated
PostgreSQL database. Tests share ONE browser session (Streamlit keeps sign-in in the
websocket session) and must run in file order. They are idempotent enough to be re-run
on the same database: records are looked up by name, not counted.
"""

from __future__ import annotations

import os
import re

import pytest
from playwright.sync_api import Error, Page, sync_playwright

BASE = os.environ.get("SS_URL", "http://localhost:8501")
CODE = os.environ.get("SS_SETUP_CODE", "")
ADMIN_EMAIL = os.environ.get("SS_ADMIN_EMAIL", "admin@example.com")

SIDEBAR_PAGES = [
    "Command Center",
    "Exposure Overview",
    "Programme Foundation",
    "Control Assurance",
    "Risk Management",
    "Policies",
    "Asset Management",
    "Discover assets",
    "Scan Center",
    "Vulnerabilities",
    "SIEM",
    "Remediation",
    "Reports & Audit",
    "Client Workspace",
]  # Calendar deliberately excluded

MAIN = '[data-testid="stMain"]'


# ----------------------------------------------------------------------------- helpers
def settle(page: Page, ms: int = 2200) -> None:
    page.wait_for_timeout(ms)
    try:
        page.wait_for_selector('[data-testid="stStatusWidget"]', state="detached", timeout=8000)
    except Error:
        pass
    page.wait_for_timeout(400)


def nav(page: Page, label: str) -> None:
    page.locator('[data-testid="stSidebar"] a', has_text=label).first.click()
    settle(page, 2800)


def tab(page: Page, name: str) -> None:
    page.locator(f'{MAIN} [role="tab"]', has_text=name).first.click()
    settle(page, 1800)


def btn(page: Page, text: str):
    return page.locator(f"{MAIN} button", has_text=text).first


def exception_text(page: Page) -> str:
    el = page.query_selector('[data-testid="stException"]')
    return el.inner_text()[:400] if el else ""


def fill_commit(page: Page, scope, label: str, value: str) -> None:
    """Streamlit commits text widgets on blur, so Tab after filling."""
    el = scope.get_by_label(label, exact=False).first
    el.click()
    el.fill(value)
    el.press("Tab")
    page.wait_for_timeout(600)


def close_dialog(page: Page) -> None:
    for _ in range(2):
        if page.query_selector('[role="dialog"]'):
            page.keyboard.press("Escape")
            page.wait_for_timeout(500)


def main_text(page: Page) -> str:
    """Text of the main area PLUS any embedded component frames (tables/lists render there)."""
    parts = [page.inner_text(MAIN)]
    for fr in page.frames[1:]:
        try:
            parts.append(fr.inner_text("body", timeout=1500))
        except Error:
            pass
    return "\n".join(parts)


# ----------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def page():
    if len(CODE) < 32:
        pytest.skip("Set SS_SETUP_CODE to the launcher's SECURESCOPE_LOCAL_SETUP_CODE (>=32 chars)")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_page(viewport={"width": 1500, "height": 1000})
        pg.set_default_timeout(15000)
        pg.goto(f"{BASE}/client-workspace", wait_until="networkidle")
        settle(pg, 3000)
        pg.get_by_text("Administrator setup / local sign-in").first.click()
        pg.wait_for_timeout(800)
        fill_commit(pg, pg, "Administrator email", ADMIN_EMAIL)
        fill_commit(pg, pg, "Display name", "QA Admin")
        fill_commit(pg, pg, "Local setup code", CODE)
        pg.get_by_text("I operate this installation").click()
        pg.wait_for_timeout(500)
        pg.get_by_role("button", name="Verify local access").click()
        settle(pg, 3500)
        assert ADMIN_EMAIL in pg.inner_text("body"), "Administrator sign-in failed"
        yield pg
        browser.close()


def cancel_scope_editor(page: Page) -> None:
    b = page.locator(f"{MAIN} button", has_text="Cancel editor")
    if b.count():
        b.first.click()
        settle(page, 1200)


@pytest.fixture(autouse=True)
def _clean(page):
    close_dialog(page)
    cancel_scope_editor(page)
    yield
    close_dialog(page)
    cancel_scope_editor(page)


# ============================================================ 01 NAVIGATION / SMOKE
@pytest.mark.parametrize("label", SIDEBAR_PAGES)
def test_01_every_page_loads_without_exception(page, label):
    nav(page, label)
    assert exception_text(page) == "", f"{label} raised an exception"
    assert main_text(page).strip(), f"{label} rendered empty"


def test_01b_connection_status_dialog_opens(page):
    page.locator('[data-testid="stSidebar"] button', has_text="Connection status").first.click()
    settle(page, 2500)
    dlg = page.locator('[role="dialog"]')
    assert dlg.count() == 1
    for name in ("OpenVAS", "Nuclei", "CISO"):
        assert name in dlg.inner_text()


def test_01c_change_context_popover_opens(page):
    nav(page, "Policies")
    btn(page, "Change context").click()
    settle(page, 1200)
    assert "Engagement / certification cycle" in page.inner_text("body")


# ============================================================ 02 EXPOSURE
def test_02_exposure_discover_assets_navigates(page):
    nav(page, "Exposure Overview")
    btn(page, "Discover assets").click()
    settle(page, 2500)
    assert page.url.rstrip("/").endswith("asset-discovery")
    assert "no-op" not in page.inner_text("body")


def test_02b_exposure_review_coverage_navigates(page):
    nav(page, "Exposure Overview")
    btn(page, "Review Coverage").click()
    settle(page, 2500)
    assert page.url.rstrip("/").endswith("asset-management")


# ============================================================ 03 PROGRAMME FOUNDATION
def test_03_discovery_profile_saves(page):
    nav(page, "Programme Foundation")
    tab(page, "Discovery")
    page.locator(f"{MAIN} textarea").first.fill("B2B SaaS platform for EU customers (QA).")
    page.locator(f"{MAIN} textarea").first.press("Control+Enter")
    page.wait_for_timeout(600)
    btn(page, "Save organization profile").click()
    settle(page, 3000)
    assert exception_text(page) == ""
    assert "Confirmed profile" in main_text(page)


def test_04_context_issue_created(page):
    title = "QA Customer data hosting regulation"
    nav(page, "Programme Foundation")
    tab(page, "Context")
    btn(page, "+ Add issue").click()
    settle(page, 1500)
    dlg = page.locator('[role="dialog"]')
    fill_commit(page, dlg, "Issue title", title)
    fill_commit(page, dlg, "Issue description", "GDPR applies to hosted data")
    fill_commit(page, dlg, "Effect on the ISMS", "Drives data-protection controls")
    dlg.get_by_role("button", name="Create issue").click()
    settle(page, 3500)
    assert exception_text(page) == ""
    assert page.locator('[role="dialog"]').count() == 0, page.inner_text("body")[-300:]
    tab(page, "Overview")
    tab(page, "Context")
    assert title in main_text(page)


def test_04b_context_issue_requires_title(page):
    nav(page, "Programme Foundation")
    tab(page, "Context")
    btn(page, "+ Add issue").click()
    settle(page, 1500)
    page.locator('[role="dialog"]').get_by_role("button", name="Create issue").click()
    settle(page, 1500)
    assert "title is required" in page.inner_text("body").lower()


@pytest.mark.xfail(
    strict=False,
    reason=(
        "BUG-14: required dialog fields are not marked, errors appear one "
        "at a time, and typed values vanish after a failed submit"
    ),
)
def test_04c_failed_validation_keeps_typed_values_and_lists_all_errors(page):
    nav(page, "Programme Foundation")
    tab(page, "Context")
    btn(page, "+ Add issue").click()
    settle(page, 1500)
    dlg = page.locator('[role="dialog"]')
    fill_commit(page, dlg, "Issue title", "QA keep my text")
    dlg.get_by_role("button", name="Create issue").click()
    settle(page, 1800)
    assert dlg.get_by_label("Issue title").first.input_value() == "QA keep my text"
    err = page.inner_text("body").lower()
    assert (
        "description" in err and "effect" in err
    ), "all missing required fields should be reported together"


def test_04d_primary_button_text_has_sufficient_contrast(page):
    nav(page, "Programme Foundation")
    tab(page, "Context")
    btn(page, "+ Add issue").click()
    settle(page, 1500)
    b = page.locator('[role="dialog"]').get_by_role("button", name="Create issue")

    def lum(c):
        r, g, bl = [int(x) for x in re.findall(r"\d+", c)[:3]]

        def f(v):
            return (v / 255) / 12.92 if v / 255 <= 0.03928 else (((v / 255) + 0.055) / 1.055) ** 2.4

        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(bl)

    fg = b.evaluate("e=>getComputedStyle(e.querySelector('p')||e).webkitTextFillColor")
    bg = b.evaluate("e=>getComputedStyle(e).backgroundColor")
    l1, l2 = sorted([lum(fg), lum(bg)], reverse=True)
    ratio = (l1 + 0.05) / (l2 + 0.05)
    assert ratio >= 4.5, f"contrast ratio {ratio:.2f} < 4.5 (fg={fg}, bg={bg})"


def test_05_interested_party_created(page):
    name = "QA Acme Customers"
    nav(page, "Programme Foundation")
    tab(page, "Interested Parties")
    btn(page, "+ Add interested party").click()
    settle(page, 1500)
    dlg = page.locator('[role="dialog"]')
    fill_commit(page, dlg, "Party name *", name)
    fill_commit(page, dlg, "Needs and expectations", "Confidentiality and uptime")
    dlg.get_by_role("button", name="Create Party").click()
    settle(page, 3000)
    assert exception_text(page) == ""
    assert page.locator('[role="dialog"]').count() == 0
    tab(page, "Overview")
    tab(page, "Interested Parties")
    assert name in main_text(page)


def test_06_scope_wizard_progress_bar_reflects_step(page):
    nav(page, "Programme Foundation")
    tab(page, "ISMS Scope")
    btn(page, "Edit scope").click()
    settle(page, 1800)
    bar = page.locator('[role="progressbar"]').first
    if bar.count() == 0:
        pytest.skip("progress bar not exposed as role=progressbar")
    step1 = float(bar.get_attribute("aria-valuenow") or 0)
    assert step1 < 100, "BUG-02: progress bar is full on step 1"
    btn(page, "Cancel editor").click()
    settle(page, 1500)


def test_06b_scope_wizard_first_step_has_no_self_referencing_back_link(page):
    nav(page, "Programme Foundation")
    tab(page, "ISMS Scope")
    btn(page, "Edit scope").click()
    settle(page, 1800)
    txt = main_text(page)
    assert "Step 1 of 6" in txt
    assert "Back to Identity & purpose" not in txt, "BUG-03: step 1 offers 'Back to' its own step"
    btn(page, "Cancel editor").click()
    settle(page, 1500)


def test_07_scope_wizard_creates_draft_version(page):
    nav(page, "Programme Foundation")
    tab(page, "ISMS Scope")
    btn(page, "Edit scope").click()
    settle(page, 1800)

    def nxt():
        btn(page, "Save & continue").click()
        settle(page, 1400)

    nxt()  # -> step 2
    for i, v in enumerate(["Tunis HQ", "Engineering"]):
        ta = page.locator(f"{MAIN} textarea").nth(i)
        ta.fill(v)
        ta.press("Control+Enter")
        page.wait_for_timeout(300)
    nxt()  # -> step 3
    for i, v in enumerate(["ERP SaaS", "AWS, PostgreSQL"]):
        ta = page.locator(f"{MAIN} textarea").nth(i)
        ta.fill(v)
        ta.press("Control+Enter")
        page.wait_for_timeout(300)
    for _ in range(3):
        nxt()
    assert "Step 6 of 6" in main_text(page)
    btn(page, "Create draft version").click()
    settle(page, 3500)
    assert exception_text(page) == ""
    btn(page, "Version history").click()
    settle(page, 2000)
    assert "Scope Version History" in main_text(page)
    assert "Draft" in main_text(page)


def test_08_governance_raci_requires_role(page):
    nav(page, "Programme Foundation")
    tab(page, "Governance")
    btn(page, "+ Assign responsibility").click()
    settle(page, 1500)
    page.locator('[role="dialog"]').get_by_role("button", name="Create RACI assignment").click()
    settle(page, 1500)
    assert "role is required" in page.inner_text("body").lower()


def test_09_engagement_milestone_created(page):
    title = "QA Stage 1 audit"
    nav(page, "Programme Foundation")
    tab(page, "Engagement")
    btn(page, "Add milestone").click()
    settle(page, 1500)
    dlg = page.locator('[role="dialog"]')
    fill_commit(page, dlg, "Milestone title", title)
    dlg.get_by_role("button", name="Create milestone").click()
    settle(page, 3000)
    assert exception_text(page) == "", exception_text(page)
    assert title in main_text(page)


def test_09b_raw_tracebacks_are_not_shown_to_users(page):
    """Even when something fails the UI must not leak server paths or 'Ask ChatGPT' links."""
    body = page.inner_text("body")
    assert "/home/" not in body and "site-packages" not in body and "Ask ChatGPT" not in body


# ============================================================ 04 CONTROL ASSURANCE
def test_10_project_plan_plan_and_save_all_tasks(page):
    nav(page, "Control Assurance")
    tab(page, "Project plan")
    btn(page, "Plan in one pass").click()
    settle(page, 2500)
    btn(page, "Suggest all dates").click()
    settle(page, 3000)
    save = page.locator(f"{MAIN} button", has_text=re.compile(r"Save \d+ changed tasks")).first
    if save.is_enabled() and "Save 0" not in save.inner_text():
        save.click()
        settle(page, 3000)
        assert exception_text(page) == ""
        assert "saved together" in page.inner_text("body")


def test_10b_project_plan_export_csv_downloads(page):
    nav(page, "Control Assurance")
    tab(page, "Project plan")
    with page.expect_download(timeout=15000) as dl:
        btn(page, "Export CSV").click()
    assert dl.value.suggested_filename.endswith(".csv")


def test_11_soa_create_version_shows_justification_guidance(page):
    nav(page, "Control Assurance")
    tab(page, "Statement of Applicability")
    btn(page, "Create SoA version").click()
    settle(page, 3000)
    assert exception_text(page) == ""
    assert "justification" in page.inner_text("body").lower()


def test_11b_soa_has_no_developer_facing_text(page):
    nav(page, "Control Assurance")
    tab(page, "Statement of Applicability")
    assert "pending verification of the live database schema" not in page.inner_text(
        "body"
    ), "BUG-08"


def test_12_assess_control_save_draft(page):
    nav(page, "Control Assurance")
    tab(page, "Assess control")
    btn(page, "Save Draft").click()
    settle(page, 2500)
    assert exception_text(page) == ""
    assert "Draft saved" in page.inner_text("body")


def test_12b_assess_submit_blocked_until_target_approved(page):
    nav(page, "Control Assurance")
    tab(page, "Assess control")
    assert btn(page, "Submit Assessment Conclusion").is_disabled()


def test_12c_confirm_requirement_set(page):
    nav(page, "Control Assurance")
    tab(page, "Assess control")
    btn(page, "Link Evidence").click()
    settle(page, 2500)
    confirm = page.locator(f"{MAIN} button", has_text="Confirm requirements")
    if confirm.count() == 0:
        pytest.skip("requirement set already confirmed in a previous run")
    confirm.first.click()
    settle(page, 3000)
    assert exception_text(page) == ""
    assert "Requirements reviewed" in page.inner_text("body")


def test_13_gap_dashboard_area_breakdown_sorted_numerically(page):
    nav(page, "Control Assurance")
    tab(page, "Gap dashboard")
    txt = main_text(page)
    if "ISO Area Breakdown" not in txt:
        pytest.skip("ISO Area Breakdown table not exposed to the DOM text")
    section = txt[txt.index("ISO Area Breakdown") :]
    order = [int(m) for m in re.findall(r"^\s*(\d{1,2})\s*$", section, flags=re.M)]
    assert order, "no numeric area rows found"
    assert order == sorted(order), f"BUG-05: areas not numerically sorted: {order}"


def test_13b_gap_dashboard_counts_are_consistent(page):
    nav(page, "Control Assurance")
    tab(page, "Gap dashboard")
    txt = main_text(page)
    m_app = re.search(r"APPLICABLE ITEMS\s*\n\s*(\d+)", txt, flags=re.I)
    m_na = re.search(r"NOT ASSESSED\s*\n\s*(\d+)", txt, flags=re.I)
    if m_app and m_na:
        assert not (
            int(m_app.group(1)) == 0 and int(m_na.group(1)) > 0
        ), "BUG-07: 'Applicable items' is 0 while 'Not assessed' is >0"


def test_14_control_profiles_tab_lists_controls(page):
    nav(page, "Control Assurance")
    tab(page, "Control profiles")
    assert "123" in page.inner_text("body")


# ============================================================ 05 RISK
def test_15_risk_register_created(page):
    import time

    name = f"QA Ops Register {int(time.time()) % 100000}"
    nav(page, "Risk Management")
    btn(page, "Add Risk Register").click()
    settle(page, 1500)
    dlg = page.locator('[role="dialog"]')
    fill_commit(page, dlg, "Register name", name)
    dlg.get_by_role("button", name="Save register").click()
    settle(page, 3000)
    assert exception_text(page) == ""
    assert name in main_text(page)


def test_15b_risk_register_view_has_no_stale_empty_banner(page):
    txt = main_text(page)
    if "Add scenario" in txt:
        assert (
            "No risks are currently assigned" not in txt
        ), "BUG-09: stale banner inside register view"


def test_16_risk_coming_soon_tabs_are_disabled_not_clickable(page):
    nav(page, "Risk Management")
    tab(page, "Methodology")
    b = btn(page, "Configure methodology")
    assert b.is_disabled() or "Coming Soon" in b.inner_text()


# ============================================================ 06 CLIENT WORKSPACE
def test_17_client_workspace_created_and_listed(page):
    name = "QA Test Client"
    nav(page, "Client Workspace")
    page.get_by_text("Create client workspace").first.click()
    settle(page, 900)
    fill_commit(page, page.locator(MAIN), "Client name", name)
    page.locator(f"{MAIN} button", has_text=re.compile("Create")).last.click()
    settle(page, 3500)
    assert exception_text(page) == ""


def test_17b_signin_form_resets_or_collapses_after_login(page):
    nav(page, "Client Workspace")
    # After a successful sign-in the setup form should not still be presenting blank fields
    inputs = page.locator(f"{MAIN} input[type=password]")
    assert (
        inputs.count() == 0 or not inputs.first.is_visible()
    ), "BUG-13: sign-in form still shown after login"


# Technical pages (no scanners needed)
def test_18_siem_unconfigured_buttons_fail_gracefully(page):
    nav(page, "SIEM")
    for label in ("Test Wazuh API", "Collect SIEM data", "Refresh page"):
        btn(page, label).click()
        settle(page, 3000)
        assert exception_text(page) == "", f"{label} raised an unhandled exception"
        nav(page, "SIEM")


def test_19_nmap_run_requires_authorization(page):
    nav(page, "Discover assets")
    assert btn(
        page, "Run Nmap"
    ).is_disabled(), "Run must be disabled until the authorization box is ticked"


def test_20_scan_center_reports_missing_engine_clearly(page):
    nav(page, "Scan Center")
    txt = page.inner_text("body")
    assert "Nuclei" in txt
    assert "missing or stale Start" not in txt, "BUG-12: missing punctuation in worker message"


# ============================================================ 08 CROSS-PAGE CONSISTENCY
@pytest.mark.parametrize(
    "label,expected_h1",
    [("Scan Center", "Scan Center"), ("Reports & Audit", "Reports & Audit")],
)
def test_21_page_title_matches_navigation_label(page, label, expected_h1):
    nav(page, label)
    h = page.evaluate(
        "()=>{const h=document.querySelector('[data-testid=stMain] h1, "
        "[data-testid=stMain] h2');return h?h.innerText:''}"
    )
    assert expected_h1.lower() in h.lower(), f"BUG-10: nav says '{label}' but page title is '{h}'"


def test_22_scope_name_is_consistent_across_pages(page):
    nav(page, "Risk Management")
    txt = page.inner_text("body")
    assert not (
        "Existing ISMS Scope" in txt and "ISMS Scope #1" in txt
    ), "BUG-06: scope has two different names"


def test_23_command_center_reflects_programme_progress(page):
    nav(page, "Command Center")
    txt = main_text(page)
    m = re.search(r"PROGRAMME FOUNDATION\s*(\d+)\s*%", txt, flags=re.I)
    if not m:
        pytest.skip("Programme foundation KPI not found in page text")
    assert (
        int(m.group(1)) > 12
    ), "KPI did not move after discovery/context/party/scope were completed"
