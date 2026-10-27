"""Capture the real running app after an operator selects an authorized test workspace.

This script navigates and reads UI state; it does not submit forms, start scans,
change identities or save domain records. Its output is live only when run against
the actual application and configured PostgreSQL database.
"""

import argparse
import json
from pathlib import Path
import re

from playwright.sync_api import sync_playwright


def snapshot(page, output: Path, name: str, checks: list):
    """Capture one visible application state and its computed sidebar/tab styling.

    Args:
        page: Live Playwright page.
        output: Directory for screenshots and checks.
        name: Safe screen label.
        checks: Mutable result list.
    Returns:
        None.
    Raises:
        AssertionError: If Streamlit renders an exception.
        OSError: If screenshot output cannot be saved.
    """
    page.wait_for_function(
        "document.querySelectorAll('[data-testid=\"stStatusWidget\"]').length === 0"
    )
    assert page.locator('[data-testid="stException"]').count() == 0, name
    painted = page.locator('[data-testid="stSidebar"] button').evaluate_all(
        """nodes => nodes.map(button => {
        const style = getComputedStyle(button);
        const child = button.querySelector('p') || button;
        const text = getComputedStyle(child);
        return {label: button.innerText, color: style.color,
            textFill: style.webkitTextFillColor, background: style.backgroundColor,
            childColor: text.color, childTextFill: text.webkitTextFillColor,
            disabled: button.disabled};
    })"""
    )
    tabs = page.get_by_role("tablist").evaluate_all("""nodes => nodes.map(node => ({
        label: node.getAttribute('aria-label'), background: getComputedStyle(node).backgroundColor,
        tabs: Array.from(node.querySelectorAll('[role="tab"]')).map(tab => ({
            label: tab.innerText, selected: tab.getAttribute('aria-selected'),
            color: getComputedStyle(tab).color, padding: getComputedStyle(tab).padding,
            indicator: getComputedStyle(tab).borderBottomWidth
        }))
    }))""")
    page.screenshot(path=str(output / f"{name}.png"), full_page=True)
    checks.append({"screen": name, "url": page.url, "sidebar": painted, "bars": tabs})


def main():
    """Run explicit read-only browser acceptance captures.

    Returns:
        None.
    Raises:
        OSError: If output cannot be created.
        AssertionError: If a requested route cannot render.
        playwright.sync_api.Error: If the browser or application is unavailable.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8501")
    parser.add_argument("--output", type=Path, default=Path("validation/design_live"))
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--pause-for-sign-in", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    checks = []
    missing = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=not args.headed)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto(args.url)
        page.get_by_test_id("stSidebar").wait_for(timeout=30000)
        if args.pause_for_sign_in:
            input(
                "Select the disposable test workspace and sign in through the browser, then press Enter: "
            )
        routes = {
            "Programme Foundation": [
                "Overview",
                "Discovery",
                "Context",
                "Interested Parties",
                "ISMS Scope",
                "Governance",
                "Engagement",
            ],
            "Control Assurance": [
                "Gap dashboard",
                "Project plan",
                "Control profiles",
                "Assess control",
                "Evidence",
                "Gap actions",
                "Statement of Applicability",
            ],
            "Risk Management": [
                "Registers & assessment",
                "Treatment plan",
                "Residual assessment",
                "Risk acceptance",
                "Monitoring & review",
                "Methodology",
            ],
            "Policies": [],
            "Asset Management": [],
            "Discover assets (Nmap)": [],
            "Scan Center": [],
            "Vulnerabilities": [],
            "SIEM": [],
            "Calendar": [],
            "Remediation": [],
            "Reports & Audit": [],
            "Client Workspace": [],
        }
        for width, height in [(1440, 1000), (1280, 800), (390, 844)]:
            page.set_viewport_size({"width": width, "height": height})
            for route, labels in routes.items():
                side = page.get_by_test_id("stSidebar")
                link = side.get_by_role("link", name=route, exact=True)
                if link.count() != 1:
                    missing.append(
                        {
                            "width": width,
                            "route": route,
                            "reason": "Route unavailable in this session",
                        }
                    )
                    continue
                link.click()
                page.get_by_test_id("stMain").wait_for()
                slug = re.sub(r"[^a-z0-9]+", "-", route.lower()).strip("-")
                snapshot(page, args.output, f"{slug}-{width}", checks)
                for label in labels:
                    tab = page.get_by_role("tab", name=re.compile(re.escape(label), re.I))
                    if tab.count() != 1:
                        missing.append({"width": width, "route": route, "tab": label})
                        continue
                    tab.click()
                    tab_slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
                    snapshot(page, args.output, f"{slug}-{tab_slug}-{width}", checks)
                    nested = {
                        "Evidence": [
                            "Overview",
                            "Evidence Register",
                            "Collect Evidence",
                            "Import Reports",
                            "Manual Evidence",
                            "Consultant Review",
                            "Evidence Requests",
                            "Auditor Package",
                            "Evidence Settings",
                        ],
                        "Governance": ["Roles & RACI", "Objectives"],
                        "Discovery": [
                            "Context suggestions",
                            "Interested parties",
                            "Scope composer",
                        ],
                    }.get(label, [])
                    for destination in nested:
                        child = page.get_by_role("tablist").last.get_by_role(
                            "tab", name=re.compile(re.escape(destination), re.I)
                        )
                        if child.count() != 1:
                            missing.append({"width": width, "route": route, "subtab": destination})
                            continue
                        child.click()
                        child_slug = re.sub(r"[^a-z0-9]+", "-", destination.lower()).strip("-")
                        snapshot(
                            page, args.output, f"{slug}-{tab_slug}-{child_slug}-{width}", checks
                        )
        browser.close()
    (args.output / "computed-styles.json").write_text(
        json.dumps({"checks": checks, "unverified": missing}, indent=2), encoding="utf-8"
    )
    print(f"Captured {len(checks)} screens. {len(missing)} route/tab checks remain unverified.")


if __name__ == "__main__":
    main()
