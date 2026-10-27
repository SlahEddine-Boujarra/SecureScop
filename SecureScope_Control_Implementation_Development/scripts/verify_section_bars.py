"""Fixture-only navigation smoke check; not live PostgreSQL acceptance evidence."""

import json
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
output = root / "validation/assurance_redesign"
app = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "scripts/stabilization_preview.py",
        "--server.port",
        "8522",
        "--server.address",
        "127.0.0.1",
        "--browser.serverAddress",
        "127.0.0.1",
    ],
    cwd=root,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(2)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto("http://127.0.0.1:8522/?screen=Foundation&sidebar=1")
        switch = page.get_by_role("button", name="Switch workspace: Northstar Services")
        switch.wait_for(timeout=15000)
        assert switch.is_visible()
        styles = switch.locator("p").evaluate(
            "e=>({display:getComputedStyle(e).display,color:getComputedStyle(e).color,text:e.textContent})"
        )
        assert styles["display"] != "none"
        assert styles["color"] == "rgb(11, 28, 48)"
        bar = page.get_by_role("tablist").first
        assert bar.evaluate("e=>getComputedStyle(e).backgroundColor") == "rgb(255, 255, 255)"
        active = bar.locator('[aria-selected="true"]')
        assert active.evaluate("e=>getComputedStyle(e).color") == "rgb(0, 104, 95)"
        page.screenshot(path=str(output / "foundation-sidebar.png"))
        switch.click()
        page.get_by_text("Client switcher opened.", exact=True).wait_for()
        page.screenshot(path=str(output / "client-switch-dialog.png"))
        assert page.locator('[data-testid="stException"]').count() == 0
        (output / "section-bar-checks.json").write_text(json.dumps(styles, indent=2))
        browser.close()
finally:
    app.terminate()
