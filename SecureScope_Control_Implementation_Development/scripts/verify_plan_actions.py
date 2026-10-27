"""Verify real browser dialog actions against synthetic in-memory fixtures."""

import subprocess
import time
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
p = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(root / "scripts/stabilization_preview.py"),
        "--server.address",
        "127.0.0.1",
        "--browser.serverAddress",
        "127.0.0.1",
        "--server.port",
        "8516",
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.STDOUT,
)
try:
    time.sleep(2)
    with sync_playwright() as w:
        b = w.chromium.launch(args=["--no-sandbox"])
        page = b.new_page(viewport={"width": 1280, "height": 900})
        page.goto("http://127.0.0.1:8516/?screen=Project%20Plan")
        page.get_by_role("button", name="Edit task 2:", exact=False).wait_for(timeout=20000)
        page.get_by_role("button", name="Edit task 2:", exact=False).click()
        page.wait_for_timeout(1000)
        assert page.get_by_text("Update a project task", exact=True).is_visible(), page.locator(
            '[data-testid="stException"]'
        ).all_text_contents()
        page.get_by_label("Resource", exact=True).wait_for()
        assert page.get_by_label("Resource", exact=True).input_value() == "Security team"
        assert page.get_by_role("dialog").is_visible()
        page.screenshot(
            path=str(root / "validation/assurance_redesign/project-task-dialog.png"), full_page=True
        )
        page.get_by_role("button", name="Cancel", exact=True).click()
        page.get_by_role("dialog").wait_for(state="hidden")
        page.get_by_role("button", name="Plan in one pass", exact=True).click()
        page.wait_for_timeout(1000)
        assert not page.locator('[data-testid="stException"]').count()
        assert not page.get_by_text("Update a project task", exact=True).count()
        page.goto("http://127.0.0.1:8516/?screen=SoA")
        page.get_by_role("button", name="A.5.2", exact=True).wait_for()
        page.get_by_role("button", name="A.5.2", exact=True).click()
        page.get_by_role("dialog").wait_for()
        page.get_by_label("Inclusion justification", exact=True).fill(
            "Required for governance review"
        )
        page.get_by_role("button", name="Apply Changes", exact=True).click()
        page.get_by_role("dialog").wait_for(state="hidden")
        page.get_by_text("Required for governance review", exact=True).wait_for()
        assert page.locator("#assurance-page tbody tr").count() == 3
        page.get_by_role("searchbox", name="Search controls").fill("A.5.2")
        assert page.locator("#assurance-page tbody tr").count() == 1
        page.get_by_role("button", name="Reset filters").click()
        assert page.locator("#assurance-page tbody tr").count() == 3
        print(
            "Project edit dialog, cancel, batch planning and SoA working-row edit/filter checks passed."
        )
        b.close()
finally:
    p.terminate()
