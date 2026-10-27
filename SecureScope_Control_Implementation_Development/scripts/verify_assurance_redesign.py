"""Run isolated, local visual checks; requires Playwright with Chromium installed."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
output = root / "validation" / "assurance_redesign"
output.mkdir(parents=True, exist_ok=True)
app = subprocess.Popen(
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
        "8515",
    ],
    cwd=root,
    stdout=open(output / "preview.log", "w"),
    stderr=subprocess.STDOUT,
)
results = []
try:
    time.sleep(2)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        for width, height in [(1440, 1000), (1280, 800), (390, 844)]:
            page = browser.new_page(viewport=dict(width=width, height=height))
            for name in (
                os.environ["SECURESCOPE_PREVIEW_SCREENS"].split(",")
                if os.getenv("SECURESCOPE_PREVIEW_SCREENS")
                else ["Assurance", "Project Plan", "Assess Control", "SoA"]
            ):
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(f"http://127.0.0.1:8515/?screen={name.replace(' ','%20')}")
                page.get_by_text("UI verification · synthetic records").wait_for(timeout=15000)
                page.wait_for_timeout(1200)
                if name == "Wazuh":
                    page.get_by_text("Configure SIEM connection", exact=True).click()
                page.wait_for_timeout(500)
                file = f"{name.lower().replace(' ','-')}-{width}.png"
                page.screenshot(path=str(output / file), full_page=True)
                page.locator('[data-testid="stMain"]').evaluate(
                    "el => el.scrollTop = el.scrollHeight"
                )
                page.wait_for_timeout(150)
                page.screenshot(
                    path=str(output / file.replace(".png", "-bottom.png")), full_page=True
                )
                fields = page.locator(
                    '[data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea'
                ).evaluate_all(
                    "els=>els.map(e=>({label:e.getAttribute('aria-label'),border:getComputedStyle(e).border,background:getComputedStyle(e).backgroundColor}))"
                )
                results.append(
                    dict(
                        screen=name,
                        width=width,
                        exceptions=page.locator('[data-testid="stException"]').all_text_contents(),
                        errors=errors,
                        fields=fields,
                        screenshot=file,
                    )
                )
                print(name, width, "errors", results[-1]["exceptions"] or errors, flush=True)
            page.close()
        page = browser.new_page(viewport=dict(width=1280, height=800))
        for name in ["Assurance", "Project Plan"]:
            page.goto(f"http://127.0.0.1:8515/?screen={name}&empty=1")
            page.wait_for_timeout(1600)
            page.screenshot(path=str(output / f"{name.lower()}-empty.png"), full_page=True)
        for name in os.environ.get(
            "SECURESCOPE_PREVIEW_SCREENS", "Assurance,Project Plan,Assess Control,SoA"
        ).split(","):
            page.set_viewport_size(dict(width=1440, height=1000))
            page.goto(f"http://127.0.0.1:8515/?screen={name.replace(' ', '%20')}")
            page.get_by_text("UI verification · synthetic records").wait_for(timeout=15000)
            page.wait_for_timeout(1000)
            content_height = page.locator('[data-testid="stMain"]').evaluate(
                "el => el.scrollHeight"
            )
            page.set_viewport_size(dict(width=1440, height=min(10000, content_height + 120)))
            page.wait_for_timeout(300)
            page.screenshot(
                path=str(output / f"{name.lower().replace(' ', '-')}-full.png"), full_page=True
            )
        browser.close()
finally:
    app.terminate()
    previous_path = output / (
        "compact-assessment-browser-results.json"
        if os.getenv("SECURESCOPE_PREVIEW_SCREENS") == "Assess Control,Control Profiles,Foundation"
        else (
            "control-assessment-browser-results.json"
            if os.getenv("SECURESCOPE_PREVIEW_SCREENS") == "Control,Assess Control"
            else (
                "project-plan-browser-results.json"
                if os.getenv("SECURESCOPE_PREVIEW_SCREENS") == "Project Plan"
                else "browser-results.json"
            )
        )
    )
    previous = []
    combined = {(item["screen"], item["width"]): item for item in previous}
    combined.update({(item["screen"], item["width"]): item for item in results})
    previous_path.write_text(json.dumps(list(combined.values()), indent=2))
