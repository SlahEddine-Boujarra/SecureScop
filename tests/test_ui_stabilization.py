"""Readiness semantics and interaction regressions for the presentation-only pass."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from securescope.ui.integration_presentation import api_configuration_status, configured_value


@pytest.mark.parametrize(
    "value", ["", "CHANGE_ME", "change-me", "your_password", "password", "<secret>"]
)
def test_placeholder_values_are_not_ready(value):
    assert not configured_value(value)
    assert (
        api_configuration_status("https://siem.internal:55000", "analyst", value) == "Needs setup"
    )


@pytest.mark.parametrize(
    "url",
    ["https://CHANGE_ME:55000", "https://wazuh.example:55000", "https://example.com", "not a url"],
)
def test_placeholder_urls_are_not_ready(url):
    assert api_configuration_status(url, "analyst", "a-real-secret") == "Needs setup"


def test_configuration_never_claims_connectivity():
    assert (
        api_configuration_status("https://siem.internal:55000", "analyst", "a-real-secret")
        == "Configured — Not verified"
    )


def test_attention_rows_sort_and_preserve_click_filter():
    app = AppTest.from_string("""
import streamlit as st
from securescope.ui.components.stitch import render_attention_actions
selected=render_attention_actions([("Failed Requirements",0),("Missing Evidence",123),("Policy Missing",2)],key="queue")
if selected: st.session_state["filter"] = selected
st.selectbox("Attention filter",["All","Missing Evidence","Policy Missing","Failed Requirements"],key="filter")
""").run()
    assert not app.exception
    assert len(app.button) == 2
    app.button[0].click().run()
    assert app.selectbox[0].value == "Missing Evidence"
    assert not app.metric


def test_identity_is_escaped_not_email_markdown(monkeypatch):
    from securescope.ui.components import primitives

    output = []
    monkeypatch.setattr(primitives, "render_html", output.append)
    primitives.identity_context("<img>@example.test", "Consultant")
    assert "&lt;img&gt;" in output[0]
    assert "mailto:" not in output[0]


def test_policy_builder_is_excluded_from_workspace_style():
    source = Path("src/securescope/ui/components_v2/assurance_workbench.js").read_text()
    assert "root.classList.toggle('client-workbench',data.mode!=='policy_builder')" in source
    assert "btn('B'," not in source
    assert "btn('I'," not in source
