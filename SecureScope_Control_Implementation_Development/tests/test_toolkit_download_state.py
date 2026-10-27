"""Streamlit state checks for downloadable toolkit revisions."""

from streamlit.testing.v1 import AppTest


def test_populated_toolkit_action_is_removed() -> None:
    """The normal UI exposes no toolkit action or missing-runtime errors."""
    app = AppTest.from_string(
        """
import streamlit as st
from securescope.ui.document_registers_ui import render_populated_toolkit_download
impact = st.number_input("Impact", min_value=1, max_value=5, value=2)
render_populated_toolkit_download(
    "asset_risks", [{"risk_ref": 1, "pre_impact": impact}],
    client_name="Client A", key="download-test",
)
"""
    ).run()
    assert not app.exception
    assert not app.button
    assert not app.error
    app.number_input[0].set_value(3).run()
    assert not app.exception
    assert not app.button
