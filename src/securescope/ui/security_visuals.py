"""Small, data-backed visualizations for investigation workspaces."""

from collections import Counter

import pandas as pd
import streamlit as st


def risk_matrix(rows: list[dict], *, key: str) -> None:
    """Display recorded pre-treatment likelihood/impact without scoring blanks.

    Args:
        rows: Saved canonical risks.
        key: Stable chart identity.
    Returns:
        None.
    Raises:
        StreamlitAPIException: If chart rendering fails.
    """
    assessed = [
        row
        for row in rows
        if type(row.get("pre_likelihood")) is int
        and type(row.get("pre_impact")) is int
        and 1 <= row["pre_likelihood"] <= 5
        and 1 <= row["pre_impact"] <= 5
    ]
    if not assessed:
        st.info(
            (
                "The risk matrix appears after likelihood and impact are recorded."
                " Missing ratings are not low risk."
            )
        )
        return
    counts = Counter((row["pre_likelihood"], row["pre_impact"]) for row in assessed)
    grid = [
        {
            "Likelihood": likelihood,
            "Impact": impact,
            "Risks": counts[(likelihood, impact)],
            "Score": likelihood * impact,
        }
        for likelihood in range(1, 6)
        for impact in range(1, 6)
    ]
    st.caption(
        (
            f"{len(assessed)}"
            " assessed risks · "
            f"{len(rows) - len(assessed)}"
            " without complete ratings. Cell labels count recorded "
            "risks."
        )
    )
    st.vega_lite_chart(
        pd.DataFrame(grid),
        {
            "height": 260,
            "encoding": {
                "x": {"field": "Impact", "type": "ordinal", "title": "Impact →"},
                "y": {
                    "field": "Likelihood",
                    "type": "ordinal",
                    "sort": "descending",
                    "title": "Likelihood →",
                },
            },
            "layer": [
                {
                    "mark": {"type": "rect", "stroke": "white", "strokeWidth": 3},
                    "encoding": {
                        "color": {
                            "field": "Score",
                            "type": "quantitative",
                            "scale": {"scheme": "yelloworangered", "domain": [1, 25]},
                            "legend": {"title": "Likelihood × impact"},
                        },
                        "tooltip": [
                            {"field": "Likelihood"},
                            {"field": "Impact"},
                            {"field": "Risks"},
                            {"field": "Score"},
                        ],
                    },
                },
                {
                    "mark": {"type": "text", "fontSize": 18, "fontWeight": "bold"},
                    "encoding": {
                        "text": {"field": "Risks", "type": "quantitative"},
                        "color": {
                            "condition": {"test": "datum.Score >= 15", "value": "white"},
                            "value": "#172336",
                        },
                    },
                },
            ],
        },
        width="stretch",
        key=key,
    )
