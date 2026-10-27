"""Native Vega-Lite chart specifications for the ISO assessment dashboard."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

TEAL = "#00685f"
LIGHT_TEAL = "#b0d5d0"
GRID = "#e2e8f0"


def _chart_base(height: int) -> dict[str, Any]:
    """Return shared chart styling without requiring a new plotting package.

    Args:
        height: Plot height in pixels.

    Returns:
        Mutable Vega-Lite base specification.

    Raises:
        No exceptions are raised.
    """

    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "height": height,
        "config": {
            "view": {"stroke": None},
            "axis": {"labelColor": "#475569", "titleColor": "#475569", "gridColor": GRID},
            "legend": {"labelColor": "#475569", "title": None},
            "font": "Inter, sans-serif",
        },
    }


def radar_chart(areas: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Plot conformity on eleven axes with tooltips and visible missing values.

    Args:
        areas: Ordered area summaries containing conformity and counts.

    Returns:
        Layered radar specification. Excluded-only areas are labeled N/A;
        a polygon is drawn only if every area has a defined denominator.

    Raises:
        KeyError: If a supplied area lacks summary fields.
    """

    spec = _chart_base(380)
    spec["padding"] = {"left": 24, "right": 24, "top": 24, "bottom": 24}
    spec["autosize"] = {"type": "fit", "contains": "padding", "resize": True}
    if not areas:
        return {**spec, "data": {"values": []}, "mark": "point"}
    grid, points, labels, spokes = [], [], [], []
    for index, area in enumerate(areas):
        angle = math.pi / 2 - 2 * math.pi * index / len(areas)
        cosine, sine = math.cos(angle), math.sin(angle)
        for radius in (20, 40, 60, 80, 100):
            grid.append({"x": radius * cosine, "y": radius * sine, "ring": radius, "order": index})
        spokes.append({"x": 0, "y": 0, "x2": 100 * cosine, "y2": 100 * sine})
        value = area["conformity"]
        labels.append(
            {
                "x": 120 * cosine,
                "y": 120 * sine,
                "label": area["code"] + (" · N/A" if value is None else ""),
            }
        )
        if value is not None:
            points.append(
                {
                    "x": value * cosine,
                    "y": value * sine,
                    "order": index,
                    "area": area["area"],
                    "conformity": value,
                    "met": area["met"],
                    "in_scope": area["in_scope"],
                }
            )
    xy = {
        dimension: {
            "field": dimension,
            "type": "quantitative",
            "axis": None,
            "scale": {"domain": [-170, 170], "nice": False},
        }
        for dimension in ("x", "y")
    }
    tooltip = [
        {"field": "area", "title": "Area"},
        {"field": "conformity", "type": "quantitative", "format": ".1f", "title": "Conformity (%)"},
        {"field": "met", "type": "quantitative", "title": "Met"},
        {"field": "in_scope", "type": "quantitative", "title": "In scope"},
    ]
    layers = [
        {
            "data": {"values": grid},
            "mark": {"type": "line", "interpolate": "linear-closed", "color": GRID},
            "encoding": {**xy, "detail": {"field": "ring"}, "order": {"field": "order"}},
        },
        {
            "data": {"values": spokes},
            "mark": {"type": "rule", "color": GRID},
            "encoding": {**xy, "x2": {"field": "x2"}, "y2": {"field": "y2"}},
        },
    ]
    if len(points) == len(areas):
        layers.append(
            {
                "data": {"values": points},
                "mark": {
                    "type": "line",
                    "interpolate": "linear-closed",
                    "stroke": TEAL,
                    "strokeWidth": 2,
                    "fill": TEAL,
                    "fillOpacity": 0.15,
                },
                "encoding": {**xy, "order": {"field": "order"}, "tooltip": tooltip},
            }
        )
    layers.extend(
        [
            {
                "data": {"values": points},
                "mark": {"type": "point", "filled": True, "color": TEAL, "size": 55},
                "encoding": {**xy, "tooltip": tooltip},
            },
            {
                "data": {"values": labels},
                "mark": {"type": "text", "fontSize": 12, "color": "#334155", "clip": False},
                "encoding": {**xy, "text": {"field": "label"}},
            },
            {
                "data": {
                    "values": [{"x": 4, "y": r, "label": f"{r}%"} for r in (20, 40, 60, 80, 100)]
                },
                "mark": {
                    "type": "text",
                    "align": "left",
                    "dy": -5,
                    "fontSize": 9,
                    "color": "#64748b",
                },
                "encoding": {**xy, "text": {"field": "label"}},
            },
        ]
    )
    return {**spec, "layer": layers}


def counts_chart(areas: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare in-scope and met counts using paired horizontal bars.

    Args:
        areas: Ordered standard-area summaries.

    Returns:
        Interactive grouped bar specification.

    Raises:
        KeyError: If area summary fields are absent.
    """

    values = [
        {"area": area["area"], "series": label, "count": area[field]}
        for area in areas
        for field, label in (("in_scope", "In scope"), ("met", "Met"))
    ]
    return {
        **_chart_base(360),
        "data": {"values": values},
        "mark": {"type": "bar", "cornerRadiusEnd": 3},
        "encoding": {
            "y": {
                "field": "area",
                "type": "nominal",
                "sort": [a["area"] for a in areas],
                "axis": {"title": None, "labelLimit": 260},
            },
            "yOffset": {"field": "series", "sort": ["In scope", "Met"]},
            "x": {
                "field": "count",
                "type": "quantitative",
                "title": "Assessment units",
                "axis": {"tickMinStep": 1},
            },
            "color": {
                "field": "series",
                "scale": {"domain": ["In scope", "Met"], "range": [LIGHT_TEAL, TEAL]},
                "legend": {"orient": "top"},
            },
            "tooltip": [
                {"field": "area", "title": "Area"},
                {"field": "series", "title": "Measure"},
                {"field": "count", "title": "Count", "type": "quantitative"},
            ],
        },
    }


def conformity_chart(areas: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Plot percent met on a fixed zero-to-one-hundred scale.

    Args:
        areas: Ordered area summaries, with None for excluded-only populations.

    Returns:
        Vertical bar chart with percent labels and N/A labels for undefined data.

    Raises:
        KeyError: If area summary fields are absent.
    """

    values = [
        {
            **area,
            "display": "N/A" if area["conformity"] is None else f'{area["conformity"]:.1f}%',
            "label_height": area["conformity"] if area["conformity"] is not None else 0,
        }
        for area in areas
    ]
    x = {
        "field": "code",
        "type": "nominal",
        "sort": [a["code"] for a in areas],
        "axis": {"title": "Standard area", "labelAngle": 0},
    }
    return {
        **_chart_base(360),
        "data": {"values": values},
        "layer": [
            {
                "mark": {
                    "type": "bar",
                    "color": TEAL,
                    "cornerRadiusTopLeft": 3,
                    "cornerRadiusTopRight": 3,
                },
                "encoding": {
                    "x": x,
                    "y": {
                        "field": "conformity",
                        "type": "quantitative",
                        "scale": {"domain": [0, 100]},
                        "title": "Conformity (%)",
                    },
                    "tooltip": [
                        {"field": "area", "title": "Area"},
                        {"field": "display", "title": "Conformity"},
                        {"field": "met", "title": "Met"},
                        {"field": "in_scope", "title": "In scope"},
                    ],
                },
            },
            {
                "mark": {"type": "text", "dy": -8, "fontSize": 10, "color": "#475569"},
                "encoding": {
                    "x": x,
                    "y": {"field": "label_height", "type": "quantitative"},
                    "text": {"field": "display"},
                },
            },
        ],
    }


def project_timeline(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build a calendar timeline of scheduled leaf tasks.

    Args:
        rows: Calculated project task rows.

    Returns:
        A range-bar chart; bars show inclusive start and finish dates.

    Raises:
        KeyError: If task fields are missing.
    """

    values = [
        {
            "task": f'{row["task_ref"]}. {row["task"]}',
            "start": row["start_date"].isoformat(),
            "finish": row["end_date"].isoformat(),
            "progress": row["progress"] or 0,
            "resource": row["resource"],
        }
        for row in rows
        if row["task_ref"] != 15 and row["start_date"] and row["end_date"]
    ]
    return {
        **_chart_base(max(120, len(values) * 28)),
        "data": {"values": values},
        "transform": [
            {"calculate": "timeOffset('day', toDate(datum.finish), 1)", "as": "finish_exclusive"}
        ],
        "mark": {"type": "bar", "cornerRadius": 3},
        "encoding": {
            "y": {
                "field": "task",
                "type": "nominal",
                "sort": [r["task"] for r in values],
                "axis": {"title": None, "labelLimit": 380},
            },
            "x": {"field": "start", "type": "temporal", "title": "Calendar date"},
            "x2": {"field": "finish_exclusive"},
            "color": {
                "field": "progress",
                "type": "quantitative",
                "scale": {"domain": [0, 100], "range": [LIGHT_TEAL, TEAL]},
                "legend": {"title": "Progress (%)"},
            },
            "tooltip": [
                {"field": f, "title": t}
                for f, t in (
                    ("task", "Task"),
                    ("start", "Start"),
                    ("finish", "End"),
                    ("progress", "Progress (%)"),
                    ("resource", "Resource"),
                )
            ],
        },
    }
