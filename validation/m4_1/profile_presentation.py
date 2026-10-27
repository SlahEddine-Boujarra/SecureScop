"""Profile the read-only adapter with synthetic inventory data; no source access."""

import cProfile
import pstats
from datetime import datetime, timezone

from securescope.ui.siem_presentation import monitoring_view

if __name__ == "__main__":
    rows = [
        dict(asset_id=n, asset_tag=f"Fixture {n}", monitoring_state="active_unverified")
        for n in range(1, 10001)
    ]
    profiler = cProfile.Profile()
    profiler.runcall(
        monitoring_view, rows, "Synthetic profile workspace", now=datetime.now(timezone.utc)
    )
    pstats.Stats(profiler).sort_stats("cumulative").print_stats(12)
