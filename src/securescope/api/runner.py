"""Console entry point for the SecureScope FastAPI control plane."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    """Start the control plane on the configured private interface and port."""

    uvicorn.run(
        "securescope.api.app:app",
        host=os.getenv("SECURESCOPE_API_HOST", "127.0.0.1"),
        port=int(os.getenv("SECURESCOPE_API_PORT", "8765")),
        reload=False,
    )


if __name__ == "__main__":
    main()
