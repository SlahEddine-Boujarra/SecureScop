"""Suppress only known harmless Windows/Streamlit runtime cleanup noise.

Real OpenVAS, GMP, SSH, PostgreSQL, and scanner errors remain visible.
"""

from __future__ import annotations

import logging
from typing import Any


class _ExpectedRuntimeNoiseFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        exception: Any = record.exc_info[1] if record.exc_info else None

        expected_reset = (
            record.name == "asyncio"
            and isinstance(exception, ConnectionResetError)
            and getattr(exception, "winerror", None) == 10054
            and (
                "_ProactorBasePipeTransport._call_connection_lost" in message
                or "Exception in callback _ProactorBasePipeTransport" in message
            )
        )

        harmless_fragment_race = (
            "Couldn't find fragment with id" in message
            and "fragment does not exist anymore" in message
        )

        return not (expected_reset or harmless_fragment_race)


_FILTER = _ExpectedRuntimeNoiseFilter()


def install_windows_asyncio_cleanup_filter() -> None:
    """Install the narrow runtime-noise filter on relevant loggers/handlers."""
    loggers = (
        logging.getLogger("asyncio"),
        logging.getLogger("streamlit"),
        logging.getLogger("streamlit.runtime.fragment"),
        logging.getLogger(),
    )

    for logger in loggers:
        if not any(
            isinstance(existing, _ExpectedRuntimeNoiseFilter) for existing in logger.filters
        ):
            logger.addFilter(_FILTER)
        for handler in logger.handlers:
            if not any(
                isinstance(existing, _ExpectedRuntimeNoiseFilter) for existing in handler.filters
            ):
                handler.addFilter(_FILTER)
