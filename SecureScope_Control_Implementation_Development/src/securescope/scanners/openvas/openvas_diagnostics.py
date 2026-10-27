"""Run non-destructive diagnostics for the SecureScope OpenVAS integration.

The script checks environment variables, PostgreSQL, the local GMP tunnel,
GMP authentication, required Greenbone resources, scanner verification, and
current SecureScope queue state. It never creates or starts a scan task.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
from typing import Any

from dotenv import load_dotenv
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from securescope.paths import ENV_FILE
from securescope.persistence.openvas_persistence import (
    count_active_openvas_scans,
    get_worker_state,
    init_openvas_tables,
    list_queued_openvas_jobs,
)
from securescope.scanners.openvas.openvas_worker_service import (
    GVM_PASSWORD,
    GVM_USERNAME,
    LOCAL_TUNNEL_HOST,
    LOCAL_TUNNEL_PORT,
    OPENVAS_ALIVE_TEST,
    PORT_LIST_NAME,
    SCAN_CONFIG_NAME,
    SCANNER_NAME,
    make_gmp_connection,
)

load_dotenv(dotenv_path=ENV_FILE, override=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(message)s",
)
logger = logging.getLogger("securescope.openvas.diagnostics")


class DiagnosticError(RuntimeError):
    """Raised when one required OpenVAS diagnostic check fails."""


def _resource_id(response: Any, element: str, name: str) -> str:
    """Return the exact Greenbone resource ID matching a name.

    Args:
        response: GMP XML response object.
        element: XML element name, such as ``config`` or ``port_list``.
        name: Exact Greenbone resource name.

    Returns:
        The matched resource UUID.

    Raises:
        DiagnosticError: If the named resource does not exist.
    """
    values = response.xpath(f"{element}[name='{name}']/@id")
    if not values:
        raise DiagnosticError(f"Greenbone resource not found: {element} named {name!r}.")
    return str(values[0])


def check_environment() -> None:
    """Validate environment variables required to authenticate with gvmd.

    Raises:
        DiagnosticError: If ``GVM_PASSWORD`` is missing.
    """
    if not GVM_PASSWORD:
        raise DiagnosticError("GVM_PASSWORD is missing in .env.")

    logger.info("GVM user: %s", GVM_USERNAME)
    logger.info("GMP tunnel endpoint: %s:%s", LOCAL_TUNNEL_HOST, LOCAL_TUNNEL_PORT)
    logger.info("Target alive test: %s", OPENVAS_ALIVE_TEST)


def check_database() -> None:
    """Initialize OpenVAS persistence and display queue state.

    Raises:
        RuntimeError: If PostgreSQL cannot be initialized or queried.
    """
    init_openvas_tables()
    queued = list_queued_openvas_jobs(limit=20)
    active = count_active_openvas_scans()
    worker_name = os.getenv("OPENVAS_WORKER_NAME", "openvas-monitor")
    worker = get_worker_state(worker_name)

    logger.info("PostgreSQL OpenVAS tables: ready")
    logger.info("Queued jobs: %s", len(queued))
    logger.info("Reserved/running scanner slots: %s", active)
    if worker:
        logger.info(
            "Worker: %s; heartbeat age: %ss; %s",
            worker.get("status"),
            worker.get("heartbeat_age_seconds"),
            worker.get("message") or "",
        )
    else:
        logger.warning("No worker heartbeat is stored yet.")


def check_tunnel(timeout_seconds: float = 5.0) -> None:
    """Verify that the local TCP endpoint accepts a connection.

    Args:
        timeout_seconds: Maximum connection wait time in seconds.

    Raises:
        DiagnosticError: If the local SSH tunnel cannot be reached.
    """
    try:
        with socket.create_connection(
            (LOCAL_TUNNEL_HOST, LOCAL_TUNNEL_PORT),
            timeout=timeout_seconds,
        ):
            pass
    except OSError as exc:
        raise DiagnosticError(
            "The local GMP tunnel is unavailable at "
            f"{LOCAL_TUNNEL_HOST}:{LOCAL_TUNNEL_PORT}: {exc}"
        ) from exc

    logger.info("Local GMP tunnel: reachable")


def check_gmp() -> None:
    """Authenticate and validate required Greenbone resources.

    Raises:
        DiagnosticError: If authentication, resource lookup, or scanner
            verification fails.
    """
    with GMP(
        connection=make_gmp_connection(),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        version_response = gmp.get_version()
        versions = version_response.xpath("version/text()")
        version = str(versions[0]) if versions else "unknown"

        config_id = _resource_id(
            gmp.get_scan_configs(),
            "config",
            SCAN_CONFIG_NAME,
        )
        port_list_id = _resource_id(
            gmp.get_port_lists(),
            "port_list",
            PORT_LIST_NAME,
        )
        scanner_ids = gmp.get_scanners().xpath(f"scanner[name='{SCANNER_NAME}']/@id")
        if not scanner_ids:
            raise DiagnosticError(f"Greenbone scanner not found: {SCANNER_NAME!r}.")
        scanner_id = str(scanner_ids[0])
        verification = gmp.verify_scanner(scanner_id)
        status = str(verification.get("status") or "")
        status_text = str(
            verification.get("status_text") or "Scanner verification returned no message."
        )
        if status and not status.startswith("2"):
            raise DiagnosticError(f"Scanner verification failed: {status} {status_text}")

    logger.info("GMP authentication: successful; version %s", version)
    logger.info("Scan config: %s (%s)", SCAN_CONFIG_NAME, config_id)
    logger.info("Port list: %s (%s)", PORT_LIST_NAME, port_list_id)
    logger.info("Scanner: %s (%s) — %s", SCANNER_NAME, scanner_id, status_text)


def main() -> int:
    """Run all diagnostics and return a process exit code.

    Returns:
        ``0`` when every check passes, otherwise ``1``.
    """
    checks = [
        ("environment", check_environment),
        ("database", check_database),
        ("tunnel", check_tunnel),
        ("GMP and scanner", check_gmp),
    ]

    for label, check in checks:
        try:
            check()
        except (DiagnosticError, RuntimeError, OSError, ValueError) as exc:
            logger.error("%s check failed: %s", label, exc)
            return 1

    logger.info("All SecureScope OpenVAS checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
