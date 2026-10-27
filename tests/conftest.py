"""Pytest configuration for local SecureScope modules.

The build environment may not include Windows/runtime-only packages. Minimal
stubs are installed only for import-time unit tests; the application installs
real packages from requirements.txt on Windows.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))


try:
    import dotenv  # noqa: F401
except ModuleNotFoundError:
    dotenv_module = types.ModuleType("dotenv")

    def load_dotenv(*_args: object, **_kwargs: object) -> bool:
        """Return a no-op result for dependency-free unit tests."""

        return False

    dotenv_module.load_dotenv = load_dotenv
    sys.modules["dotenv"] = dotenv_module


try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    requests_module = types.ModuleType("requests")
    auth_module = types.ModuleType("requests.auth")

    class Session:
        """Import-only HTTP session stub."""

        def request(self, *_args: object, **_kwargs: object) -> object:
            """Reject accidental network use in offline unit tests."""

            raise RuntimeError("HTTP is unavailable in the unit-test stub.")

        get = request
        post = request

    class HTTPBasicAuth:
        """Import-only basic-auth value object."""

        def __init__(self, username: str, password: str) -> None:
            self.username = username
            self.password = password

    requests_module.Session = Session
    auth_module.HTTPBasicAuth = HTTPBasicAuth
    requests_module.auth = auth_module
    sys.modules["requests"] = requests_module
    sys.modules["requests.auth"] = auth_module


try:
    import urllib3  # noqa: F401
except ModuleNotFoundError:
    urllib3_module = types.ModuleType("urllib3")
    exceptions_module = types.ModuleType("urllib3.exceptions")

    class InsecureRequestWarning(Warning):
        """Import-only TLS warning stub."""

    def disable_warnings(*_args: object, **_kwargs: object) -> None:
        """Ignore warning configuration in dependency-free unit tests."""

    exceptions_module.InsecureRequestWarning = InsecureRequestWarning
    urllib3_module.disable_warnings = disable_warnings
    urllib3_module.exceptions = exceptions_module
    sys.modules["urllib3"] = urllib3_module
    sys.modules["urllib3.exceptions"] = exceptions_module


try:
    import psycopg2  # noqa: F401
except ModuleNotFoundError:
    psycopg2_module = types.ModuleType("psycopg2")

    class PsycopgError(Exception):
        """Stub PostgreSQL exception."""

    def unavailable_connect(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("PostgreSQL is unavailable in the build test stub.")

    psycopg2_module.Error = PsycopgError
    psycopg2_module.connect = unavailable_connect
    extras_module = types.ModuleType("psycopg2.extras")
    sql_module = types.ModuleType("psycopg2.sql")
    pool_module = types.ModuleType("psycopg2.pool")

    class Json:
        """Stub JSON adapter."""

        def __init__(self, value: object) -> None:
            self.value = value

    class RealDictCursor:
        """Stub cursor factory marker."""

    class PoolError(Exception):
        """Stub psycopg2 pool exception."""

    class ThreadedConnectionPool:
        """Import-only connection-pool stub for unit tests."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getconn(self) -> object:
            raise RuntimeError("PostgreSQL is unavailable in the build test stub.")

        def putconn(self, *_args: object, **_kwargs: object) -> None:
            return None

        def closeall(self) -> None:
            return None

    extras_module.Json = Json
    extras_module.RealDictCursor = RealDictCursor
    sql_module.SQL = lambda value: value
    pool_module.PoolError = PoolError
    pool_module.ThreadedConnectionPool = ThreadedConnectionPool
    psycopg2_module.extras = extras_module
    psycopg2_module.sql = sql_module
    psycopg2_module.pool = pool_module
    sys.modules["psycopg2"] = psycopg2_module
    sys.modules["psycopg2.extras"] = extras_module
    sys.modules["psycopg2.sql"] = sql_module
    sys.modules["psycopg2.pool"] = pool_module


try:
    import nmap  # noqa: F401
except ModuleNotFoundError:
    nmap_module = types.ModuleType("nmap")

    class PortScannerError(Exception):
        """Stub Nmap exception."""

    class PortScanner:
        """Stub scanner that must not be used by unit tests."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("Nmap is unavailable in the build test stub.")

    nmap_module.PortScannerError = PortScannerError
    nmap_module.PortScanner = PortScanner
    sys.modules["nmap"] = nmap_module

try:
    import streamlit  # noqa: F401
except ModuleNotFoundError:
    streamlit_module = types.ModuleType("streamlit")
    streamlit_module.session_state = {}

    def _noop(*_args: object, **_kwargs: object) -> None:
        return None

    def _decorator(*_args: object, **_kwargs: object):
        def wrap(function):
            return function

        return wrap

    streamlit_module.set_page_config = _noop
    streamlit_module.markdown = _noop
    streamlit_module.html = _noop
    streamlit_module.cache_data = _decorator
    streamlit_module.fragment = _decorator
    sys.modules["streamlit"] = streamlit_module

try:
    import gvm  # noqa: F401
except ModuleNotFoundError:
    gvm_module = types.ModuleType("gvm")
    connections_module = types.ModuleType("gvm.connections")
    errors_module = types.ModuleType("gvm.errors")
    protocols_module = types.ModuleType("gvm.protocols")
    gmp_module = types.ModuleType("gvm.protocols.gmp")
    transforms_module = types.ModuleType("gvm.transforms")

    class GvmError(Exception):
        """Stub Greenbone exception."""

    class GMP:
        """Import-only GMP stub."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

    class EtreeCheckCommandTransform:
        """Import-only transform stub."""

    errors_module.GvmError = GvmError
    gmp_module.GMP = GMP
    transforms_module.EtreeCheckCommandTransform = EtreeCheckCommandTransform
    gvm_module.connections = connections_module
    protocols_module.gmp = gmp_module

    sys.modules["gvm"] = gvm_module
    sys.modules["gvm.connections"] = connections_module
    sys.modules["gvm.errors"] = errors_module
    sys.modules["gvm.protocols"] = protocols_module
    sys.modules["gvm.protocols.gmp"] = gmp_module
    sys.modules["gvm.transforms"] = transforms_module
