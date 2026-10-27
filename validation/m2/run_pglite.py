"""Run explicit test commands beside a disposable loopback-only PGlite server."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import psycopg2

ROOT = Path(__file__).resolve().parent
APP = ROOT.parents[1]
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
url = f"postgresql://postgres:postgres@127.0.0.1:{port}/postgres?sslmode=disable&connect_timeout=5"
with (ROOT / "pglite-server.log").open("w") as log:
    server = subprocess.Popen(
        [
            str(ROOT / "pglite/node_modules/.bin/pglite-server"),
            "--db=memory://",
            "--host=127.0.0.1",
            f"--port={port}",
            "--max-connections=8",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        for attempt in range(150):
            if server.poll() is not None:
                raise RuntimeError("Embedded server exited during startup")
            try:
                connection = psycopg2.connect(url)
                break
            except psycopg2.OperationalError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Embedded server did not become reachable")
        with connection, connection.cursor() as cursor:
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            print(version, flush=True)
        connection.close()
        (ROOT / "engine.json").write_text(
            json.dumps(
                {
                    "engine": "PGlite (PostgreSQL compiled to WebAssembly)",
                    "version": version,
                    "pglite": "0.5.8",
                    "socket": "0.2.11",
                    "native_postgresql": False,
                    "data": "disposable in-memory database",
                    "concurrency_validated": False,
                },
                indent=2,
            )
        )
        environment = dict(os.environ, SECURESCOPE_TEST_DATABASE_URL=url, PYTHONPATH="src")
        result = subprocess.run(
            [sys.executable, *sys.argv[1:]], env=environment, cwd=APP, timeout=180
        )
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
sys.exit(result.returncode)
