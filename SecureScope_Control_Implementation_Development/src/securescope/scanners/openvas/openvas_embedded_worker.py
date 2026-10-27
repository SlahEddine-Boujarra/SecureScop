"""Single-lane embedded OpenVAS worker for SecureScope stabilization.

All Greenbone Management Protocol traffic is intentionally serialized. The
previous multi-threaded worker opened several GMP sessions through one SSH
forwarded Unix socket at the same time, which caused intermittent gvmd 500
responses, timeouts, New tasks that never received start_task, and Local only
rows that never synchronized.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv

from securescope.paths import ENV_FILE
from securescope.persistence.openvas_persistence import update_worker_heartbeat
from securescope.scanners.openvas.openvas_worker_service import (
    process_openvas_fast_status_cycle,
    process_openvas_queue_start_cycle,
    process_openvas_worker_cycle,
)

load_dotenv(dotenv_path=ENV_FILE, override=False)

WORKER_NAME = os.getenv("OPENVAS_WORKER_NAME", "openvas-monitor")
POLL_SECONDS = max(2, int(os.getenv("OPENVAS_FAST_STATUS_POLL_SECONDS", "5")))
DEEP_POLL_SECONDS = max(30, int(os.getenv("OPENVAS_DEEP_RECONCILE_SECONDS", "60")))
ERROR_RETRY_SECONDS = max(5, int(os.getenv("OPENVAS_WORKER_ERROR_RETRY_SECONDS", "10")))
PRIORITY_WATCH_TTL_SECONDS = max(15, int(os.getenv("OPENVAS_PRIORITY_WATCH_TTL_SECONDS", "30")))

logger = logging.getLogger("securescope.openvas.embedded")


def _is_tunnel_offline_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(
        token in text
        for token in (
            "winerror 10061",
            "actively refused",
            "ssh tunnel offline",
            "connection refused",
        )
    )


@dataclass
class EmbeddedWorkerRuntime:
    """Exactly one provider thread for task start, status and finalization."""

    thread: threading.Thread | None = None
    # Compatibility fields retained for the existing UI.
    starter_thread: threading.Thread | None = None
    deep_thread: threading.Thread | None = None
    priority_thread: threading.Thread | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    wake_event: threading.Event = field(default_factory=threading.Event)
    state_lock: threading.Lock = field(default_factory=threading.Lock)
    started: bool = False
    last_message: str = "Not started"
    last_error: str = ""
    last_cycle_at: str = ""
    starter_message: str = "Not started"
    starter_error: str = ""
    last_start_cycle_at: str = ""
    deep_message: str = "Not started"
    deep_error: str = ""
    last_deep_cycle_at: str = ""
    priority_batch_id: int | None = None
    watched_batches: dict[int, float] = field(default_factory=dict)
    priority_message: str = "Not started"
    priority_error: str = ""
    last_priority_cycle_at: str = ""
    priority_inflight: set[int] = field(default_factory=set)

    def start(self) -> "EmbeddedWorkerRuntime":
        self.stop_event.clear()
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(
                target=self._run,
                name="SecureScopeOpenVASStableProvider",
                daemon=True,
            )
            self.thread.start()
        # The UI expects these attributes. They intentionally reference the one
        # real thread instead of creating competing GMP loops.
        self.starter_thread = self.thread
        self.deep_thread = self.thread
        self.priority_thread = self.thread
        self.started = True
        return self

    def _persist_heartbeat(self, *, status: str, message: str) -> None:
        try:
            update_worker_heartbeat(
                worker_name=WORKER_NAME,
                pid=os.getpid(),
                hostname=socket.gethostname(),
                status=status,
                message=message,
            )
        except Exception:
            logger.exception("Could not persist worker heartbeat")

    def _active_watched_batch(self) -> int | None:
        now = time.monotonic()
        with self.state_lock:
            expired = [
                batch_id
                for batch_id, expires_at in self.watched_batches.items()
                if expires_at <= now
            ]
            for batch_id in expired:
                self.watched_batches.pop(batch_id, None)
            active = sorted(self.watched_batches)
            self.priority_batch_id = active[-1] if active else None
            return self.priority_batch_id

    def watch_batch(
        self,
        batch_id: int,
        *,
        ttl_seconds: int = PRIORITY_WATCH_TTL_SECONDS,
    ) -> None:
        normalized = int(batch_id)
        with self.state_lock:
            self.priority_batch_id = normalized
            self.watched_batches[normalized] = time.monotonic() + max(15, int(ttl_seconds))
        self.wake_event.set()

    def _run(self) -> None:
        self._persist_heartbeat(
            status="running",
            message="Single-lane OpenVAS provider worker started.",
        )
        last_deep = 0.0

        while not self.stop_event.is_set():
            cycle_started = time.monotonic()
            watched_batch = self._active_watched_batch()
            try:
                # 1) Create/start any explicitly activated batch. Management
                # commands are serialized in the worker service.
                start_result = process_openvas_queue_start_cycle()
                now_iso = datetime.now(timezone.utc).isoformat()
                self.last_start_cycle_at = now_iso
                self.starter_error = str(start_result.get("error") or "")
                if int(start_result.get("busy") or 0):
                    self.starter_message = "Provider command lane is busy."
                else:
                    self.starter_message = (
                        f"Started {start_result.get('started', 0)} task(s); "
                        f"{start_result.get('queued', 0)} await dispatch."
                    )

                # 2) Refresh the currently visible batch first. With no visible
                # batch, refresh the bounded global recent-task set.
                if watched_batch is not None:
                    with self.state_lock:
                        self.priority_inflight.add(int(watched_batch))
                    try:
                        sync_result = process_openvas_fast_status_cycle(batch_id=int(watched_batch))
                    finally:
                        with self.state_lock:
                            self.priority_inflight.discard(int(watched_batch))
                    self.last_priority_cycle_at = now_iso
                    self.priority_error = str(sync_result.get("error") or "")
                    self.priority_message = (
                        f"Batch #{watched_batch}: synchronized "
                        f"{sync_result.get('updated', 0)} task(s); "
                        f"{sync_result.get('failed', 0)} failed."
                    )
                else:
                    sync_result = process_openvas_fast_status_cycle()

                self.last_cycle_at = datetime.now(timezone.utc).isoformat()
                self.last_error = str(sync_result.get("error") or "")
                self.last_message = (
                    f"Provider sync updated {sync_result.get('updated', 0)} "
                    f"task(s); {sync_result.get('failed', 0)} failed."
                )

                # 3) Heavy report import/finalization runs less frequently and
                # never concurrently with start/status GMP commands.
                if time.monotonic() - last_deep >= DEEP_POLL_SECONDS:
                    deep_result = process_openvas_worker_cycle(
                        batch_id=int(watched_batch) if watched_batch is not None else None
                    )
                    self.last_deep_cycle_at = datetime.now(timezone.utc).isoformat()
                    self.deep_error = str(deep_result.get("error") or "")
                    self.deep_message = (
                        f"Finalized {deep_result.get('finalized', 0)} task(s); "
                        f"{deep_result.get('failed', 0)} failed."
                    )
                    last_deep = time.monotonic()

                self._persist_heartbeat(
                    status="running",
                    message=(f"{self.starter_message} {self.last_message}"),
                )
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                if error != self.last_error:
                    if _is_tunnel_offline_error(exc):
                        logger.warning("OpenVAS provider lane paused: %s", error)
                    else:
                        logger.exception("Single-lane OpenVAS worker failed")
                self.last_error = error
                self.last_message = error
                self.starter_error = error
                self.priority_error = error
                self._persist_heartbeat(status="error", message=error)

            elapsed = time.monotonic() - cycle_started
            wait_seconds = max(0.2, POLL_SECONDS - elapsed)
            self.wake_event.wait(wait_seconds)
            self.wake_event.clear()

    def wake(self, batch_id: int | None = None) -> None:
        if batch_id is not None:
            self.watch_batch(int(batch_id))
        self.wake_event.set()

    def snapshot(self) -> dict[str, Any]:
        with self.state_lock:
            watched = sorted(self.watched_batches)
            inflight = sorted(self.priority_inflight)
            priority_batch_id = self.priority_batch_id
        alive = bool(self.thread and self.thread.is_alive())
        return {
            "started": self.started,
            "alive": alive,
            "starter_alive": alive,
            "deep_alive": alive,
            "priority_alive": alive,
            "owns_lock": True,
            "mode": "single-lane stabilization",
            "message": self.last_message,
            "error": self.last_error,
            "last_cycle_at": self.last_cycle_at,
            "starter_message": self.starter_message,
            "starter_error": self.starter_error,
            "last_start_cycle_at": self.last_start_cycle_at,
            "deep_message": self.deep_message,
            "deep_error": self.deep_error,
            "last_deep_cycle_at": self.last_deep_cycle_at,
            "priority_batch_id": priority_batch_id,
            "priority_inflight": inflight,
            "watched_batches": watched,
            "priority_message": self.priority_message,
            "priority_error": self.priority_error,
            "last_priority_cycle_at": self.last_priority_cycle_at,
        }


_RUNTIME: EmbeddedWorkerRuntime | None = None
_RUNTIME_LOCK = threading.Lock()


def start_embedded_openvas_worker() -> EmbeddedWorkerRuntime:
    global _RUNTIME
    with _RUNTIME_LOCK:
        if _RUNTIME is None:
            _RUNTIME = EmbeddedWorkerRuntime()
        return _RUNTIME.start()
