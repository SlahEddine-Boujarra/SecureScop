"""Safe command builder and health checks for the Nuclei CLI.

SecureScope integrates the open-source Nuclei command-line scanner rather than
running Nuclei as an HTTP service. The standalone SecureScope worker owns every
process. Streamlit only creates PostgreSQL jobs and displays their state.

Nuclei OSS does not require an API key. A ProjectDiscovery Cloud Platform key
is optional and is configured outside SecureScope with ``nuclei -auth`` when
cloud result upload is desired.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from securescope.core.output_sanitizer import (
    display_tool_output,
    extract_semantic_version,
    strip_ansi_sequences,
)
from securescope.paths import ENV_FILE, PROJECT_ROOT

APP_DIR = PROJECT_ROOT
load_dotenv(dotenv_path=ENV_FILE, override=False)


class NucleiError(RuntimeError):
    """Base exception for Nuclei integration failures."""


class NucleiConfigurationError(NucleiError):
    """Raised when the Nuclei integration configuration is invalid."""


class NucleiNotInstalledError(NucleiError):
    """Raised when the configured Nuclei executable cannot be found."""


class NucleiExecutionError(NucleiError):
    """Raised when a bounded Nuclei command returns an error."""


PROFILE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "standard": {
        "label": "Standard safe assessment",
        "description": (
            "Runs official community templates across supported protocols while "
            "excluding denial-of-service, fuzzing and brute-force tags."
        ),
        "flags": [],
    },
    "cve": {
        "label": "Known CVEs",
        "description": "Runs templates tagged with CVE identifiers.",
        "flags": ["-tags", "cve"],
    },
    "exposure": {
        "label": "Exposure and misconfiguration",
        "description": (
            "Focuses on exposed panels, files, weak defaults and common " "misconfigurations."
        ),
        "flags": ["-tags", "exposure,misconfig"],
    },
    "network": {
        "label": "Network, TLS and DNS",
        "description": (
            "Runs TCP, SSL, DNS and HTTP templates against the asset targets "
            "derived from Nmap inventory."
        ),
        "flags": ["-type", "tcp,ssl,dns,http"],
    },
    "automatic-web": {
        "label": "Automatic web technology scan",
        "description": (
            "Uses Nuclei automatic web scanning and Wappalyzer technology "
            "detection to select matching template tags."
        ),
        "flags": ["-automatic-scan"],
    },
}


@dataclass(frozen=True)
class NucleiConfig:
    """Runtime configuration for the Nuclei command-line integration.

    Attributes:
        binary: Configured executable path or command name.
        template_directory: Optional explicit templates directory.
        rate_limit: Global requests-per-second ceiling for one job.
        bulk_size: Maximum hosts processed per template.
        concurrency: Maximum templates processed concurrently.
        request_timeout_seconds: Per-request timeout used by Nuclei.
        retries: Number of request retries.
        max_host_errors: Host error threshold before Nuclei skips the host.
        disable_interactsh: Whether OAST templates are disabled.
        disable_unsigned_templates: Whether unsigned templates are rejected.
        disable_update_check: Whether automatic update checks are disabled.
        dashboard_upload: Whether results are uploaded to an already
            authenticated ProjectDiscovery Cloud account.
        command_timeout_seconds: Bound for diagnostic commands.
        excluded_tags: Comma-separated tags omitted from normal scans.
    """

    binary: str
    template_directory: str
    rate_limit: int
    bulk_size: int
    concurrency: int
    request_timeout_seconds: int
    retries: int
    max_host_errors: int
    disable_interactsh: bool
    disable_unsigned_templates: bool
    disable_update_check: bool
    dashboard_upload: bool
    command_timeout_seconds: int
    excluded_tags: str

    @classmethod
    def from_environment(cls) -> "NucleiConfig":
        """Build a validated configuration from environment variables.

        Returns:
            A validated :class:`NucleiConfig` instance.

        Raises:
            NucleiConfigurationError: If a numeric setting is invalid.
        """

        default_binary = APP_DIR / "tools" / "nuclei" / "nuclei.exe"
        binary = os.getenv(
            "NUCLEI_BINARY",
            str(default_binary) if default_binary.exists() else "nuclei",
        ).strip()

        def env_int(name: str, default: int, minimum: int) -> int:
            raw = os.getenv(name, str(default)).strip()
            try:
                value = int(raw)
            except ValueError as exc:
                raise NucleiConfigurationError(
                    f"{name} must be an integer, received {raw!r}."
                ) from exc
            if value < minimum:
                raise NucleiConfigurationError(f"{name} must be at least {minimum}.")
            return value

        def env_bool(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        if not binary:
            raise NucleiConfigurationError("NUCLEI_BINARY cannot be empty.")

        return cls(
            binary=binary,
            template_directory=os.getenv(
                "NUCLEI_TEMPLATES_DIR",
                "",
            ).strip(),
            rate_limit=env_int("NUCLEI_RATE_LIMIT", 50, 1),
            bulk_size=env_int("NUCLEI_BULK_SIZE", 10, 1),
            concurrency=env_int("NUCLEI_CONCURRENCY", 10, 1),
            request_timeout_seconds=env_int(
                "NUCLEI_REQUEST_TIMEOUT_SECONDS",
                10,
                1,
            ),
            retries=env_int("NUCLEI_RETRIES", 1, 0),
            max_host_errors=env_int("NUCLEI_MAX_HOST_ERRORS", 20, 1),
            disable_interactsh=env_bool(
                "NUCLEI_DISABLE_INTERACTSH",
                False,
            ),
            disable_unsigned_templates=env_bool(
                "NUCLEI_DISABLE_UNSIGNED_TEMPLATES",
                False,
            ),
            disable_update_check=env_bool(
                "NUCLEI_DISABLE_UPDATE_CHECK",
                True,
            ),
            dashboard_upload=env_bool(
                "NUCLEI_DASHBOARD_UPLOAD",
                False,
            ),
            command_timeout_seconds=env_int(
                "NUCLEI_DIAGNOSTIC_TIMEOUT_SECONDS",
                30,
                2,
            ),
            excluded_tags=os.getenv(
                "NUCLEI_EXCLUDE_TAGS",
                "dos,fuzz,fuzzing,bruteforce,creds-stuffing,token-spray",
            ).strip(),
        )


class NucleiClient:
    """Bounded wrapper around the local Nuclei executable."""

    def __init__(self, config: NucleiConfig | None = None) -> None:
        """Initialize the wrapper.

        Args:
            config: Optional explicit runtime configuration.
        """

        self.config = config or NucleiConfig.from_environment()

    def resolved_binary(self) -> str:
        """Return an executable path that can be passed to ``subprocess``.

        Returns:
            Absolute or PATH-resolved executable path.

        Raises:
            NucleiNotInstalledError: If the executable cannot be found.
        """

        configured = Path(self.config.binary).expanduser()
        if configured.is_file():
            return str(configured.resolve())

        resolved = shutil.which(self.config.binary)
        if resolved:
            return resolved

        raise NucleiNotInstalledError(
            "Nuclei was not found. Install the official Windows binary or set "
            "NUCLEI_BINARY to nuclei.exe."
        )

    def _run_read_only(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        """Run one read-only Nuclei command with a strict timeout.

        Args:
            arguments: Command arguments excluding the executable.

        Returns:
            The completed process.

        Raises:
            NucleiExecutionError: If execution fails or times out.
        """

        command = [self.resolved_binary(), *arguments]
        try:
            result = subprocess.run(
                command,
                cwd=APP_DIR,
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NucleiExecutionError(
                f"Nuclei command timed out after {exc.timeout} seconds."
            ) from exc
        except OSError as exc:
            raise NucleiExecutionError(
                f"Could not execute Nuclei: {type(exc).__name__}: {exc}"
            ) from exc

        if result.returncode != 0:
            detail = display_tool_output(result.stderr or result.stdout, 1000)
            raise NucleiExecutionError(f"Nuclei returned exit code {result.returncode}: {detail}")
        return result

    @staticmethod
    def _first_nonempty_line(value: str) -> str:
        """Return the first non-empty output line."""

        for line in strip_ansi_sequences(value).splitlines():
            if line.strip():
                return line.strip()
        return ""

    def version(self) -> str:
        """Return the installed Nuclei version string."""

        result = self._run_read_only(["-version"])
        output = result.stdout or result.stderr
        line = self._first_nonempty_line(output)
        match = re.search(r"v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?", line)
        return match.group(0) if match else line or "Unknown"

    def templates_version(self) -> str:
        """Return the installed community-template version when available."""

        try:
            result = self._run_read_only(["-templates-version"])
        except NucleiExecutionError:
            return "Not reported"
        output = result.stdout or result.stderr
        return extract_semantic_version(output)

    def health(self) -> dict[str, Any]:
        """Return redacted local engine health information.

        Returns:
            Health data safe to display in the Streamlit interface.

        Raises:
            NucleiError: If the executable cannot be used.
        """

        self.resolved_binary()
        version = self.version()
        template_directory = self.config.template_directory
        return {
            "ok": True,
            "binary": "Nuclei CLI",
            "version": version,
            "templates_version": self.templates_version(),
            "template_directory": (
                "Custom template directory" if template_directory else "Nuclei default"
            ),
            "dashboard_upload": self.config.dashboard_upload,
            "api_key_required": False,
            "message": "Nuclei CLI and templates are available.",
        }

    def update_templates(self) -> str:
        """Update the official community template collection.

        Returns:
            A concise command result.

        Raises:
            NucleiExecutionError: If the update fails.
        """

        arguments = ["-update-templates"]
        if self.config.template_directory:
            arguments.extend(["-update-template-dir", self.config.template_directory])
        result = self._run_read_only(arguments)
        output = (result.stdout or result.stderr or "").strip()
        return output[-2000:] or "Template update completed."

    def build_scan_command(
        self,
        *,
        target_file: Path,
        output_file: Path,
        profile_name: str,
        scan_name: str,
        project_directory: Path,
    ) -> list[str]:
        """Build a safe Nuclei command for one SecureScope job.

        Args:
            target_file: File containing one target per line.
            output_file: JSONL findings output path.
            profile_name: Key from :data:`PROFILE_DEFINITIONS`.
            scan_name: Stable SecureScope job name.
            project_directory: Per-job Nuclei project directory.

        Returns:
            A subprocess argument list.

        Raises:
            NucleiConfigurationError: If the profile is unknown.
        """

        profile = PROFILE_DEFINITIONS.get(profile_name)
        if profile is None:
            raise NucleiConfigurationError(f"Unknown Nuclei profile: {profile_name!r}.")

        target_file = target_file.resolve()
        output_file = output_file.resolve()
        project_directory = project_directory.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        project_directory.mkdir(parents=True, exist_ok=True)

        command = [
            self.resolved_binary(),
            "-list",
            str(target_file),
            "-jsonl-export",
            str(output_file),
            "-silent",
            "-no-color",
            "-omit-raw",
            "-omit-template",
            "-no-stdin",
            "-stats",
            "-stats-json",
            "-stats-interval",
            "5",
            "-rate-limit",
            str(self.config.rate_limit),
            "-bulk-size",
            str(self.config.bulk_size),
            "-concurrency",
            str(self.config.concurrency),
            "-timeout",
            str(self.config.request_timeout_seconds),
            "-retries",
            str(self.config.retries),
            "-max-host-error",
            str(self.config.max_host_errors),
            "-project",
            "-project-path",
            str(project_directory),
        ]

        if self.config.excluded_tags:
            command.extend(["-exclude-tags", self.config.excluded_tags])
        if self.config.template_directory:
            command.extend(["-templates", self.config.template_directory])
        if self.config.disable_interactsh:
            command.append("-no-interactsh")
        if self.config.disable_unsigned_templates:
            command.append("-disable-unsigned-templates")
        if self.config.disable_update_check:
            command.append("-disable-update-check")
        if self.config.dashboard_upload:
            command.extend(["-dashboard", "-scan-name", scan_name])

        command.extend(str(flag) for flag in profile["flags"])
        return command


def profile_options() -> list[dict[str, str]]:
    """Return stable profile metadata for the user interface."""

    return [
        {
            "key": key,
            "label": str(value["label"]),
            "description": str(value["description"]),
        }
        for key, value in PROFILE_DEFINITIONS.items()
    ]
