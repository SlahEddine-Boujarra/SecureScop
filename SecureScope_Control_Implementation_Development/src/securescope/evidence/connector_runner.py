"""Allowlisted command plans for defensive evidence collectors.

This module never accepts free-form command arguments. Commands are passed to
subprocess as argument lists with ``shell=False`` and are intended to run only
inside the independent evidence worker.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from securescope.evidence.tool_catalog import ExecutionPolicy, get_tool

DOMAIN = re.compile(
    r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+|@[A-Za-z0-9:+._-]+)?$")
PROFILE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
PROVIDERS = {"aws", "azure", "gcp", "kubernetes", "m365", "github"}


class ConnectorPlanError(ValueError):
    """Raised when a collector, target or executable is not safely supported."""


@dataclass(frozen=True)
class CollectionPlan:
    """Fully resolved, non-shell collector execution plan."""

    tool_id: str
    command: tuple[str, ...]
    output_path: Path
    timeout_seconds: int
    stdout_is_report: bool = False


def _executable(tool_id: str) -> str:
    """Resolve one allowlisted executable from the approved source catalog."""

    tool = get_tool(tool_id)
    for candidate in tool.executable_names:
        resolved = shutil.which(candidate)
        if resolved:
            return str(Path(resolved).resolve())
    raise ConnectorPlanError(f"{tool.name} is not installed or is not on PATH.")


def _url(value: str) -> str:
    """Validate an HTTP(S) URL without embedded credentials."""

    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConnectorPlanError("Collector target must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise ConnectorPlanError("Collector URLs cannot contain credentials.")
    return value.strip()


def _domain(value: str) -> str:
    """Validate a DNS domain used by authorized reconnaissance collectors."""

    candidate = value.strip().lower().rstrip(".")
    if not DOMAIN.fullmatch(candidate):
        raise ConnectorPlanError("Collector target must be a valid DNS domain.")
    return candidate


def _local_path(value: str, allowed_root: Path | None) -> str:
    """Resolve a local target beneath an administrator-approved root."""

    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise ConnectorPlanError(f"Collector path does not exist: {path}")
    if allowed_root:
        root = allowed_root.resolve()
        if path != root and root not in path.parents:
            raise ConnectorPlanError(
                "Collector path is outside SECURESCOPE_COLLECTOR_ALLOWED_ROOT."
            )
    return str(path)


def build_collection_plan(
    tool_id: str,
    target: str,
    output_directory: Path,
    *,
    allowed_root: Path | None = None,
    profile: str = "",
    timeout_seconds: int = 1800,
) -> CollectionPlan:
    """Build an allowlisted plan for one defensive local collector."""

    tool = get_tool(tool_id)
    if tool.execution_policy is not ExecutionPolicy.DEFENSIVE_ONLY:
        raise ConnectorPlanError(f"{tool.name} cannot run through the defensive evidence worker.")
    if timeout_seconds < 30 or timeout_seconds > 14_400:
        raise ConnectorPlanError("Collector timeout must be between 30 and 14400 seconds.")
    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    executable = _executable(tool_id)
    output = output_directory / "report.json"
    stdout_report = False
    if tool_id == "zap":
        command = (
            executable,
            "-cmd",
            "-quickurl",
            _url(target),
            "-quickout",
            str(output),
            "-quickprogress",
        )
    elif tool_id == "amass":
        command = (executable, "enum", "-passive", "-d", _domain(target), "-json", str(output))
    elif tool_id == "theharvester":
        output = output_directory / "theharvester"
        command = (executable, "-d", _domain(target), "-b", "all", "-f", str(output))
    elif tool_id == "dnsrecon":
        command = (executable, "-d", _domain(target), "-j", str(output))
    elif tool_id == "nikto":
        command = (executable, "-h", _url(target), "-Format", "json", "-output", str(output))
    elif tool_id == "wapiti":
        output = output_directory / "wapiti"
        command = (executable, "-u", _url(target), "-f", "json", "-o", str(output))
    elif tool_id == "droopescan":
        command = (executable, "scan", "-u", _url(target), "--output", "json")
        stdout_report = True
    elif tool_id == "lynis":
        output = output_directory / "lynis-report.dat"
        command = (
            executable,
            "audit",
            "system",
            "--quick",
            "--no-colors",
            "--report-file",
            str(output),
        )
    elif tool_id == "openscap":
        policy = _local_path(target, allowed_root)
        if not PROFILE.fullmatch(profile):
            raise ConnectorPlanError(
                "OpenSCAP collection requires an allowlisted profile identifier."
            )
        output = output_directory / "openscap-results.arf.xml"
        command = (
            executable,
            "xccdf",
            "eval",
            "--profile",
            profile,
            "--results-arf",
            str(output),
            policy,
        )
    elif tool_id == "trivy":
        path = _local_path(target, allowed_root)
        command = (executable, "fs", "--format", "json", "--output", str(output), path)
    elif tool_id == "grype":
        if not IMAGE.fullmatch(target.strip()) or target.strip().startswith("-"):
            raise ConnectorPlanError("Grype target must be a container image reference.")
        command = (executable, target.strip(), "-o", "json", "--file", str(output))
    elif tool_id == "prowler":
        provider = target.strip().lower()
        if provider not in PROVIDERS:
            raise ConnectorPlanError("Unsupported Prowler provider.")
        output = output_directory / "prowler"
        command = (executable, provider, "-M", "json-ocsf", "-o", str(output))
    elif tool_id == "scoutsuite":
        provider = target.strip().lower()
        if provider not in PROVIDERS:
            raise ConnectorPlanError("Unsupported ScoutSuite provider.")
        output = output_directory / "scoutsuite"
        command = (executable, provider, "--report-dir", str(output))
    elif tool_id == "osv-scanner":
        path = _local_path(target, allowed_root)
        command = (executable, "scan", "--format", "json", "--output", str(output), path)
    elif tool_id == "semgrep-ce":
        path = _local_path(target, allowed_root)
        command = (executable, "scan", "--config", "auto", "--json-output", str(output), path)
    elif tool_id == "bandit":
        path = _local_path(target, allowed_root)
        command = (executable, "-r", path, "-f", "json", "-o", str(output))
    else:
        raise ConnectorPlanError(f"No local collection plan is implemented for {tool.name}.")
    return CollectionPlan(
        tool_id=tool_id,
        command=tuple(command),
        output_path=output,
        timeout_seconds=timeout_seconds,
        stdout_is_report=stdout_report,
    )


def execute_collection_plan(plan: CollectionPlan) -> bytes:
    """Execute a resolved plan with no shell and return its report bytes."""

    try:
        result = subprocess.run(
            list(plan.command),
            shell=False,
            check=False,
            capture_output=True,
            timeout=plan.timeout_seconds,
            cwd=plan.output_path.parent,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConnectorPlanError(f"Collector execution failed: {exc}") from exc
    if result.returncode not in {0, 1}:
        stderr = result.stderr.decode("utf-8", errors="replace")[-2_000:]
        raise ConnectorPlanError(f"Collector exited with code {result.returncode}: {stderr}")
    if plan.stdout_is_report:
        if not result.stdout:
            raise ConnectorPlanError("Collector did not produce a report on stdout.")
        return result.stdout
    if plan.output_path.is_file():
        return plan.output_path.read_bytes()
    if plan.output_path.is_dir():
        candidates = sorted(
            path
            for path in plan.output_path.rglob("*")
            if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".xml", ".csv", ".dat"}
        )
        if candidates:
            return candidates[0].read_bytes()
    alternatives = sorted(
        path for path in plan.output_path.parent.glob(f"{plan.output_path.name}*") if path.is_file()
    )
    if alternatives:
        return alternatives[0].read_bytes()
    raise ConnectorPlanError("Collector completed without a supported report file.")
