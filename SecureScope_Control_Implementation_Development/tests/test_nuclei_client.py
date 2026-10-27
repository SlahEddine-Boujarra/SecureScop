"""Tests for safe Nuclei CLI configuration and command construction."""

from __future__ import annotations

from pathlib import Path

from securescope.scanners.nuclei.nuclei_client import NucleiClient, NucleiConfig, profile_options


def _config(binary: Path) -> NucleiConfig:
    return NucleiConfig(
        binary=str(binary),
        template_directory="",
        rate_limit=25,
        bulk_size=5,
        concurrency=4,
        request_timeout_seconds=8,
        retries=1,
        max_host_errors=10,
        disable_interactsh=True,
        disable_unsigned_templates=True,
        disable_update_check=True,
        dashboard_upload=False,
        command_timeout_seconds=5,
        excluded_tags="dos,fuzz,fuzzing,bruteforce,creds-stuffing,token-spray",
    )


def test_build_scan_command_is_argument_list(tmp_path: Path) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"")
    target_file = tmp_path / "targets.txt"
    target_file.write_text("https://192.0.2.10\n", encoding="utf-8")
    client = NucleiClient(_config(binary))

    command = client.build_scan_command(
        target_file=target_file,
        output_file=tmp_path / "findings.jsonl",
        profile_name="cve",
        scan_name="scan-1",
        project_directory=tmp_path / "project",
    )

    assert isinstance(command, list)
    assert command[0] == str(binary.resolve())
    assert "-jsonl-export" in command
    assert "-disable-unsigned-templates" in command
    assert "-no-interactsh" in command
    assert command[command.index("-rate-limit") + 1] == "25"
    assert command[-2:] == ["-tags", "cve"]
    assert not any("|" in item or ";" in item for item in command)


def test_profiles_are_stable() -> None:
    keys = [item["key"] for item in profile_options()]
    assert keys == ["standard", "cve", "exposure", "network", "automatic-web"]
