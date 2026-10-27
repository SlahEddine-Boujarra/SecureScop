"""Tests for durable Nuclei job naming."""

from securescope.persistence.nuclei_persistence import deterministic_scan_name


def test_nuclei_scan_name_contains_attempt_identity() -> None:
    name = deterministic_scan_name(
        client_id=7,
        batch_uuid="batch-uuid",
        job_uuid="job-uuid",
        asset_ip="192.0.2.10",
        attempt_number=3,
    )
    assert name.startswith("securescope-nuclei-c7-")
    assert "192.0.2.10" in name
    assert name.endswith("-a3")
