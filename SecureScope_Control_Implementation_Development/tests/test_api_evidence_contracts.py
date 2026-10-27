"""HTTP evidence contracts with injected membership; these are not authentication tests."""

from importlib import import_module
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

api = import_module("securescope.api.app")

IMPORT_BODY = {
    "tool_id": "nmap",
    "filename": "scan.xml",
    "content_base64": "dGVzdA==",
    "title": "Scan",
    "summary": "Test evidence",
    "scope_description": "Test scope",
    "owner": "Owner",
}


@pytest.fixture
def api_client(monkeypatch):
    """Inject an administrator context without invoking a database or real login.

    Args:
        monkeypatch: Pytest mutation rollback fixture.
    Yields:
        TestClient: HTTP client for the control plane.
    Raises:
        RuntimeError: If the application cannot start.
    """
    context = api.WorkspaceContext(
        workspace="Client Alpha", email="operator@example.invalid", role="Administrator"
    )
    monkeypatch.setitem(api.app.dependency_overrides, api.workspace_context, lambda: context)
    with TestClient(api.app) as client:
        yield client


@pytest.mark.parametrize("encoded", ["not-base64!", "a", "é"])
def test_malformed_import_cannot_reach_storage(api_client, monkeypatch, encoded):
    """Reject malformed import bytes before a service can store evidence.

    Args:
        api_client: Isolated HTTP client.
        monkeypatch: Pytest mutation rollback fixture.
        encoded: Invalid base64 input.
    Returns:
        None.
    Raises:
        AssertionError: If invalid evidence reaches the service.
    """
    ingest = Mock()
    monkeypatch.setattr(api, "ingest_report", ingest)
    response = api_client.post(
        "/v1/evidence/import", json={**IMPORT_BODY, "content_base64": encoded}
    )
    assert response.status_code == 400
    ingest.assert_not_called()


def test_import_preserves_context_and_decoded_bytes(api_client, monkeypatch):
    """Keep import routing bound to the injected workspace and preserve report bytes.

    Args:
        api_client: Isolated HTTP client.
        monkeypatch: Pytest mutation rollback fixture.
    Returns:
        None.
    Raises:
        AssertionError: If the API changes bytes or routes to another workspace.
    """
    ingest = Mock(return_value=17)
    monkeypatch.setattr(api, "ingest_report", ingest)
    response = api_client.post("/v1/evidence/import", json=IMPORT_BODY)
    assert response.status_code == 201
    assert response.json() == {"evidence_id": 17}
    assert ingest.call_args.args == ("Client Alpha",)
    assert ingest.call_args.kwargs["content"] == b"test"
    assert ingest.call_args.kwargs["submitted_by"] == "operator@example.invalid"


@pytest.mark.parametrize("timeout", [0, 29, 14401])
def test_invalid_collector_timeout_never_enqueues(api_client, monkeypatch, timeout):
    """Reject collector bounds before creating a persistent job.

    Args:
        api_client: Isolated HTTP client.
        monkeypatch: Pytest mutation rollback fixture.
        timeout: Out-of-range job timeout.
    Returns:
        None.
    Raises:
        AssertionError: If an invalid job reaches the queue.
    """
    enqueue = Mock()
    monkeypatch.setattr(api, "enqueue_evidence_job", enqueue)
    response = api_client.post(
        "/v1/collection-jobs",
        json={"tool_id": "nmap", "target": "example.invalid", "timeout_seconds": timeout},
    )
    assert response.status_code == 422
    enqueue.assert_not_called()


def test_auditor_cannot_import_evidence(api_client, monkeypatch):
    """Enforce the existing read-only auditor capability at the HTTP boundary.

    Args:
        api_client: Isolated HTTP client.
        monkeypatch: Pytest mutation rollback fixture.
    Returns:
        None.
    Raises:
        AssertionError: If an auditor invokes a mutation service.
    """
    context = api.WorkspaceContext(
        workspace="Client Alpha", email="auditor@example.invalid", role="Auditor"
    )
    monkeypatch.setitem(api.app.dependency_overrides, api.workspace_context, lambda: context)
    ingest = Mock()
    monkeypatch.setattr(api, "ingest_report", ingest)
    response = api_client.post("/v1/evidence/import", json=IMPORT_BODY)
    assert response.status_code == 403
    ingest.assert_not_called()


def test_import_service_rejection_is_not_reported_as_success(api_client, monkeypatch):
    """Return a failure when evidence validation rejects an otherwise valid request.

    Args:
        api_client: Isolated HTTP client.
        monkeypatch: Pytest mutation rollback fixture.
    Returns:
        None.
    Raises:
        AssertionError: If rejected evidence is represented as created.
    """
    monkeypatch.setattr(
        api, "ingest_report", Mock(side_effect=api.EvidenceServiceError("Unsupported report"))
    )
    response = api_client.post("/v1/evidence/import", json=IMPORT_BODY)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported report"
