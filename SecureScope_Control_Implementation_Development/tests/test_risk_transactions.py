"""Exercise risk writes through the real repository and transaction manager.

The pool is simulated: these tests verify commit/rollback and SQL parameters,
but do not replace the PostgreSQL integration gate.
"""

from unittest.mock import MagicMock, Mock

import psycopg2
import pytest

from securescope.persistence import db_service
from securescope.persistence import risk_register_repository as repository
from securescope.persistence.grc_repository import GrcRepositoryError


@pytest.fixture
def database(monkeypatch):
    """Provide a mock pool to the real transaction manager.

    Args:
        monkeypatch: Pytest patch fixture.
    Returns:
        Tuple of cursor, connection and pool mocks.
    Raises:
        None.
    """
    cursor = MagicMock()
    cursor.fetchone.side_effect = [{"id": 7}, None]
    connection = MagicMock()
    connection.closed = False
    connection.cursor.return_value.__enter__.return_value = cursor
    pool = Mock()
    pool.getconn.return_value = connection
    monkeypatch.setattr(db_service, "_get_connection_pool", lambda: pool)
    monkeypatch.setattr(repository, "run_pending_migrations", lambda: None)
    return cursor, connection, pool


def risk(reference: int = 1) -> dict:
    """Construct a valid assessment for repository contracts.

    Args:
        reference: Positive risk reference.
    Returns:
        Assessment with inherent and proposed residual scores.
    Raises:
        None.
    """
    return {
        "risk_ref": reference,
        "threat": "Loss of customer records",
        "pre_likelihood": 3,
        "pre_impact": 4,
        "post_likelihood": 2,
        "post_impact": 3,
        "control_references": "A.8.13, A.5.30",
    }


def test_save_attributes_actor_and_commits_links_together(database):
    """Server-side authorization and link callback run before the one commit."""
    cursor, connection, pool = database
    events = []
    connection.commit.side_effect = lambda: events.append("commit")
    authorize = Mock(side_effect=lambda *args: events.append("authorize"))
    after_save = Mock(side_effect=lambda *args: events.append("links"))
    result = repository.save_risk_record(
        "Client A", risk(), actor=" reviewer ", authorize=authorize, after_save=after_save
    )
    assert result == 1
    assert events == ["authorize", "links", "commit"]
    authorize.assert_called_once_with(cursor, 7)
    after_save.assert_called_once_with(cursor, 7, {1: 1})
    audit = cursor.execute.call_args.args
    assert audit[1][:3] == (7, "1", "reviewer")
    assert audit[1][-1].adapted == {"revision": 1}
    connection.rollback.assert_not_called()
    pool.putconn.assert_called_once_with(connection, close=False)


def test_late_stale_write_rolls_back_entire_batch(database):
    """A conflict on the second assessment also rolls back the first write."""
    cursor, connection, _ = database
    cursor.fetchone.side_effect = [{"id": 7}, None, {"revision": 2}]
    after_save = Mock()
    with pytest.raises(GrcRepositoryError, match="Risk 2 changed"):
        repository.save_risk_records(
            "Client A",
            [risk(1), risk(2)],
            actor="reviewer",
            expected_revisions={1: 0, 2: 1},
            after_save=after_save,
        )
    assert any(
        "INSERT INTO securescope_risk_register" in c.args[0] for c in cursor.execute.call_args_list
    )
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()
    after_save.assert_not_called()


def test_failed_links_roll_back_assessment_and_audit(database):
    """A supporting-record failure cannot leave a risk in the wrong register."""
    _, connection, _ = database
    with pytest.raises(ValueError, match="stale links"):
        repository.save_risk_record(
            "Client A",
            risk(),
            actor="reviewer",
            after_save=Mock(side_effect=ValueError("stale links")),
        )
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_authorization_rejection_prevents_writes(database):
    """A denied actor cannot reach either assessment or audit insertion."""
    cursor, connection, _ = database
    with pytest.raises(ValueError, match="not a member"):
        repository.save_risk_record(
            "Client A",
            risk(),
            actor="outsider",
            authorize=Mock(side_effect=ValueError("not a member")),
        )
    assert not any("INSERT" in c.args[0] for c in cursor.execute.call_args_list)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_database_error_rolls_back_and_preserves_cause(database):
    """Database failures expose a useful domain error without partial commits."""
    cursor, connection, _ = database
    cursor.execute.side_effect = psycopg2.OperationalError("connection lost")
    with pytest.raises(GrcRepositoryError, match="No risks were saved") as error:
        repository.save_risk_record("Client A", risk(), actor="reviewer")
    assert isinstance(error.value.__cause__, db_service.DatabaseError)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


@pytest.mark.parametrize("score", [True, 1.5, -1, 6, "invalid"])
def test_invalid_assessment_never_borrows_a_connection(database, score):
    """Invalid score inputs are rejected before touching persistence."""
    _, _, pool = database
    with pytest.raises(ValueError):
        repository.save_risk_record(
            "Client A", dict(risk(), pre_likelihood=score), actor="reviewer"
        )
    pool.getconn.assert_not_called()


def test_duplicate_references_are_rejected_before_transaction(database):
    """Batch imports cannot silently overwrite duplicate assessment references."""
    _, _, pool = database
    with pytest.raises(ValueError, match="Duplicate reference"):
        repository.save_risk_records(
            "Client A", [risk(), risk()], actor="reviewer", expected_revisions={1: 0}
        )
    pool.getconn.assert_not_called()


def test_existing_risk_requires_explicit_matching_revision(database):
    """The insert default cannot overwrite an existing assessment."""
    cursor, connection, _ = database
    cursor.fetchone.side_effect = [{"id": 7}, {"revision": 8}]
    with pytest.raises(GrcRepositoryError, match="Reload"):
        repository.save_risk_record("Client A", risk(), actor="reviewer")
    connection.commit.assert_not_called()


def test_seed_failure_rolls_back_every_example(database, monkeypatch):
    """Starter examples must not leave an incomplete, unrepeatable seed batch."""
    cursor, connection, _ = database
    monkeypatch.setattr(repository, "list_risk_register", lambda client: [])
    monkeypatch.setattr(repository, "starter_risks", lambda: [risk(1), risk(2)])
    cursor.fetchone.side_effect = None

    def rows(statement, parameters):
        """Select client identity or the simulated concurrently inserted risk."""
        if "WHERE name =" in statement:
            cursor.fetchone.return_value = {"id": 7}
        elif "SELECT revision" in statement:
            cursor.fetchone.return_value = {"revision": 1} if parameters[1] == 2 else None

    cursor.execute.side_effect = rows
    with pytest.raises(GrcRepositoryError):
        repository.seed_starter_risks("Client A", actor="reviewer")
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_seed_commits_all_examples_once(database, monkeypatch):
    """A successful seed reports all records and performs one atomic commit."""
    cursor, connection, _ = database
    cursor.fetchone.side_effect = [{"id": 7}, None, None]
    monkeypatch.setattr(repository, "list_risk_register", lambda client: [])
    monkeypatch.setattr(repository, "starter_risks", lambda: [risk(1), risk(2)])
    assert repository.seed_starter_risks("Client A", actor="reviewer") == 2
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()


def test_seed_leaves_an_existing_register_untouched(database, monkeypatch):
    """Existing client assessments never receive automatic example records."""
    _, _, pool = database
    monkeypatch.setattr(repository, "list_risk_register", lambda client: [risk(5)])
    assert repository.seed_starter_risks("Client A", actor="reviewer") == 0
    pool.getconn.assert_not_called()


def test_list_risks_scopes_query_and_derives_scores(database):
    """Read results use the requested client and recompute stored score inputs."""
    cursor, _, _ = database
    cursor.fetchall.return_value = [risk()]
    rows = repository.list_risk_register("Client A")
    assert cursor.execute.call_args.args[1] == (7,)
    assert rows[0]["pre_risk_score"] == 12
    assert rows[0]["post_risk_score"] == 6


def test_missing_client_rejects_read(database):
    """An unknown client cannot fall back to an unscoped risk list."""
    cursor, connection, _ = database
    cursor.fetchone.side_effect = [None]
    with pytest.raises(GrcRepositoryError, match="not found"):
        repository.list_risk_register("Missing")
    connection.rollback.assert_called_once()
