"""PostgreSQL integration checks; use an isolated schema in the explicit test DB."""

import os
import uuid
from contextlib import contextmanager
from datetime import date
from pathlib import Path

import psycopg2
import pytest

from securescope.grc.isms_project_plan import ProjectTaskUpdate
from securescope.persistence import isms_project_repository as repository
from securescope.persistence.db_service import DatabaseError

TEST_DATABASE_URL = os.getenv("SECURESCOPE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL, reason="Explicit SECURESCOPE_TEST_DATABASE_URL is not configured"
)


@pytest.fixture
def project_database(monkeypatch):
    """Create isolated tables, bind repository transactions, and clean up after testing.

    Args:
        monkeypatch: Pytest replacement manager.

    Yields:
        Context manager opening a transaction in the temporary schema.

    Raises:
        psycopg2.Error: If the explicitly configured integration database fails.
    """

    schema = "test_isms_" + uuid.uuid4().hex
    admin = psycopg2.connect(TEST_DATABASE_URL)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(f"CREATE SCHEMA {schema};")

    @contextmanager
    def connection():
        """Provide commit/rollback semantics equivalent to the production pool."""

        conn = psycopg2.connect(TEST_DATABASE_URL, options=f"-c search_path={schema}")
        try:
            with conn:
                yield conn
        except psycopg2.Error as exc:
            raise DatabaseError(str(exc)) from exc
        finally:
            conn.close()

    try:
        with connection() as conn, conn.cursor() as cursor:
            cursor.execute(
                "CREATE TABLE securescope_clients (id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE);"
            )
            cursor.execute("INSERT INTO securescope_clients(name) VALUES ('Alpha'), ('Beta');")
            migration = Path(__file__).parents[1] / "database/migrations/007_isms_project_plan.sql"
            cursor.execute(migration.read_text())
            cursor.execute(migration.read_text())
        monkeypatch.setattr(repository, "connect", connection)
        monkeypatch.setattr(repository, "run_pending_migrations", lambda: [])
        yield connection
    finally:
        with admin.cursor() as cursor:
            cursor.execute(f"DROP SCHEMA {schema} CASCADE;")
        admin.close()


def test_saved_tasks_are_workspace_isolated_and_audited(project_database):
    """Saving the same task reference for two clients must retain separate values."""

    update = ProjectTaskUpdate("Security Manager", date(2026, 9, 7), 10, 3)
    assert (
        repository.save_project_task("Alpha", 1, update, actor="Reviewer", expected_revision=0) == 1
    )
    assert repository.load_project_plan("Beta")["tasks"] == []
    repository.save_project_task("Beta", 1, update, actor="Second reviewer", expected_revision=0)
    saved = repository.load_project_plan("Alpha")
    assert saved["tasks"][0]["completed_days"] == 3
    assert saved["events"][0]["actor"] == "Reviewer"
    assert saved["events"][0]["revision"] == 1


def test_conflicting_revision_and_unknown_workspace_do_not_write(project_database):
    """Reject stale updates and unknown clients without creating an audit event."""

    update = ProjectTaskUpdate("Manager", date(2026, 9, 7), 5, 1)
    repository.save_project_task("Alpha", 2, update, actor="First", expected_revision=0)
    with pytest.raises(repository.ProjectPlanError, match="changed"):
        repository.save_project_task("Alpha", 2, update, actor="Stale", expected_revision=0)
    with pytest.raises(repository.ProjectPlanError, match="no longer exists"):
        repository.save_project_task("Unknown", 2, update, actor="User", expected_revision=0)
    assert len(repository.load_project_plan("Alpha")["events"]) == 1


def test_audit_failure_rolls_back_the_task_update(project_database):
    """A failed audit append cannot leave an unaudited task mutation committed."""

    with project_database() as conn, conn.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE securescope_isms_project_events ADD CHECK (actor <> 'Rejected');"
        )
    update = ProjectTaskUpdate("Manager", date(2026, 9, 7), 5, 1)
    with pytest.raises(repository.ProjectPlanError, match="No tasks were saved"):
        repository.save_project_task("Alpha", 1, update, actor="Rejected", expected_revision=0)
    assert repository.load_project_plan("Alpha") == {"tasks": [], "events": []}


def test_workspace_delete_cascades_only_its_plan_and_history(project_database):
    """Keep workspace removal compatible with the new plan and audit tables."""

    update = ProjectTaskUpdate("Manager", None, 0, 0)
    for client in ("Alpha", "Beta"):
        repository.save_project_task(client, 1, update, actor="Reviewer", expected_revision=0)
    with project_database() as conn, conn.cursor() as cursor:
        cursor.execute("DELETE FROM securescope_clients WHERE name = 'Alpha';")
        cursor.execute("SELECT COUNT(*) FROM securescope_isms_project_events;")
        assert cursor.fetchone()[0] == 1
    assert len(repository.load_project_plan("Beta")["tasks"]) == 1
