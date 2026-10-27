"""User-facing error boundaries preserve validation without exposing server details."""

from securescope.grc.engagement_models import GrcValidationError
from securescope.grc.engagement_service import GrcWorkspaceService
from securescope.persistence.grc_workspace_repository import GrcWorkspaceRepositoryError


def test_repository_details_are_logged_not_displayed(caplog):
    """Unexpected persistence details remain server-side with a reference identifier."""
    error = GrcWorkspaceRepositoryError("/home/server/site-packages: database failed")
    message = str(GrcWorkspaceService._translate("create milestone", error))
    assert "Reference:" in message
    assert "/home/" not in message
    assert "database failed" in caplog.text


def test_validation_remains_actionable():
    """Safe domain validation is still visible to the person correcting the form."""
    assert (
        str(
            GrcWorkspaceService._translate(
                "create issue", GrcValidationError("Issue title is required.")
            )
        )
        == "Issue title is required."
    )
