"""Read-only, reference-aware artifact reconciliation; never deletes evidence or orphan files."""

import argparse
import json
import os

from psycopg2.extras import RealDictCursor

from securescope.evidence.storage import EvidenceStorageError, evidence_root, read_artifact
from securescope.persistence.db_service import DatabaseError, connect
from securescope.persistence.evidence_repository import EvidenceRepositoryError, _client_id
from securescope.persistence.foundation_repository import member_role


def inspect_workspace(client_name: str, actor: str) -> dict:
    """Verify referenced artifacts and report unreferenced files without changing either.

    Args:
        client_name: Exact workspace; actor: Host-authenticated administrator identity.
    Returns:
        Counts, failed artifact IDs and unreferenced relative filenames; never source bytes.
    Raises:
        EvidenceRepositoryError: On denied membership; DatabaseError: On failed inventory read.
        OSError: If the workspace directory cannot be enumerated.
    """
    with connect() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        client_id = _client_id(cur, client_name)
        if member_role(cur, client_id, actor) != "Administrator":
            raise EvidenceRepositoryError("Workspace Administrator membership required.")
        cur.execute(
            "SELECT id,storage_reference,sha256 FROM securescope_evidence_artifacts WHERE client_id=%s",
            (client_id,),
        )
        artifacts = [dict(r) for r in cur.fetchall()]
    referenced = {r["storage_reference"] for r in artifacts}
    failures = []
    for artifact in artifacts:
        try:
            read_artifact(
                client_id, artifact["storage_reference"], expected_sha256=artifact["sha256"]
            )
        except EvidenceStorageError:
            failures.append(artifact["id"])
    root = evidence_root()
    directory = root / str(client_id)
    present = {path.relative_to(root).as_posix() for path in directory.rglob("*") if path.is_file()}
    return dict(
        workspace=client_name,
        referenced=len(artifacts),
        verified=len(artifacts) - len(failures),
        failed_artifact_ids=failures,
        unreferenced_files=sorted(present - referenced),
        deleted_files=0,
    )


def main() -> None:
    """Run the host-admin reconciliation command; exit nonzero on failed verification/access."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    try:
        result = inspect_workspace(args.workspace, os.getenv("SECURESCOPE_CURRENT_USER_EMAIL", ""))
    except (EvidenceRepositoryError, DatabaseError, OSError) as exc:
        parser.exit(1, f"Artifact inspection unavailable: {type(exc).__name__}\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["failed_artifact_ids"] else 0)


if __name__ == "__main__":
    main()
