"""Export live PostgreSQL column/constraint metadata without migrations or client data."""

import argparse
import json
import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from securescope.paths import ENV_FILE

TABLES = [
    "securescope_soa_versions",
    "securescope_soa_items",
    "securescope_risk_register",
    "securescope_working_registers",
    "securescope_opportunity_register",
]


def inspect_schema(connection: object) -> dict:
    """Read actual schema metadata in a read-only transaction.

    Args:
        connection: Existing psycopg2 connection; no application initializer runs.
    Returns:
        JSON-compatible column, constraint, and migration metadata.
    Raises:
        psycopg2.Error: If metadata queries or the read-only transaction fail.
    """
    connection.set_session(readonly=True)
    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute(
            "SELECT table_name, column_name, data_type, udt_name, is_nullable, column_default "
            "FROM information_schema.columns WHERE table_schema = %s "
            "AND table_name = ANY(%s) ORDER BY table_name, ordinal_position",
            ("public", TABLES),
        )
        columns = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT c.relname AS table_name, con.conname AS constraint_name, "
            "pg_get_constraintdef(con.oid) AS definition FROM pg_constraint con "
            "JOIN pg_class c ON c.oid = con.conrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relname = ANY(%s) ORDER BY c.relname, con.conname",
            ("public", TABLES),
        )
        constraints = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT to_regclass(%s) AS relation", ("public.securescope_schema_migrations",)
        )
        migrations = []
        if cursor.fetchone()["relation"]:
            cursor.execute(
                "SELECT version, name, checksum FROM securescope_schema_migrations ORDER BY version"
            )
            migrations = [dict(row) for row in cursor.fetchall()]
    return {
        "columns": columns,
        "constraints": constraints,
        "migrations": migrations,
        "missing_tables": sorted(set(TABLES) - {row["table_name"] for row in columns}),
    }


def main() -> int:
    """Write the live metadata needed to finalize toolkit import mappings.

    Returns:
        Zero on success or two if configuration/connection fails.
    Raises:
        OSError: If the requested output cannot be written.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("toolkit_schema.json"))
    args = parser.parse_args()
    load_dotenv(ENV_FILE, override=False)
    url = os.getenv("SECURESCOPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        print("No database connection is configured. No queries or migrations ran.")
        return 2
    try:
        with psycopg2.connect(url, connect_timeout=5) as connection:
            metadata = inspect_schema(connection)
    except psycopg2.Error:
        print("Could not read database schema metadata. Check the local connection configuration.")
        return 2
    args.output.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    print(
        f"Schema metadata saved to {args.output.name}; no client records or credentials included."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
