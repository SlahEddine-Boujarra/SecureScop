# SecureScope v5.3.8.5 — Migration Compatibility Hotfix

## Purpose

Repair startup failures seen while applying migration 006 on previously
published Windows/PostgreSQL workspaces without changing scanner, evidence,
control-assurance, or Programme Foundation behavior.

## Changes

- Preserved the originally published `006_organization_knowledge.sql` byte-for-byte.
- Added `006_organization_knowledge_compat.sql` as the preferred compatibility
  alias for migration version 6.
- The compatibility migration keeps client ownership and repository-level
  engagement/scope validation while using simple PostgreSQL foreign keys for the
  optional engagement and scope references. This avoids dependence on composite
  constraints that may differ across previously published schemas.
- Added migration checksum compatibility so databases that already applied the
  original migration 006 remain valid and are not re-migrated.
- Simplified migration execution to pass SQL text directly to psycopg2 rather
  than wrapping complete migration scripts in `psycopg2.sql.SQL`.
- Added regression coverage for migration-006 alias selection and preservation
  of the original published migration checksum.

## Data safety

The failed migration is executed inside a transaction. PostgreSQL rolls the
failed DDL back, so this hotfix does not require manually deleting migration-006
objects before restarting.
