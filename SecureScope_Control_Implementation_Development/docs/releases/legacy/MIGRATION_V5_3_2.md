# PostgreSQL migration for v5.3.2

Back up PostgreSQL and `.env` before upgrading.

```powershell
.\.venv\Scripts\python.exe -m securescope.cli.run_migrations
```

`start_securescope.ps1` runs the same command automatically before starting
scanner workers.

The migration runner:

- creates `securescope_schema_migrations` when missing;
- uses a PostgreSQL advisory transaction lock;
- validates immutable SHA-256 checksums;
- applies `001_v6_exposure_grc.sql` and
  `002_v6_1_quick_remediation.sql` in order;
- rolls back the active transaction when PostgreSQL rejects a migration.

The migrations contain no `DROP TABLE`, `TRUNCATE` or data-deletion statement.
They add canonical findings, remediation, Gap Assessment, SoA, risk-treatment,
audit and approved-execution tables. All tenant data tables reference
`securescope_clients` through `client_id`.
