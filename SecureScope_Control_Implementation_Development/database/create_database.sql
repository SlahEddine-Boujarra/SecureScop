-- SecureScope PostgreSQL first installation.
-- Replace CHANGE_ME before running as a PostgreSQL administrator.

CREATE USER securescope WITH PASSWORD 'CHANGE_ME';
CREATE DATABASE securescope OWNER securescope;
GRANT ALL PRIVILEGES ON DATABASE securescope TO securescope;

-- Application tables and migrations are created automatically on startup.
