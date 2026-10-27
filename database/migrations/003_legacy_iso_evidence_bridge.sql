-- SecureScope migration-version compatibility bridge.
--
-- Migration version 003 was previously released with multiple ISO evidence
-- schemas. The migration runner recognizes only their exact published
-- checksums. Migration 004 additively reconciles every supported database to
-- the v5.3.7 evidence-platform schema.

SELECT 1;
