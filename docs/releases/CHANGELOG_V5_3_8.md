# SecureScope v5.3.8

- Preserves the corrected v5.3.7 ISO Evidence Platform and scanner behavior.
- Adds immutable migration `005_grc_engagement_context_scope.sql`.
- Leaves migration bytes `001`–`004` unchanged and recognizes the published
  migration-003 aliases through the explicit compatibility bridge.
- Backfills one default engagement and draft scope per existing client without
  rewriting existing records.
- Adds consulting organizations, engagement cycles, milestones, versioned ISMS
  scopes, organizational units, context issues, climate determinations,
  interested parties, requirements, engagement memberships and RACI roles.
- Adds Administrator/Consultant scope approval with immutable approved versions.
- Adds hash-chained, append-only GRC audit events and immutable approval records.
- Adds the default **Gap Assessment → GRC Workspace** interface with persistent
  client → engagement → scope selectors.
- Makes Client Workspace selection open the GRC workspace overview.
- Removes the obsolete A.8.1 endpoint-coverage tab from Gap Assessment while
  preserving the Wazuh/A.8.17 evidence backend and aggregate dashboard metrics.
- Adds authenticated FastAPI endpoints for every first-milestone create and
  approval workflow.
- Adds domain, migration, tenant-isolation, navigation and API contracts.
- Keeps Nmap, OpenVAS, Nuclei, Wazuh, evidence workers, scan identity, reports,
  SoA, remediation and CISO Assistant integration unchanged.
