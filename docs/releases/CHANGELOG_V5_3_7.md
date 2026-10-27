# SecureScope v5.3.7

- Preserves the v5.3.6 Streamlit navigation and scanner behavior.
- Adds all 30 assessable requirements under ISO/IEC 27001 clauses 4–10 and all
  93 Annex A controls to the workspace assessment catalog.
- Adds the ISO Evidence Hub inside **Gap Assessment → Assess control**.
- Adds 31 open-source evidence sources with enforced execution modes.
- Replaces WPScan with Droopescan because commercial WPScan integration is not
  open source under the product's official terms.
- Adds bounded JSON/JSONL/SARIF/CycloneDX/CSV/XML/XCCDF/ARF/DAT/text normalization.
- Rejects XML DTD/entity declarations and redacts common secrets from normalized data.
- Preserves raw artifacts outside PostgreSQL with SHA-256 and optional Fernet encryption.
- Adds users, workspace memberships and Administrator/Contributor/Consultant/Auditor roles.
- Adds consultant-only validation and control mapping approval.
- Adds manual evidence requests, freshness tracking and hash-chained audit events.
- Adds PDF, Excel and complete auditor ZIP deliverables.
- Adds a FastAPI control plane and independent persistent defensive-collector worker.
- Keeps offensive and credential-testing sources import-only.
- Recognizes the exact published migration-003 checksums from the earlier ISO
  Evidence Hub and ISO Evidence Platform packages without weakening checksum
  validation for any unknown migration content.
- Applies the complete schema additively through
  `004_v5_3_7_iso_evidence_platform.sql`, preserving existing workspaces,
  assets, scans, findings, evidence, reports and audit history.
