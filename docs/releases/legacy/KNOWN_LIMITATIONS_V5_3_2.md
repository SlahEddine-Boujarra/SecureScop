# Known limitations

- PostgreSQL, Streamlit and external integrations were not available in the
  build environment, so migration execution and browser rendering require the
  Windows deployment environment.
- The included automated verification worker currently queues Nuclei. OpenVAS
  verification can still be initiated manually from Scan Center.
- Wazuh Active Response confirms API acceptance and captures sanitized logs;
  endpoint-specific rollback remains an administrator procedure.
- SecureScope does not automatically close a finding after a recipe runs.
- Organizational ISO evidence still requires analyst input and validation.
- AI wording refinement is optional and disabled; deterministic remediation
  remains available without an API key.
