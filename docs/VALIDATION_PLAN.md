# Validation plan

- Compile all Python modules.
- Run unit and regression tests.
- Verify no removed provider modules or references remain.
- Run Nuclei read-only diagnostics.
- Validate one authorized asset campaign before batch tests.
- Validate worker restart recovery.
- Validate JSONL parsing with representative HTTP, network and CVE findings.
- Validate PDF, client history, CISO synchronization and ISO evidence.
- Validate OpenVAS separately through its existing doctor and GMP diagnostics.
