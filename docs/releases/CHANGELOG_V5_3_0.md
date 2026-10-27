# SecureScope v5.3.0 — OpenVAS and Nuclei

## Removed

- All local REST-provider modules, workers, probes, scripts, tests,
  configuration and documentation from the superseded second engine.

## Added

- ProjectDiscovery Nuclei open-source CLI integration.
- Safe profile-based command builder with rate and concurrency limits.
- Durable PostgreSQL Nuclei batches, jobs, retries, events and worker state.
- Detached per-job runner with atomic result markers and restart recovery.
- Nuclei JSONL parsing, common findings, PDF evidence and client history.
- Nuclei Scan Center and scanner-fabric dashboard.
- Windows install, diagnostics, template-update and worker scripts.
- Implementation, quick-start and acceptance documentation.

## Preserved

- OpenVAS/Greenbone, Nmap, client workspaces, Wazuh, endpoint clock evidence,
  ISO Annex A.8 assessment, vulnerability intelligence, reports and CISO
  Assistant integration.
