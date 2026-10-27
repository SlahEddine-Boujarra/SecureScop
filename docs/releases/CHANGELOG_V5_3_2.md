# SecureScope v5.3.2

This release starts from the supplied v5.3.1 archive and adds only the
Remediation and Gap Assessment capabilities.

## Added

- persistent canonical findings and scanner observations;
- deterministic Quick Remediation candidates and multi-asset grouping;
- plans, tasks, milestones, risk acceptance and audit history;
- integrity-checked remediation recipe registry;
- optional, default-off Wazuh Active Response adapter and worker;
- verification scan queueing without automatic finding closure;
- versioned ISO/IEC 27001:2022 control profiles and targets;
- quantitative, checklist, process, SLA, effectiveness and composite models;
- six independent assurance dimensions;
- control gaps, improvement actions, Statement of Applicability and Risk
  Treatment Plans;
- two additive PostgreSQL migrations and a checksum-protected migration ledger.

## Preserved

OpenVAS, Nuclei, Nmap, scanner queues, workers, retries, reports, CISO
Assistant, Wazuh monitoring, NTP evidence, client workspaces and the v5.3.1 UI
remain in place. No scanner execution module was rewritten.
