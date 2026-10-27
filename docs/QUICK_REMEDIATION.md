# Quick Remediation

Quick Remediation creates deterministic plans from canonical OpenVAS and
Nuclei findings. It works without an OpenAI API key.

## Candidate preparation

- informational observations are excluded by default;
- findings are grouped only when normalized vulnerability identity and safe
  remediation action match;
- every individual finding and asset link is retained;
- scanner solution/remediation, CVE, product, version, KEV, EPSS, severity,
  asset criticality, exposure, age and SLA contribute to the proposal;
- a Low finding does not default to Critical unless a documented factor such
  as confirmed CISA KEV exposure justifies escalation.

The compact plan form proposes a title, action, priority, owner, due date,
validation method, first task and verification requirement. Advanced ownership
and planning fields remain optional.

## Lifecycle and closure

Plans and work items are persisted with owners, due dates, status history and
evidence. A change reaches Pending verification after execution. SecureScope
queues a fresh targeted Nuclei scan after the configured delay, but it does not
mark a finding Verified. Closure still requires fresh evidence or an authorized
analyst decision according to the finding transition rules.

## Execution boundary

Guidance and plan preparation do not execute commands. Approved execution is a
separate, optional path limited to signed registry recipes, an exact workspace,
one confirmed asset, an active synchronized Wazuh agent and an identified
approver. Scanner, NVD, AI and free-text commands are never executable inputs.
