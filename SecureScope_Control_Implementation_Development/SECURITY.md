# Security policy

## Supported version

Security fixes are applied to the latest maintained SecureScope version. The
v5.4.9.dev0 build is intended for controlled enterprise evaluation.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Report the affected
version, impact, reproduction steps, and suggested mitigation privately to the
repository owner or the organization's security contact.

## Repository hygiene

- Keep the GitHub repository private unless publication is formally approved.
- Never commit `.env`, passwords, API tokens, SSH private keys, certificates,
  exported evidence, scanner output, or customer asset inventories.
- Rotate any credential immediately if it appears in Git history.
- Protect the default branch, require pull-request review, and enable secret
  scanning and dependency alerts.
- Run scans only with written authorization and an approved target scope.

## Remediation safety

Wazuh Active Response remediation is disabled by default. Enabling it requires
both configuration switches, an administrator-maintained command allow-list,
an integrity-checked recipe, and a fresh verification scan. Scanner or AI text
is never executed as an endpoint command.

