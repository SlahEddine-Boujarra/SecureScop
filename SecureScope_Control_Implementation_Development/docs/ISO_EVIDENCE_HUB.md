# ISO Evidence Hub

## Purpose and boundary

SecureScope v5.3.8 supports assessment of ISO/IEC 27001:2022 clauses 4–10 and the
Statement of Applicability for all 93 Annex A controls. The catalog contains
short labels and SecureScope assessment metadata; it does not reproduce the
copyrighted standard. Use a licensed copy of ISO/IEC 27001:2022 and Amendment
1:2024 when interpreting requirements.

No scanner, API, collector, AI model, or imported report can mark a control
Implemented, approve a Statement of Applicability entry, accept risk, or close a
gap. Automated evidence is advisory and must be reviewed by a Consultant.

## Evidence-to-control process

1. Define the client workspace and assessment scope.
2. Define applicability and verification criteria for the clause/control.
3. Collect evidence through an existing worker, an allowlisted defensive
   collector, an authenticated API, report import, or manual submission.
4. Retain the original artifact outside PostgreSQL with a SHA-256 checksum.
5. Normalize bounded observations and redact common secret fields from the
   normalized payload.
6. Suggest relevant controls from the conservative source catalog.
7. Have a Consultant validate/reject the evidence and approve/change mappings.
8. Assess design, implementation, scope coverage, operating effectiveness,
   evidence assurance, and validation separately.
9. Record the conclusion, gaps, improvement actions, SoA and risk treatment.
10. Produce the printable control matrix or checksum-verified auditor package.

## Manual, hybrid and technical evidence

All 30 assessable requirements under clauses 4–10 are manual. Annex A controls
without a defensible technical source are manual. A control with a tool mapping
is Hybrid—not automatic—because policy/design, approved scope and effectiveness
still require human examination, interview, observation, sampling or testing.

Typical manual areas include leadership, policies, risk decisions, competence,
awareness, suppliers, legal obligations, most physical controls, internal audit,
management review and corrective action. A backup report may support A.8.13,
for example, but the Consultant must still verify policy, coverage, retention,
restoration testing, ownership, failures and corrective action.

## Workspace roles

| Role | Capabilities |
|---|---|
| Administrator | Configure, collect, import, submit, review, export and read |
| Client contributor | Import, submit and read |
| Consultant | Collect, import, submit, review, export and read |
| Auditor | Read and export only |

The Streamlit UI resolves `SECURESCOPE_CURRENT_USER_EMAIL` against a real
`client_id` membership. When no active membership is found, Evidence Hub
mutations are disabled. Create the first membership locally:

```powershell
$env:PYTHONPATH = ".\src"
.\.venv\Scripts\python.exe -m securescope.cli.manage_membership `
  --workspace "Default Client" `
  --email "consultant@example.com" `
  --name "ISO Consultant" `
  --role "Consultant" `
  --granted-by "Local administrator"
```

## Storage and encryption

Set `SECURESCOPE_EVIDENCE_STORAGE_ROOT` to a protected, backed-up durable
volume. PostgreSQL stores references, checksums, normalized evidence, review
state and audit history—not large raw reports. File permissions are restricted
where the operating system supports them.

Optional at-rest encryption uses a Fernet key:

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the result in a secret manager and expose it as
`SECURESCOPE_EVIDENCE_ENCRYPTION_KEY`. Do not commit it. Losing the key makes
encrypted evidence unrecoverable.

## FastAPI and workers

The API binds to `127.0.0.1:8765` by default. It requires
`X-SecureScope-Workspace` and `X-SecureScope-User` headers for every business
route, then resolves the membership in PostgreSQL. Put TLS and a trusted
identity-aware reverse proxy in front of it before any remote deployment.

```powershell
.\scripts\windows\start_api.ps1
.\scripts\windows\start_evidence_worker.ps1
```

The API enqueues defensive collection. Only the worker executes allowlisted
commands, always with `shell=False`. Set `SECURESCOPE_COLLECTOR_ALLOWED_ROOT` to
the only directory that local source/config scanners may inspect. Import-only
tools cannot enter the execution queue.

## Auditor deliverables

The Evidence Hub produces a landscape printable PDF matrix and a ZIP containing:

- PDF control matrix for clauses 4–10 and Annex A;
- filterable Excel matrix and evidence register;
- validated evidence metadata;
- validated original reports when selected;
- hash-chained evidence audit history; and
- `SHA256SUMS.txt` for package integrity verification.

Coverage and evidence counts are not certification conclusions.
