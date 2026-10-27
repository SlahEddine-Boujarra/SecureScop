# ISO Programme Setup foundation

SecureScope v5.3.8 introduces the first engagement-aware GRC milestone without
replacing the existing scanner, evidence, assessment, remediation or reporting
modules. Version 5.3.8.4 adds a discovery-first working experience while keeping
the formal registers and approval model intact.

## User flow

1. Open **Client workspace** in the sidebar.
2. Select a client or choose **Overview** for the current client.
3. SecureScope opens the **ISO 27001 Assurance Command Center**.
4. Select an engagement or certification cycle and ISMS scope in the persistent
   context selector.
5. Open **Programme Setup**.
6. Open **Discovery** to record a short organization profile once and review
   proposed Context, Interested Parties and Scope content.
7. Use Engagement, Context, Interested Parties, ISMS Scope, and Roles & RACI as
   advanced/formal registers. Only the selected section is queried and rendered.

Discovery converts confirmed profile information into provenance-aware organization
facts. Deterministic recommendations are never inserted automatically: the
consultant reviews and accepts them. Scope Composer creates a draft only; approval
remains a separate human confirmation decision.

The persistent context is:

```text
Client workspace
└── Engagement / certification cycle
    └── ISMS scope
```

All records and API mutations are verified against that context in PostgreSQL.
Changing a selector cannot expose a record belonging to another client or
engagement.

## Included records

- consulting organization and client relationship;
- engagement and certification-cycle metadata;
- real engagement members backed by workspace users;
- milestones;
- scope definitions and immutable versions;
- sites, departments and organizational units;
- internal and external context issues;
- climate-change relevance determinations;
- interested parties and their requirements;
- user-backed ISMS roles and RACI assignments;
- immutable scope approvals;
- hash-chained GRC audit events.

## Scope approval

Creating a scope always creates a draft version. An active workspace member with
the Administrator or Consultant role must approve it with a rationale. Once
approved, the version cannot be edited. A later change creates a new version and
the scope definition points to the most recently approved version.

Deleting an entire client workspace remains possible through the existing
workspace cascade. The immutability triggers distinguish that administrative
deletion from an attempt to alter an approved record inside an active workspace.

## Programme foundation progress

The Command Center calculates eight engagement-scoped foundation items:

- engagement activated;
- organizational context recorded;
- climate relevance determined;
- interested parties identified;
- applicable requirements recorded;
- ISMS scope approved;
- ISMS responsibilities assigned;
- programme milestones scheduled.

The result is labelled **programme foundation**, not compliance, certification,
or audit readiness. Risk, control, evidence, and audit dimensions are shown as
unmeasured until those records can be filtered by engagement and scope.

## Organization knowledge

Migration `006_organization_knowledge.sql` adds a quick organization profile and
reusable organization facts. Facts carry source type, source reference, confidence
and review status so later document, import, integration and technical-discovery
sources can feed the same knowledge layer without writing directly to approved
ISO records.

## Existing workspace upgrade

Migration `005_grc_engagement_context_scope.sql` is additive. For each existing
client it creates:

- a relationship with the default consulting organization;
- `Existing ISO 27001 Programme` as an active default engagement;
- `Existing ISMS Scope` with draft version 1.

Migrations `001`–`004` are not edited. Existing assets, scan identities, jobs,
reports, findings, evidence, SoA versions and remediation history are not moved
or rewritten.

## Membership prerequisite

Engagement roles, RACI assignments and scope approvals require a real active
workspace membership. Create one with the existing command:

```powershell
$env:PYTHONPATH = ".\src"
.\.venv\Scripts\python.exe -m securescope.cli.manage_membership `
  --workspace "Default Client" `
  --email "consultant@example.com" `
  --name "ISO Consultant" `
  --role "Consultant" `
  --granted-by "Local administrator"
```

Set `SECURESCOPE_CURRENT_USER_EMAIL` to the same email. The fallback
`local-consultant` principal may prepare drafts but cannot approve a scope or be
assigned as a real user.

## Human-decision boundary

This release does not let scanners approve scope, applicability, risks,
assessments or certification readiness. OpenVAS, Nuclei, Nmap and Wazuh remain
supporting evidence sources only.

Future intelligence and technical-discovery sources should create facts or
reviewable proposals first. They must not bypass the existing human decisions for
scope approval, control assessment, SoA, risk acceptance or certification readiness.
