# Control Assurance capability update

## Implementation decisions

| Area | Decision |
| --- | --- |
| Programme Foundation, governed Scope and Risk lifecycle | Keep the existing architecture and persistence. |
| Control Profiles | Extend the existing versioned profile with individually assessable requirements and a full-page workspace. |
| Evidence, Policies, Risks and Remediation | Link canonical records; no parallel control, evidence, policy or task store. |
| Assurance | Derive explainable conclusions from explicit source facts, current scope and approved relationships. |
| Historical records | Preserve prior profiles, assessments, criteria, evidence and audit history. |

## User workflow

Select Client, Engagement and ISMS Scope, then open Control Assurance → Control Profiles. Selecting a control opens its workspace with Overview, Requirements, Evidence, Policies, Risks, Remediation and History.

The header separates applicability, implementation, evidence coverage and assurance. “Why this status?” identifies unresolved mandatory requirements and provides a direct next action. Requirement drawers show the expected result, assessment method, source, coverage, freshness and supporting evidence. Missing evidence is neutral and is never converted into explicit failure.

Consultants can add or edit requirements, associate canonical Interested Party requirement IDs, choose applicable assets, map policies and evidence, create a policy draft, or create an existing-model improvement action. Policy drafts do not satisfy an Approved Policy requirement. Changes to approved policy data are considered in the next workspace/dashboard evaluation; enabled continuous evaluation records changed conclusions through the existing worker.

Organization-specific profile fields remain editable through “Edit Organization Implementation Profile.” Reference names remain fixed. Edits create profile versions with concurrency checks. Legacy criteria can be explicitly prepared as individual manual requirements; previous records are retained and automation defaults off for that conversion.

Evidence must have an explicit association with the selected engagement and scope and an approved control mapping. Linking scope coverage does not silently validate the evidence itself. Imported or manual source evidence requires the existing validation workflow.

## Source capability and automation

The normalized assurance envelope accepts only typed facts supported by the provider:

- SIEM/Wazuh: explicit log coverage, named configuration-test outcomes and safety observations.
- Nmap: explicit completed discovery coverage.
- Nuclei/OpenVAS: explicit completed scan coverage. A scan result alone does not prove remediation or effectiveness.
- Asset Inventory: collection from the canonical inventory and classification values for the configured assets.
- Classification: explicit evaluated and classified asset coverage.
- OpenSCAP/Prowler: explicit named configuration-test outcomes.
- Manual evidence: a consultant conclusion and rationale supported by validated, scoped evidence.

Provider integration requires the normalized `metadata.assurance` facts. Existing raw scan findings are not automatically interpreted as complete coverage. A provider that does not expose the required facts yields Unknown or No Evidence. Native inventory collection is included; this update does not claim that every external connector already supplies every assurance fact or initiates new network scans.

Continuous Auto-Assurance is opt-in and Administrator-controlled. The existing evidence worker rechecks enabled profiles every five minutes, reading candidates in batches. It can refresh eligible inventory evidence daily. Automatic verification requires approved current scope, a profile reviewed against that scope version, confirmed applicability, all mandatory machine requirements passing, current evidence, complete safety observations and no unresolved canonical blockers. The enabling administrator must remain authorized. Policy, Scope, SoA and risk acceptance decisions remain human-controlled.

Evidence expiry, missing facts, contradictory observations and scope changes prevent automatic verification. Evaluation snapshots retain encrypted inputs, source identities, engine version and an input fingerprint. Unchanged results do not generate duplicate evaluation snapshots.

## Dashboard and related modules

Implementation, assessment, evidence and effectiveness metrics have separate denominators. No human assessments displays Not Assessed rather than 0% conformity. The attention list filters by owner and control area; canonical requirement remediation appears in My Control Work. Asset details expose scoped evidence health and affected-control navigation.

Risk and policy links retain canonical IDs and selected context. Related treatments remain read-only in Control Assurance. The existing risk editor and matrix calculations are unchanged. Overdue objectives now require an explicit current-versus-historical choice; historical objectives remain outside current KPI summaries.

## Validation and deployment limits

The package includes Python regression results, DOM interaction results and the source revision under `validation/`. Python 3.11 syntax compatibility, flake8 and whitespace checks passed for changed Python files. No new dependencies or schema migration were introduced.

Four existing PostgreSQL integration tests require `SECURESCOPE_TEST_DATABASE_URL` and were skipped in this environment. Live database transactions, external-provider connectivity and a rendered browser session against your installation have not been verified here. Run the package's existing migration and validation procedures against a backed-up test installation before replacing a running deployment.
