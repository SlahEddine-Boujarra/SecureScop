# SecureScope 5.4.4 — Programme Foundation

This is an additive update to the 5.4.3 Menu Fix build. It retains that build's native sidebar page links and adds controlled first-Administrator setup, minimal Policy/Objectives versions, and review snapshots over the existing risk register.

## Install and first Administrator

1. Back up your PostgreSQL database and stop the previous application.
2. Extract the new full build into a separate folder. Transfer your existing local configuration and encrypted credential storage using the existing installation instructions. Do not overwrite your existing deployment until the new installation connects successfully.
3. Run `start_securescope.ps1`. The launcher creates a random, process-local setup code and displays it in its PowerShell window. Keep that window and code private.
4. Open your client workspace, then **Programme Foundation → Administrator setup / local sign-in**. Enter your email, display name and the launcher code; confirm and select **Verify local access**.
5. With no existing Administrator, this creates the first active Administrator membership and a persistent bootstrap marker in one transaction. If an Administrator already exists, the code can sign in only as an existing active Administrator. It cannot create a replacement Administrator.
6. Open **Formal ISMS records → Roles & RACI** to add people or change workspace roles. Only an active Administrator can do this. The last active Administrator cannot be demoted through this interface.

The launcher code changes on restart and is never written into the database or a configuration file. The browser password input clears on submission. Subsequent local sign-ins require the current code. This is a host-operator access mechanism, not a complete multi-user password/SSO system. Membership grants do not automatically create a remote login provider. Existing trusted identity configuration remains in place; the FastAPI authentication model has not been changed.

Migration 010 adds `securescope_foundation_versions` and `securescope_workspace_bootstraps`. The existing migration runner discovers it automatically. No existing client records are replaced or seeded. Migration execution against your live PostgreSQL instance remains unverified in this environment.

## Where things live

| Area | Contents |
| --- | --- |
| Overview | Independent Context, Interested Parties, Scope, Risk, Policy and Objectives states; explicit unavailable states for failed reads |
| Engagement management | Engagement tracking and Discovery |
| Formal ISMS records | Context, Interested Parties, Scope, Risk assessment, Policy, Objectives, Roles & RACI |

The original risk entry path remains **Control Assurance → Risk Treatment Plan → Risk register → Asset-based risk register**. A new action there opens the Foundation risk review. Foundation also exposes the same canonical editor under **Risk assessment → Add or edit canonical risks**.

## Data and lifecycle

| Record | Storage / behaviour |
| --- | --- |
| Asset risks | Existing `securescope_risk_register`; no duplicate editable register or scoring system |
| Risk review | Scope/engagement-associated snapshots in `securescope_foundation_versions`; snapshots cover the entire client risk register, explicitly stated in the UI |
| Policy | Versioned title, policy text, owner and evidence reference |
| Objectives | Versioned title, measure, baseline, target, action plan, resources, due date, owner and evidence reference |
| Context / Parties / Scope | Existing repositories and domain editors retained; no silent conversion into new records |

Discover the purpose and source, prepare a suggestion or draft, review and submit it, then approve as Administrator. Suggestions are starter text, never approved facts. Policy/Objectives row edits stay in browser state until **Save draft version** is selected. Each successful transition appends a new stored version, with owner, actor, rationale and approval identity. Historical versions remain viewable. This is application-level append-only history; database owners retain their normal database privileges.

Approval checks current database membership and reviewed version. Changed canonical risk revisions, changed register ownership, edited Policy/Objectives content or a concurrent version update block approval. Save and review a fresh draft. Risk review introduces no claim that a suggested treatment is verified residual risk.

Your `toolkit_schema.json` confirms migrations 001–009 and the canonical risk columns, including `revision`. It does not supply membership/Context/Parties/Scope records or row counts, so it cannot prove whether deployed zero counts are correct. Membership and Foundation foreign keys were checked against the repository migrations. No live connection credentials or fresh preview link were available.

## Interface changes

| Surface | Before | This update |
| --- | --- | --- |
| Foundation layout | Engagement and formal records mixed as peers | Separate area selector and plain-text register navigation |
| Overview | Blended preparation indicators | Independent states and counts; failed reads show Unavailable |
| Scope | Stretched edit actions and approval acknowledgement problems | Content-width secondary edit actions; explicit reviewed checkbox; Administrator-only primary approval |
| Policy/Objectives/Risk review | No common formal version workflow | Shared paged reading view, search for editable records, owner, review rationale, status and history |
| Membership | Host configuration/CLI dead end | In-app host-proven setup and Administrator member editor |

Existing shared tokens, escaped status pills and wrapped table components are reused. Review and Needs update use the actionable amber tone; Draft and Not started remain neutral. HTML labels pass through the existing safe-text component helper. SQL values remain parameterized.

## Verification and limits

On 10 September 2026, **62 focused tests passed** across the new Foundation tests and the existing Programme Foundation, GRC workspace and evidence migration tests. These include first-admin rejection/success paths, last-admin protection, approval permissions, stale risk/owner/version rejection, canonical snapshot selection, Streamlit Policy editing, read-only register rendering, group navigation, and explicit failed-read states. Six dependency deprecation warnings were emitted. Python compilation and release archive integrity were also checked.

Database access in the new repository tests is mocked; Streamlit interaction tests use synthetic fixtures. No production data was changed. No live PostgreSQL migration test or pixel-level browser review was possible here. The PowerShell launcher change was inspected but not executed on Windows in this environment.

This pass does not implement the opportunity-table proposal, a new toolkit importer, faithful recalculated template generation, full cross-register traceability, CSV formula-injection changes, or FastAPI authentication changes. It does not assert completion of every earlier broad redesign request. Existing Context and Interested Parties remain domain-specific records; their count is not treated as approval. The new Policy/Objectives registers provide the agreed minimal version/status/approval pattern.
