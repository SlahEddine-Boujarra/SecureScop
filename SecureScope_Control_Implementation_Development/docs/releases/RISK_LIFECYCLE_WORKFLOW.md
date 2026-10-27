# Risk lifecycle workflow — development update

## Architecture inspection

The canonical scenario is `securescope_risk_register`, accessed by `risk_register_repository`. It already owns asset/threat/vulnerability, current ratings/rationales, treatment action/control references, cost, ownership/progress notes, residual ratings/rationales and comments. Scores are calculated by `grc/risk_register.py`, not stored from browser input.

The existing `risk_detail` workspace record holds register placement, discovered-asset links, review metadata and now the summary, description, existing-control references, numeric progress, due date and conclusion. These are extensions of the same risk reference. `risk_links.save_assessment` writes the canonical row and supporting metadata in one transaction, retaining workspace authorization and both concurrency checks. Narrative additions reuse the existing encrypted-text mechanism. The canonical list reader resolves these extensions so they are available to other views and JSON exports.

Risk interactions use the existing Streamlit Components v2 action bridge (`dispatch_risk`) and repository calls, not dedicated REST risk controllers. No duplicate API or scenario entity was introduced. Existing workbook `scenario_risks` working documents were found during inspection; they remain legacy document registers and are not a new backing store for this editor. No automatic copy or merge of legacy workbook records was performed.

## Implemented

- Seven visible sections: Description; Pre-Treatment; Treatment; Post-Treatment; Matrix/Comparison; Conclusion; Review/Complete.
- Risk summary and description coexist with asset, threat and vulnerability on the same scenario.
- Existing and treatment controls select multiple current workspace Control Profiles.
- Numeric 0–100% progress, treatment due date, retained free-text progress notes/timescale, and Blocked/Cancelled statuses.
- Pre/post likelihood × impact formulas update directly; no manually editable score or risk level.
- A 5×5 individual matrix uses distinct ● pre-treatment and ◆ residual markers, including coincident positions. Hover/focus titles expose risk and cell information.
- Register Table View / Matrix View, inherent/residual selection, cell counts, click-through to existing risks, and an explicit unassessed count. Existing register, search, owner-view and assessment-state filters apply to both views.
- Compact default register columns and a complete View/Edit workflow instead of showing all input fields as columns.
- Draft saves preserve identified incomplete rows. Completion enforces required identification, ratings/rationales, treatment owner/date/progress, mitigation control links, conclusion and decision.
- Completion is pinned to the canonical revision. Later changes invalidate completion in the UI. Approval and formal acceptance remain separate.
- Lifecycle navigation now uses segmented controls. Register creation remains only in the register-list header; later lifecycle stages do not create scenarios.
- Existing impacted-asset selection/search, treatment tasks, comments, review submission and approval are retained.

## Important distinctions

The configured methodology feature does not yet exist in this codebase. The browser receives the current canonical 1–5 rules and level mapping from Python; it does not invent a second threshold configuration. Matrix colors use existing design tokens. The 5×5 matrix follows the supplied markdown, even though the reference image shows four levels.

No organization-specific risk appetite is configured, so the UI says this explicitly instead of inventing a threshold warning. Formal risk-owner acceptance, configurable versioned methodology, automated review campaigns and dedicated residual verification/sign-off remain unfinished. Choosing Accept residual risk records a proposed decision only. Complete Assessment means the required assessment fields are filled; it does not prove that treatment operates. Residual estimates remain labeled planned/unverified and assessment edits invalidate prior residual verification.

## Installation

This is a full development source package. Keep the installation's existing configuration and credential-encryption key; new narrative fields use that key. Back up the database and test this build separately first.

Run the existing migration launcher before the app/workers. Migration **013_risk_treatment_statuses.sql** widens the existing status constraint for Blocked and Cancelled. It does not recreate or delete risk rows. Do not enable this build against a database where the migration has not run.

## Validation and limitations

- Python: 492 passed, four skipped PostgreSQL integration tests, two dependency deprecation warnings, using Python 3.12.
- Frontend: 24 Node/DOM checks passed, including live scoring, shared pre/post record saves, two markers in one cell, matrix aggregation/drilldown, read-only fields and stage-specific creation actions.
- Black, isort and flake8 passed. Source/test compilation and Python 3.11 grammar compatibility checks passed. The new build was not executed under a Python 3.11 interpreter here.
- Live PostgreSQL migration/application writes, Windows installation and browser visual verification remain unverified. Transaction tests use simulated database connections.
- The wider master remediation roadmap is not complete; the coverage floor remains deferred as previously authorized.
