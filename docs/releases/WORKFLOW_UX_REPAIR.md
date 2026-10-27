# Workflow visibility and action repairs — development update

This updates the Control Implementation development checkpoint. It retains the existing models, repository services, permissions and assessment validation. It is not completion of the wider remediation roadmap.

## Changes

- Implementation evidence opens above the Control Profile table, with a clear Back action. Owner, linked Policy and Procedure versions, Evidence count and Verification result appear immediately. Missing requirements and the existing evaluator's reasons are visible. Historical snapshots remain optional details.
- Draft recorder defaults to the existing signed-in identity, including local sessions. Draft-save success/errors appear in the tab where Save was clicked. Review & save and Assessment conclusion both offer visible draft saves; Assessment conclusion also offers Save assessment through the existing finalization service. Target requirements and validation rules remain unchanged.
- Risk registers use a searchable, policy-style table with Add Risk Register in the header. Scenario creation is available only in Registers & assessment. Treatment, residual assessment, acceptance and monitoring no longer show creation buttons. Stale creation events on those stages are rejected server-side. Foundation links to Risk Management instead of duplicating its creation button.
- Audited 75 Python accordion usages. Replaced 21 essential workflow disclosures with visible sections. Product phase states are also visible, with only their delivery details collapsed. Optional history, import tools, filters, logs and secondary administration remain collapsible. See WORKFLOW_DISCLOSURE_AUDIT.md for every audited location.
- Radio choices have consistent spacing, selected-state styling and keyboard-focus outlines; native semantics remain intact.

## Validation

479 Python tests passed; 7 skipped; 2 third-party deprecation warnings. 20 frontend DOM checks passed. Tests exercise component event routing, persistence arguments, consecutive draft revisions, visible feedback, finalization and lifecycle-specific actions. Python 3.11 compilation, Black, isort and flake8 checks passed for the changed Python code.

The seven skips include four tests needing an explicit live test database and three Python 3.12 tokenizer checks (the Python 3.11 parser checks run). No live PostgreSQL, Windows installation or browser visual pass was performed. Mocked UI/repository boundaries cannot prove successful writes against your deployment. The 60% coverage floor remains deferred as authorized.

## Use

Install this complete development source in a separate directory and point it to a backed-up test database. Preserve your existing configuration and encryption key. The package includes no client database or credentials. Use the existing launcher and Python 3.11 dependency installation instructions. No new schema migration is introduced by this UI update.

In Control Profiles, open a row and select Implementation evidence. Save or discard dirty profile edits first; their protection remains. In Assess control, enter the assessment and use Save assessment draft or Save assessment at the bottom of Assessment; Review & save remains available for validation decisions. New registers are created from the Risk registers list; use the back link from a scenario list to reach it.
