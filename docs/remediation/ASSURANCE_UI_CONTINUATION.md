> Superseded by `../releases/RISK_MANAGEMENT_UX_CHECKPOINT.md`. The later screenshot review confirmed the local launch-code access path matches this source. This package is a full development checkpoint.

# SecureScope assurance UI continuation — 15 September 2026

This is a development patch against the available Python 3.11 repaired checkpoint
(5.4.9.dev0, base commit 514d5be). It is not a completed remediation release.
The user reports a newer working local-account implementation. That newer source
was not present in the available ZIPs, so this patch still requires a merge into it.
Do not replace the working account build with this older source baseline.

## Implemented

- Assess Control now opens the guided editor as the main workflow. Four sections
  organize scope and target, evidence, assessment, and review/save. Inputs have
  visible boundaries and consistent spacing. Target approval is accessible first;
  finalization stays disabled without a target. Criterion results, effectiveness
  testing and re-test details remain available. Drafts retain their values when
  switching between controls, and the selected control stays in Assess Control.
- Control Profiles uses a searchable, paginated table with an editable right-side
  drawer. It groups intent, owners, scope, assessment methods and evidence needs.
  Saves use the existing versioned profile service and create a new draft version.
  The existing target must be reviewed for the new profile before assessment.
- The shared drawer retains the table behind it, has an independent scroll area,
  visible header/footer actions, full-value text, Escape/Tab handling, focus return,
  and explicit discard confirmation for unsaved profile edits. Failed saves keep
  edited values. Scope/Foundation record details reuse this drawer presentation.
- Risk tables use minimum readable column widths with horizontal scrolling instead
  of squeezing words into narrow columns. The Foundation canonical-risk view shows
  a concise business summary and opens all assessment fields in a detail drawer.
  The bulk risk editor keeps its existing persistence/export flow and wider fields.
- Server handling resolves control IDs in the current workspace, whitelists fields,
  and takes the actor from the existing identity helper. Auditor edits and foreign
  control IDs are rejected. Profile saves compare the opened version while holding
  a client transaction lock, preventing an older drawer from overwriting newer edits.
- The Windows security-update recipe keeps its exact integrity-pinned LF bytes in
  Git checkouts. No recipe commands or expected digest were changed.
- The user explicitly deferred the 60% coverage floor. CI still collects coverage
  and runs tests; its floor is temporarily zero. Other gates remain enabled.

Navigation, application scale and Exposure Overview code were not redesigned.
No new database migration is required for this patch.

## Verification

- Python 3.11.16: 424 tests passed; 7 skipped.
- Four skips need a configured PostgreSQL test database; three tokenizer checks
  intentionally require Python 3.12. Python 3.11 compilation succeeds for src,
  tests and scripts.
- 15 frontend test entries passed, including existing policy/risk/calendar tests
  and new drawer editing, read-only, keyboard, escaping and failure-recovery checks.
- Black, isort, flake8, dependency consistency and git whitespace checks pass.
- Measured Python coverage is approximately 32.1%; the 60% goal is deferred.
- Streamlit AppTest renders the synthetic profile, assessment and risk previews;
  actual route tests verify profile-to-assessment navigation and control switching.
- Browser visual verification remains unverified: the preview server starts, but
  the connected browser rejects localhost with ERR_BLOCKED_BY_CLIENT.
- Live PostgreSQL transaction/concurrency tests, Windows interactive verification,
  hosted CI and integration with the newer local-account build remain outstanding.

## Patch contents and integration

The ZIP contains `changes.patch`, `changed-files/` with the new versions of every
changed file, this report, and `base-revision.txt`. The source copies are for review;
blindly overwriting those paths in a newer build could remove newer work.

For a Git checkout of the exact baseline, apply after making a working branch:

```sh
git apply --check changes.patch
git apply changes.patch
python -m compileall -q src tests scripts
python -m pytest -q --cov=securescope --cov-fail-under=0
npm ci --prefix tests/frontend
npm test --prefix tests/frontend
python -m streamlit run scripts/preview_assurance_ux.py
```

The preview uses synthetic records and session-only saves; it does not connect to
PostgreSQL, start scanners, or change production records. Stop it with Ctrl+C.

For the newer working-account build, upload that full source ZIP for a contextual
merge and regression run. Authentication must be reviewed in that version before
marking Phase 1 complete. Phase 2 ISO workflow completion, Phase 3 architecture/data
work, remaining Phase 4 screens and Phase 5 validation remain on the remediation
backlog; this patch completes the specifically requested UI work, not all phases.
