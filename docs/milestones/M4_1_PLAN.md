# M4.1 — SIEM/Wazuh UX integration

27 October 2026. User authorized continuation to the next stage after the M3 delivery.

The inspected roadmap defines M4 as ATLAS UX integration. Execute its first bounded screen, SIEM/Wazuh, before migrating the remaining screens. Reference: ATLAS v10 offline package and its SIEM reference image; later UX instructions in `docs/codex-handoff/03_UX_DECISIONS.md` take precedence.

Baseline: restored M3 delivery source `f20d74f52bcc2335c364f54d6e9c83f0fbfdea08`, all 916 delivery entries hash-verified. The extracted source is a new local Git repository; its restore commit is not the original historical commit.

## Scope and implementation order

1. Reproduce existing focused Wazuh/UI tests in an isolated virtual environment.
2. Add a presentation-only adapter and Components v2 monitoring table/inspector. Use canonical asset IDs and repository-derived statuses; never derive verification from active-agent status or alert count. Whitelist presentation fields, escape text, isolate component state by workspace, and show no invented scope membership.
3. Replace the sprawling connection/configuration area with one compact native Wazuh actions popover. Route configure, test, collect, bindings and schedules to existing implementations. Keep existing role checks and add explicit server-side action guards.
4. Add search, state filters, paging, clear empty/error states, keyboard-operated inspection and responsive layout. Preserve full source reasons, observation hash/times and the distinction from human assessments.
5. Run focused and general regressions, DOM and browser checks where available. Record synthetic-data boundaries and unavailable live/database gates accurately. Package the first M4 slice for review.

## Affected files

- `src/securescope/app.py`: SIEM route presentation/action placement only; retain clock-evidence section and exports.
- New `src/securescope/ui/siem_presentation.py`: explicit safe presentation contract.
- New `src/securescope/ui/components_v2/monitoring_workbench.{py,js,css}`: existing Components v2 integration, scoped styles and shared tokens.
- `src/securescope/ui/wazuh_monitoring_ui.py`: compact action menu and on-demand existing editors.
- Focused Python/frontend tests and `validation/m4_1/` reproduction/verification artifacts.

No schema migration, new worker, broker, scanner, compliance rule, global navigation rewrite or production enablement. Existing services, policies, risk management, Nmap, Nuclei and M3 checks remain intact. A.8.17 code/records/identity logic remain unchanged. Other M4 screens follow in subsequent reviewed slices.

## Acceptance

Full-width table by default; details accessible by mouse and keyboard; search/filter/pagination preserve stable IDs; workspace changes clear selected state; no markup execution from source text; disabled actions have server-side guards; no empty-data success claim; expired proof cannot remain visually current; monitor states retain M1/M2 meanings. Configuration, bindings, recurring-job history/cancellation, existing clock workflow and CSV/Excel exports remain reachable. Production gates from M3 remain open.

## Approved continuation: Kimi review integration

During M4.1, the user supplied `Kimi_Agent_Wazuh Evidence App Review.zip` and requested inspection of its bug fixes before continuing M4. Compare it against the restored M3 source and merge its applicable UI corrections into the current working tree. This adds the existing Evidence Register/sidebar affordances, shared status presentation, Command Center Wazuh status-label correction, and configured-default-workspace selection to the bounded delivery. Preserve the separate reviewer/scope filters alongside the new combined search. Record the archive's missing files as packaging omissions, not deletions.

The Dockerfile and automatic evaluation bootstrap are reviewed but excluded from the application runtime: they introduce deployment, database lifecycle and assumed-identity behavior beyond this UI milestone. No production gates are waived. See `M4_1_KIMI_REVIEW.md` for the per-file disposition.
