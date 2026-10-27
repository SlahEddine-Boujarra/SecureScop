## Scoped evidence and assurance correction pass (2026-10-06)

- Repair canonical technical evidence scope associations, mappings and idempotent backfill; unify freshness and add independent Wazuh proof ingestion.
- Preserve human assessment decisions; add migration 016 for draft SoA exclusions with strict approved-state guards.
- Polish assurance workflows, sidebar geometry and automatic Windows UTF-8 startup. Part I UI removals remain excluded.
- 730 Python tests passed; 5 PostgreSQL checks skipped. Live database, Wazuh, Windows and browser/caret acceptance remain pending. See CORRECTION_PASS_20261005.md.

## Nuclei evidence integration and workflow corrections (2026-10-04)

- Add trusted Nuclei JSONL evidence provenance, deterministic check mapping, configured-asset scope links and current asset coverage through existing services.
- Keep human assurance decisions separate from automated collection; retain manual/import review.
- Preserve collector scope context, canonical dotenv loading and startup migration safety without per-poll migration checks.
- Separate Control Profiles list/detail rendering and place requirement confirmation in its section.
- Deliver policy Word/PDF exports directly through nonce-deduplicated browser Blob downloads.
- Add migration 015 and regression tests. 695 Python tests pass, 4 PostgreSQL tests skip; live acceptance remains pending. See NUCLEI_EVIDENCE_IMPLEMENTATION.md.


## Workflow correction pass

- BUG-04: Normalize GRC audit payloads once before hashing and storing, including milestone dates. Added a stored-payload/hash regression. Supplied browser regression is now an assertion; live browser execution remains pending.
- BUG-15: Hide Streamlit exception details globally; Programme Foundation service failures now log full server details and return an operation-specific reference. Domain validation remains readable.
- BUG-01: Handle Exposure Overview navigation after the button event rather than invoking page switching inside its callback. Strengthened the supplied test to assert the Asset Discovery URL.
- BUG-02: Restore distinct native progress track and fill colors
- BUG-03: Hide self-referencing Back control on the first scope step
- BUG-08: Use clear preview-only import wording
- BUG-08: Use clear preview-only import wording
- BUG-09: Limit scope-wide empty banner to the risk register list
- BUG-10: Match Scan Center and Reports & Audit titles to navigation
- BUG-13: Show signed-in identity instead of the local setup form
- BUG-05: Reuse canonical numeric ISO area ordering in the assurance dashboard
- BUG-12: Consolidate missing-engine guidance under one repair expander
- BUG-10b: Set readable painted text on primary and dialog submit buttons

- fix(NAV-01): Remove overlapping native/custom tab indicators and old inline tab styling. Preserve native navigation, overflow and keyboard behavior; verify reruns do not accumulate bars.
