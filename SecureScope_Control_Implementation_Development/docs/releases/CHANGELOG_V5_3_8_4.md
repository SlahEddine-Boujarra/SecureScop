# SecureScope v5.3.8.4 — Programme Foundation Discovery

## Purpose

Reduce repeated ISO 27001 data entry without changing SecureScope's original
technical-assurance objective. Nmap, OpenVAS, Nuclei, Wazuh and other evidence
sources remain inputs to control assurance; the new discovery layer improves the
organizational context that makes those observations meaningful.

## Changes

- Replaced vulnerable Markdown-based custom dashboard rendering with a trusted
  `st.html()` presentation helper for dashboard cards, foundation rows, context
  bar, status badges and programme-progress components. This prevents indented
  HTML fragments from appearing as source text in the Streamlit application.
- Added additive migration `006_organization_knowledge.sql` with:
  - one workspace organization profile;
  - provenance-aware organization facts;
  - client/engagement/scope ownership fields;
  - explicit source, confidence and review states.
- Added **Discovery** to Programme Setup before the advanced manual registers.
- Added a compact organization quick profile covering industry, activity,
  employee range, infrastructure, departments, technologies, markets, locations,
  products/services and certification drivers.
- Confirmed profile values are materialized as reusable organization facts instead
  of being copied independently into every ISO form.
- Added deterministic Context recommendations. A recommendation becomes a real
  context record only after the consultant clicks **Add**.
- Added deterministic Interested-Party recommendations. The consultant selects
  the exact starter requirements to accept; only those requirements are created
  as applicable.
- Added Scope Composer. It prepares a formal statement and boundary summary from
  confirmed facts, but creates only a draft scope version. Existing human approval
  and immutability controls remain unchanged.
- Programme attention items for missing Context/Parties/Requirements now route to
  Discovery first rather than directly to blank manual forms.
- Filled the Command Center readiness column with programme dimensions to reduce
  the excessive empty space created by the taller attention column.

## Assurance boundary preserved

This release does not change scanner workers, findings, evidence normalization,
control assessment, SoA, risk treatment or remediation logic. Organization
Discovery does not declare ISO controls implemented. Technical evidence remains
supporting evidence and final assessment decisions remain human-controlled.

## Validation

- Python source compilation: passed.
- Regression suite: **149 passed**.
- Migrations 001–005 remain byte-stable; migration 006 is additive only.
