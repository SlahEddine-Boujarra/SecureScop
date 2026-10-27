# Approved UX direction — do not substitute demo code for application logic

The user iterated through several offline layouts and approved **SecureScope ATLAS** as the latest unified design direction. Visual reference is the archived ATLAS v10 offline prototype. Later specific decisions below override older screenshot differences. Never carry prototype's fake data, `localStorage`, fake status counts, or simulation into real production.

## Navigation + shell
- Professional enterprise navigation, single collapsible blue sidebar + persistent workspace/top command bar in ATLAS; user explicitly rejected older cluttered multi-rail/double-sidebar iterations. Aligned real vector icons, clear active states, restrained palette, tables readable at desktop/mobile widths.
- Workspace selector, role-sensitive routes, correct scope context in headers; preserve deep links, active state, keyboard accessibility and popovers. No inert buttons.

## High-value workflows that must survive
- **Policy Library:** clean searchable compact library, no *large* main-page Review Queue and Version History panels. Those audit/history/approval features remain available contextually/backend. Click policy -> **Policy Builder: Suggestions | Word-like editable document**. Section navigation, insert/rewrite suggested wording, directly edit text, bold/italic/lists, save draft, true Word/PDF export using existing services; preserve approved version immutability.
- **Risk Management:** user prefers **original application's risk workspace** (named registers, scenarios, treatment lifecycle, details) enhanced, not replaced with a generic heatmap dashboard. Inherent AND Residual 5x5 matrices, filters/clickable cells. Replace four oversized KPI cards with compact **Risks registered**, **High inherent exposure**, **In treatment**; move **Current scope** to header/context selector. Derived real values only.
- **Evidence Register:** Aurora-command-console-inspired explorer; searchable/filterable evidence list plus contextual right inspector, tabs **Overview / Mappings / Provenance**. Trust level, artifact SHA-256, scope match, freshness and exact ISO requirement must be readable.
- **Asset Management:** keep original table-first inventory, search/filter/selection/detail flows, asset tag prominence, Wazuh sync state and scanner coverage. Add **Asset Classification** distinct page and fields (criticality + information class), with controlled edits and audit metadata. Do not auto-assign scope based on class.
- **Nmap Discovery:** preserve original **Custom Scan Builder** with presets, advanced options, ports/timing, NSE scripts, rendered safe command preview, authorization confirmation, candidate review/admission, parsed/exportable results. Nmap and Nuclei are separate experiences.
- **Scan Workspace / Nuclei:** preserve scanner worker queue, live job state, results, JSONL artifacts and evidence links; no new fake engines. No unsupported Nessus/OpenVAS panels by default.
- **SIEM / Wazuh:** user explicitly rejected bulky **Connection & Collection** section. One compact **Wazuh actions** menu/button for configure/test/collect; full-width **asset synchronization and monitoring table** with accurate states and evidence drilldown. Don't remove backend connector management controls.
- **Command Center:** concise ISO programme journey and Annex A coverage overview, but no fake percentages/certification assurances. Journey is a planning interface; Annex A counts A.5=37/A.6=8/A.7=14/A.8=34, status derived only from approved SoA and human assessment.
- **Control Assurance:** scopes, requirements, verified evidence, coverage and human implementation/effectiveness decision should remain distinct; a consultant-oriented Assessment form with reason/action, not a giant checklist maze.
- **Programme Foundation:** Context and climate relevance, Interested Parties requirements, controlled Scope/Dependencies/Exclusions, Objectives, Roles & RACI, SoA, audit planning; use progressive disclosure and meaningful structured forms.
- **Audit/Reporting:** audit scope and evidence readiness, report composer/exports, versioned human outcomes. No invented certification states.

## Integration rules
- Implement against Streamlit native and Components v2. Reuse existing design tokens where possible; consolidate conflicting legacy CSS without creating an extra overriding stylesheet maze.
- Page-by-page migration with screenshots, keyboard/accessibility checks, visible loading/empty/error/stale states, responsive widths, and full feature parity acceptance.
- Avoid wholesale replacing original risk/scanner/Policy Builder backend with screenshots or generated static frontend stubs.
