# SecureScope v5.4.0 — Streamlit Modernization + Stitch UI

## Architecture

- Upgraded the supported Streamlit line to 1.62.x.
- Replaced the session-state top-level router with `st.Page` + hidden
  `st.navigation`, while preserving the custom SecureScope sidebar.
- Added stable URL paths and hidden contextual routes for Asset Discovery,
  Technical Assurance and Evidence Hub.
- Added a navigation compatibility bridge using `st.switch_page`.
- Added fragment boundaries to high-interaction application pages and a parallel
  technical-coverage fragment on Command Center.
- Added a process-wide `ThreadedConnectionPool` for shared PostgreSQL repository
  traffic.

## Stitch UI foundation

- Added centralized SecureScope design tokens.
- Added native Streamlit Components v2 for Stitch KPI cards, Certification
  Journey and the enterprise control table.
- Kept safe Streamlit fallbacks for environments where Components v2 is not
  available.
- Control Profiles now separate SecureScope recommendation from Human
  Assessment while preserving every existing assurance workflow.
- Preserved the v5.3.8.13 Command Center, Exposure Overview and Programme
  Foundation interaction model as the visual reference.

## Safety and compatibility

- No database migration is introduced by v5.4.0.
- OpenVAS, Nuclei and evidence workers remain persistent/background services.
- Automated evidence remains advisory and never silently replaces human ISO
  assessment.
- Evidence Hub, Gap Actions, Statement of Applicability and Risk Treatment Plan
  remain fully available.
