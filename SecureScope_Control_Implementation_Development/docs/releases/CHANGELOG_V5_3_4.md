# SecureScope v5.3.4

UI-only correction based on v5.3.3.

## Changed

- Removed the `Discover / Manage / OpenVAS / Reports / Monitor / Assess`
  workflow bar from every application page.
- Fixed the sidebar label drift by assigning every Material Symbol a fixed
  `1.15rem` icon column.
- Kept expanded sidebar buttons left-aligned even when the Streamlit mode
  marker is rendered outside the sidebar subtree.
- Converted the seven ISO A.8 sections into equal icon controls.
- Converted the six Gap Assessment sections into equal icon controls.
- Preserved complete section names in the DOM and added hover/focus tooltips.

## Preserved

- Asset Management remains free of clock/NTP presentation fields.
- NTP evidence and ISO A.8.17 backend services remain available elsewhere.
- Nmap, OpenVAS, Nuclei, Wazuh, PostgreSQL, CISO Assistant, remediation,
  reports, queues and workers are unchanged.
- No migration or environment-variable change is required.
