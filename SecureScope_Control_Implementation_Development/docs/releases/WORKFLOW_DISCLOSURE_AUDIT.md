# Workflow disclosure audit

Essential state and actions are visible. Histories, imports, logs and secondary configuration retain disclosure. No state is inferred from opening a panel.

| Source | Original line | Section | Decision |
|---|---:|---|---|
| src/securescope/app.py | 4879 | Create client workspace | Keep: secondary details / optional administration |
| src/securescope/app.py | 6043 | Exposure analysis and recent scan activity | Keep: secondary details / optional administration |
| src/securescope/app.py | 6956 | Review detailed evidence and remediation | Keep: secondary details / optional administration |
| src/securescope/app.py | 8560 | OpenVAS provider status guide | Keep: secondary details / optional administration |
| src/securescope/app.py | 3068 | Deployment files and exact locations | Keep: secondary details / optional administration |
| src/securescope/app.py | 6853 | Live / diagnostic Nmap output | Keep: secondary details / optional administration |
| src/securescope/app.py | 6855 | Nmap error output | Keep: secondary details / optional administration |
| src/securescope/app.py | 9246 | <dynamic title> | Keep: secondary details / optional administration |
| src/securescope/app.py | 9331 | OpenVAS submission diagnostics | Keep: secondary details / optional administration |
| src/securescope/app.py | 9885 | Review saved report | Keep: secondary details / optional administration |
| src/securescope/app.py | 6701 | <dynamic title> | Keep: secondary details / optional administration |
| src/securescope/app.py | 9025 | Review duplicate IP records | Keep: secondary details / optional administration |
| src/securescope/ui/control_assessment_ui.py | 72 | Edit control owners and assessment scope | Visible workflow section |
| src/securescope/ui/control_assessment_ui.py | 200 | 1. Agree the target | Visible workflow section |
| src/securescope/ui/control_assessment_ui.py | 384 | Use an additional evidence reference | Keep: secondary details / optional administration |
| src/securescope/ui/control_assessment_ui.py | 442 | Assurance dimensions and effectiveness testing | Visible workflow section |
| src/securescope/ui/control_assessment_ui.py | 701 | Previous assessments and decisions | Keep: secondary details / optional administration |
| src/securescope/ui/control_assessment_ui.py | 220 | Measurement and acceptance details | Keep: secondary details / optional administration |
| src/securescope/ui/gap_dashboard_ui.py | 221 | Calculation method and detailed counts | Keep: secondary details / optional administration |
| src/securescope/ui/gap_dashboard_ui.py | 507 | Quick single-task correction | Keep: secondary details / optional administration |
| src/securescope/ui/gap_dashboard_ui.py | 510 | Saved project timeline | Keep: secondary details / optional administration |
| src/securescope/ui/gap_dashboard_ui.py | 524 | Recent project changes | Keep: secondary details / optional administration |
| src/securescope/ui/wazuh_settings_ui.py | 65 | Configure SIEM connection | Keep: secondary details / optional administration |
| src/securescope/ui/feature_availability.py | 46 | Implementation status | Visible phase/status table; delivery details stay optional |
| src/securescope/ui/risk_workspace.py | 77 | View scoring rubrics | Keep: secondary details / optional administration |
| src/securescope/ui/risk_workspace.py | 92 | Risk details and related records | Keep: secondary details / optional administration |
| src/securescope/ui/risk_workspace.py | 241 | Add treatment action | Visible workflow section |
| src/securescope/ui/risk_workspace.py | 342 | Generate assessment workbook | Keep: secondary details / optional administration |
| src/securescope/ui/risk_workspace.py | 382 | Edit register details | Keep: secondary details / optional administration |
| src/securescope/ui/dual_engine_ui.py | 194 | :material/preview: Preview PDF | Keep: secondary details / optional administration |
| src/securescope/ui/nmap_custom_ui.py | 84 | <dynamic title> | Keep: secondary details / optional administration |
| src/securescope/ui/nmap_custom_ui.py | 219 | Nmap stdout | Keep: secondary details / optional administration |
| src/securescope/ui/nmap_custom_ui.py | 222 | Nmap stderr | Keep: secondary details / optional administration |
| src/securescope/ui/policy_workspace.py | 113 | More filters | Keep: secondary details / optional administration |
| src/securescope/ui/policy_workspace.py | 284 | Bulk import policy documents | Keep: secondary details / optional administration |
| src/securescope/ui/policy_workspace.py | 329 | Upload policy / create document | Visible workflow section |
| src/securescope/ui/policy_workspace.py | 802 | Related policies | Keep: secondary details / optional administration |
| src/securescope/ui/policy_workspace.py | 259 | Starter policy catalog | Keep: secondary details / optional administration |
| src/securescope/ui/policy_workspace.py | 541 | <dynamic title> | Keep: secondary details / optional administration |
| src/securescope/ui/control_implementation_ui.py | 86 | Implementation requirements and document links | Visible workflow section |
| src/securescope/ui/control_implementation_ui.py | 77 | Last recorded evaluation | Keep: secondary details / optional administration |
| src/securescope/ui/evidence_hub_ui.py | 761 | Shared evidence defaults | Visible workflow section |
| src/securescope/ui/evidence_hub_ui.py | 314 | Scope, ownership and freshness | Visible workflow section |
| src/securescope/ui/evidence_hub_ui.py | 537 | Update an existing request | Visible workflow section |
| src/securescope/ui/evidence_hub_ui.py | 735 | Enable workspace access | Visible workflow section |
| src/securescope/ui/document_registers_ui.py | 281 | Import an existing Excel register | Keep: secondary details / optional administration |
| src/securescope/ui/document_registers_ui.py | 245 | Risk distribution | Keep: secondary details / optional administration |
| src/securescope/ui/document_registers_ui.py | 454 | Saved versions | Keep: secondary details / optional administration |
| src/securescope/ui/calendar_workspace.py | 43 | Add event | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 719 | Filters | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 980 | Update finding lifecycle | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 2035 | Control detail, evidence and version history | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 2090 | Create a new assessment-profile version | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 2402 | Approve a versioned target for this control | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 1276 | Advanced details | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 1809 | Approved endpoint execution | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 1926 | All tasks and milestones | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 1858 | Update remediation work item | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 3522 | Detailed A.8 technical assurance | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 3573 | Import from toolkit template | Keep: secondary details / optional administration |
| src/securescope/ui/exposure_management_ui.py | 3679 | Create a versioned SoA snapshot | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 3776 | Create an approved Risk Treatment Plan | Visible workflow section |
| src/securescope/ui/exposure_management_ui.py | 3565 | Statement of Applicability version history | Keep: secondary details / optional administration |
| src/securescope/ui/workspace_deletion.py | 21 | <dynamic title> | Keep: secondary details / optional administration |
| src/securescope/ui/pages/command_center.py | 649 | Programme milestones and assurance lineage | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/discovery.py | 866 | Edit organization profile | Visible workflow section |
| src/securescope/ui/grc_workspace/formal.py | 64 | Administrator setup / local sign-in | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/formal.py | 246 | Discover: source and purpose | Visible workflow section |
| src/securescope/ui/grc_workspace/formal.py | 395 | Version history | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/formal.py | 281 | Add or edit canonical risks | Visible workflow section |
| src/securescope/ui/grc_workspace/formal.py | 299 | Add / edit record | Visible workflow section |
| src/securescope/ui/grc_workspace/sections.py | 280 | Foundation register | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/sections.py | 386 | Engagement administration | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/sections.py | 1036 | Matrix view | Keep: secondary details / optional administration |
| src/securescope/ui/grc_workspace/router.py | 328 | Approvals, history and related records | Visible workflow section |

Custom-component disclosure: policy editing guidance stays optional; risk and control drawers retain full visible fields. Native radio semantics and keyboard navigation remain intact.
