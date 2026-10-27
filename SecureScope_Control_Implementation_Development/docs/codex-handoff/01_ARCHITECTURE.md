# Verified system architecture and source-map

> Paths below were confirmed inside archived source ZIP `(21)` and are relative to its extracted repository root. Recheck exact paths on current branch. 'Exists' does not mean fully functional/tested in production.

## Main stack and boundaries
- Python 3.11, Streamlit 1.62-era app; native Streamlit plus Components v2; source package in `src/securescope/`.
- PostgreSQL repositories and additive migrations. API/control plane via FastAPI. Persistent job infrastructure; separate Nuclei worker and general Evidence Worker; protected artifacts.
- Nmap discovers/enriches authorized assets. Nuclei emits JSONL vulnerability scan artifacts processed into canonical Evidence. Wazuh API (and optional indexer-backed security observations) supplies agent/log/monitoring/clock facts. **No standalone Wazuh Worker**.
- Existing legacy integrations may include OpenVAS. Preserve their backward compatibility; new desired design emphasizes Nmap, Nuclei, Wazuh.

## Known modules to inspect
| Concern | Existing module |
|---|---|
| Wazuh matching and coverage | `src/securescope/integrations/wazuh_service.py` |
| Persisted Wazuh facts | `src/securescope/persistence/db_wazuh_service.py` |
| Wazuh -> canonical evidence | `src/securescope/evidence/wazuh_bridge.py` |
| Nuclei conservative checks | `src/securescope/evidence/automated_checks.py` |
| Assurance re-evaluation | `src/securescope/evidence/continuous_assurance.py` |
| Generic evidence worker | `src/securescope/evidence/evidence_worker.py` |
| Evidence database | `src/securescope/persistence/evidence_repository.py` |
| Scope-aware assessment workspace | `src/securescope/persistence/assurance_workspace_repository.py` |
| Nuclei persistence | `src/securescope/persistence/nuclei_persistence.py` |
| Nmap builder | `src/securescope/ui/nmap_custom_ui.py` |
| Wazuh and security UX | `src/securescope/ui/integration_presentation.py`, `src/securescope/ui/exposure_management_ui.py` |
| Policy editor | `src/securescope/ui/components_v2/policy_editor.py` |
| Risk workflow | `src/securescope/ui/risk_workspace.py`, `src/securescope/grc/risk_lifecycle.py` |
| Control assessment | `src/securescope/ui/control_assessment_ui.py`, `src/securescope/ui/control_profiles_workbench.py` |

## Bugs seen in archive (21) to verify on current branch
- `monitoring_status(None)` returns `"Not monitored"`; should become an unknown/not-verified state absent better proof.
- `monitoring_status(active agent)` returns `"Monitored"`; active agent alone does not verify security observations.
- Agent matcher documents IP -> exact hostname -> **fuzzy hostname contains**. Ambiguous/duplicate IP or fuzzy matches must not be treated as proven identity or scope.
- Summary logic for A.8.16 sets status `"Implemented"` when all inventory agents are active. Replace with factual monitoring-coverage results only; leave human control implementation/effectiveness to the assessment process.
- These are findings from the archived ZIP, not a claim newer changes are absent.

## Important related project rules
- ISMS scope version/approval, SoA applicability, risk acceptance, policy versioning, and assessor sign-off must be preserved.
- Scope links based on stable, authorized membership and provenance, not inferred via discovery or policy classification.
- Existing scan evidence must be backfillable and idempotent; don't create duplicates on refresh.
- Exports and auditor packages need artifact checksums, references, retention, and tenant-level access checks.
- First-admin controlled setup is not configured in the user's last-known environment: inspect actual auth and onboarding flows, do not assume an administrator exists.
