# SecureScope runtime architecture

For the v5.3.8 package boundaries and dependency direction, see
[`architecture/OVERVIEW.md`](architecture/OVERVIEW.md).

```text
Browser / Streamlit presentation
        |
        +--> application services <-- FastAPI control plane
                    |
                    +--> client --> engagement --> approved ISMS scope
                    +--> PostgreSQL workspace tables
                    +--> protected artifact storage
                    +--> persistent job queues
                              |
                              +--> OpenVAS worker --> GMP --> Greenbone
                              +--> Nuclei worker --> local Nuclei CLI
                              +--> Evidence worker --> allowlisted defensive tools
                    |
                    +--> normalized evidence and canonical findings
                              |
                              +--> consultant validation
                              +--> clauses 4-10 and 93 Annex A controls
                              +--> SoA, gaps and risk treatment
                              `--> printable matrix and auditor package
```

Every engagement-owned GRC row uses `client_id` and `engagement_id`; scope-owned
rows also use `scope_id`. Existing scanner jobs remain workspace-owned through
`client_id`. Raw scanner
and evidence artifacts remain separate from normalized observations. The API
and Streamlit processes enqueue work; only independently restartable workers
invoke approved scanner or collector adapters.

Offensive and credential-testing sources are import-only. CISO Assistant stays
an external integration. AI can refine advisory remediation text but cannot
close findings, validate evidence, approve controls, change the SoA or accept
risk.

## Identity rules

An IP address is target data, not scan identity. Nuclei persists `client_id`,
`batch_uuid`, `job_uuid`, `attempt_number`, asset IP, runner PID and exact file
paths. A retry creates a new attempt and does not overwrite the prior evidence.

## Nuclei lifecycle

1. Streamlit validates the client, selected inventory records and authorization.
2. It creates one batch and one job per unique asset.
3. The standalone worker claims queued jobs with PostgreSQL row locks.
4. It derives targets from the asset IP, hostname and Nmap web-service ports.
5. It writes a command as a JSON argument array; no shell command is used.
6. A detached child runs Nuclei and writes an atomic result marker.
7. The worker reconciles the marker after restarts, parses JSONL, generates PDF
   evidence and writes common scan history.

## Nuclei and API keys

Local Nuclei OSS execution needs no API key. ProjectDiscovery Cloud
authentication is optional and performed with the official `nuclei -auth`
command outside SecureScope. SecureScope never stores that optional cloud key.
