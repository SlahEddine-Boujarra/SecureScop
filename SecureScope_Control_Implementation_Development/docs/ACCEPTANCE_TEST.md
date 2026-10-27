# SecureScope v5.3.1 acceptance test

## Static validation

```powershell
.\.venv\Scripts\python.exe -m compileall -q .
.\.venv\Scripts\python.exe -m pytest -q
```

## Nuclei validation

1. `scripts/windows/run_nuclei_diagnostics.ps1` reports an installed executable
   and templates.
2. `scripts/windows/start_nuclei_worker.ps1` produces a recent
   `nuclei-monitor` heartbeat.
3. The engine buttons switch between OpenVAS and Nuclei without a sidebar
   selector overriding the choice.
4. A one-asset authorized campaign creates exactly one Nuclei job.
5. Closing and reopening the browser does not lose the job.
6. Completion stores raw JSONL, a PDF report and common client history.
7. Retrying an interrupted job creates a new attempt and preserves the old one.
8. A multi-asset batch creates one current job per unique asset IP.

## Safety validation

Inspect the saved `command.json` and confirm it is a JSON argument array, not a
shell string. Confirm rate limits, excluded unsafe tags and template-trust
settings match the `.env`.


## Report action regression

1. Confirm queued Nuclei rows with no PID do not produce PyArrow errors.
2. Complete one Nuclei job and confirm the PDF icon appears in that row only.
3. Click the icon and download the provider PDF copy.
4. Complete an OpenVAS job for the same client and IP.
5. Click either report icon and download the combined OpenVAS + Nuclei PDF.
6. Confirm no report icon was added outside Scan Center live job tables.
