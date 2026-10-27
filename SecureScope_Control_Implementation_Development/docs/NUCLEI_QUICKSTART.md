# Nuclei quick start

```powershell
cd "C:\path\to\SecureScope_v5_3_6_Professional_GitHub"
Copy-Item .env.example .env
notepad .env
.\scripts\windows\install_nuclei_windows.ps1
.\scripts\windows\update_nuclei_templates.ps1
.\scripts\windows\run_nuclei_diagnostics.ps1
.\scripts\windows\start_nuclei_worker.ps1
.\start_securescope.ps1
```

In the UI:

1. Discover and save authorized assets.
2. Open **Scan Center**.
3. Click the normal **Nuclei** button.
4. Select one asset or multiple assets.
5. Select a Nuclei profile.
6. Confirm authorization.
7. Create the campaign.
8. Follow the durable live table and event timeline.

Diagnostics are written to `logs/nuclei_diagnostics.json`. Per-job evidence is
stored under `logs/nuclei_jobs/<job_uuid>/` and final reports under `reports/`.
