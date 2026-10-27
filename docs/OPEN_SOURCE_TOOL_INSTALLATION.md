# Open-source evidence sources and installation

SecureScope does not require all 31 sources. Install only the tools approved for
the client scope. Existing Nmap, OpenVAS, Nuclei, Wazuh and CISO Assistant
configuration remains valid. Many security tools are more reliable in a
dedicated Linux/WSL worker than directly on Windows.

Never place credentials in connector report files or SecureScope code. API
credentials belong in environment variables or a production secret manager.

## Integration matrix

| Source | Mode | Installation/connection guidance |
|---|---|---|
| Nmap | Existing worker | Use the official Windows installer and keep `nmap.exe` on PATH. |
| OpenVAS/Greenbone | Existing worker | Keep the existing GMP/SSH-tunnel configuration; run Greenbone on its supported Linux appliance/VM. |
| Nuclei | Existing worker | Run `scripts/windows/install_nuclei_windows.ps1`. |
| OWASP ZAP | Defensive CLI/import | Install the official ZAP desktop package; add its launcher to PATH. |
| Wazuh | Existing API | Configure the existing Wazuh API/indexer variables. |
| CISO Assistant Community | Existing API | Deploy the Community edition separately and configure the existing API token. |
| OWASP Amass | Defensive CLI/import | Install the official release binary or a dedicated Go build in the worker. |
| theHarvester | Defensive CLI/import | Prefer `pipx install theHarvester` in WSL/Linux. |
| DNSRecon | Defensive CLI/import | Prefer the project package in WSL/Linux; add `dnsrecon` to PATH. |
| Nikto | Defensive CLI/import | Install Perl and Nikto in WSL/Linux; add `nikto` to PATH. |
| Wapiti | Defensive CLI/import | `pipx install wapiti3` in an isolated worker environment. |
| Droopescan | Defensive CLI/import | `pipx install droopescan`; used as the open-source CMS/WordPress alternative. |
| Lynis | Defensive CLI/import | Linux/Unix endpoint collector; install from the distribution package or official repository. |
| OpenSCAP | Defensive CLI/import | Install `oscap` and approved SCAP content on a Linux worker. |
| Trivy | Defensive CLI/import | Download the official Windows release binary or install it on the Linux/CI worker. |
| Grype | Defensive CLI/import | Download the official Anchore release binary and place it on worker PATH. |
| Prowler | Defensive CLI/import | Use an isolated environment: `pipx install prowler`; configure read-only cloud credentials externally. |
| ScoutSuite | Defensive CLI/import | Use `pipx install scoutsuite`; configure read-only cloud credentials externally. |
| OSV-Scanner | Defensive CLI/import | Download the official release binary and place it on PATH. |
| Semgrep CE | Defensive CLI/import | Prefer `pipx install semgrep` in Linux/WSL/CI. |
| Bandit | Defensive CLI/import | `pipx install bandit` in the code-analysis worker. |
| SonarQube Community | API/import | Run the Community server separately and connect through its Web API or export reports. |
| Metasploit | Import only | No installation is required by SecureScope; import authorized test results only. |
| Hydra | Import only | No installation is required by SecureScope; import authorized test results only. |
| Medusa | Import only | No installation is required by SecureScope; import authorized test results only. |
| Ncrack | Import only | No installation is required by SecureScope; import authorized test results only. |
| BeEF | Import only | No installation is required by SecureScope; import authorized test results only. |
| Atomic Red Team | Import only | No installation is required by SecureScope; import authorized test results only. |
| Redmine | API/import | Run Redmine separately; integrate through a least-privilege API key or import. |
| GLPI | API/import | Run GLPI separately; integrate through a least-privilege API client or import. |
| GitLab CE | API/import | Run GitLab CE separately; use a scoped access token or issue/SARIF export. |

WPScan is deliberately not in the commercial open-source catalog: its official
terms state that commercial integration requires a paid license. Droopescan is
the open-source replacement for CMS/WordPress exposure evidence.

## Python application dependencies

The normal Windows launcher installs the v5.3.8 dependencies. For an existing
virtual environment, run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m securescope.cli.run_migrations
```

Then start only the processes you need:

```powershell
.\start_securescope.ps1
.\scripts\windows\start_api.ps1
.\scripts\windows\start_evidence_worker.ps1
```

Use official project documentation to select versions and validate licensing
before commercial deployment. SecureScope detects executables on PATH but does
not install third-party scanners silently.
