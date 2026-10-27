# Implementing ProjectDiscovery Nuclei in SecureScope

## Why the CLI integration is used

Nuclei is an open-source, template-driven command-line scanner. Its primary
integration surface is the CLI; the official SDK is Go-oriented. SecureScope
therefore uses `subprocess` argument arrays rather than pretending Nuclei is a
local REST API.

## Installation

Use the supplied Windows installer helper:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\windows\install_nuclei_windows.ps1
```

Alternatively install the official binary manually and configure:

```env
NUCLEI_BINARY=C:\Tools\nuclei\nuclei.exe
```

Update community templates:

```powershell
.\scripts\windows\update_nuclei_templates.ps1
```

## Configuration

The important `.env` settings are:

```env
SECURESCOPE_ENABLED_SCAN_ENGINES=OpenVAS,Nuclei
SECURESCOPE_DEFAULT_SCAN_ENGINE=Nuclei
NUCLEI_BINARY=tools\nuclei\nuclei.exe
NUCLEI_DEFAULT_PROFILE=standard
NUCLEI_RATE_LIMIT=50
NUCLEI_BULK_SIZE=10
NUCLEI_CONCURRENCY=10
NUCLEI_DISABLE_UNSIGNED_TEMPLATES=false
NUCLEI_EXCLUDE_TAGS=dos,fuzz,bruteforce
NUCLEI_MAX_CONCURRENT_SCANS=2
NUCLEI_WORKER_AUTOSTART=true
```

## Template trust mode

`NUCLEI_DISABLE_UNSIGNED_TEMPLATES=false` is the functional default for the
official community template collection. Nuclei still applies its built-in
ignore list, and SecureScope adds explicit unsafe-tag exclusions. Set the value
to `true` only after confirming that the templates required by your installed
version have valid signatures; strict mode can deliberately skip unsigned
templates. Custom templates must be reviewed and signed under your own template
trust process.

## Profiles

- `standard` — official community templates with unsafe tags excluded.
- `cve` — templates tagged `cve`.
- `exposure` — exposure and misconfiguration tags.
- `network` — TCP, TLS, DNS and HTTP protocol templates.
- `automatic-web` — automatic web technology-based template selection.

## Target derivation

For each Nmap inventory asset, the worker includes the bare IP/hostname for
network templates. For detected web ports it also creates explicit `http://`
and `https://` URLs. The generated target list is stored with the exact job.

## Output and reports

Nuclei is invoked with JSONL export. Each line is normalized into the common
SecureScope finding model, including template ID, severity, matched endpoint,
CVE/CVSS where supplied, tags, references and cautious ISO Annex A.8 mappings.
Raw JSONL and generated PDF evidence are retained.

## Optional ProjectDiscovery Cloud

Local scanning remains free and does not need an API key. To use the optional
cloud dashboard, authenticate the Nuclei CLI directly:

```powershell
nuclei -auth
```

Then set `NUCLEI_DASHBOARD_UPLOAD=true`. Do not put the cloud key in the
SecureScope `.env`.

## Operational safety

- always require explicit scan authorization;
- keep rate and concurrency limits appropriate for the lab;
- use the official community collection and enable strict signature-only mode when your template trust process requires it;
- review custom templates before use;
- disable Interactsh/OAST when policy does not permit outbound callbacks;
- do not treat Nuclei as a complete authenticated infrastructure scanner;
- combine it with OpenVAS, Nmap, Wazuh and analyst evidence.

## Official references used for this implementation

- Installation: https://docs.projectdiscovery.io/opensource/nuclei/install
- CLI and rate-limit flags: https://docs.projectdiscovery.io/opensource/nuclei/running
- Input formats: https://docs.projectdiscovery.io/opensource/nuclei/input-formats
- Authenticated scans: https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans
- Template documentation: https://docs.projectdiscovery.io/templates/introduction
- Open-source repository: https://github.com/projectdiscovery/nuclei
- Community templates: https://github.com/projectdiscovery/nuclei-templates
