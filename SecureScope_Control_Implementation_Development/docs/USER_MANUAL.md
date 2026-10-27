# SecureScope user manual

## 1. Start

Run `start_securescope.ps1` and open `http://localhost:8501`.

## 2. Select a workspace

Use the sidebar client workspace selector. Assets, campaigns, reports and ISO
reviews remain isolated by client.

## 3. Discover assets

Run Nmap discovery or the custom Nmap profile builder, review results and save
approved assets.

## 4. Scan Center

Open **Scan Center**, then use the normal **OpenVAS** or **Nuclei** button.
The selected engine applies to new campaigns only.

For Nuclei, choose target mode, profile, optional CISO synchronization and
confirm authorization. The live page reads PostgreSQL and can be reopened.

## 5. Findings and reports

Completed provider reports are normalized into client history. Review severity,
CVE/CVSS data, remediation guidance and downloadable PDFs.

## 6. Wazuh and clock assurance

Wazuh agent evidence supports monitoring controls. Endpoint clock probes—not
UDP/123 alone—support ISO A.8.17 synchronization evidence.

## 7. ISO assessment

Review automated Annex A.8 evidence, record applicability and analyst status,
and create corrective actions. Scanner output is evidence, not certification.
