# Dual-engine scan reports

SecureScope v5.3.1 adds row-level PDF actions to the two live job tables inside
**Scan Center** only:

- OpenVAS live execution table;
- Nuclei live operations table.

No report icon is added to the general dashboard, asset inventory, findings,
SIEM, ISO mapping, or client-history tables.

## Report action

The live tables use supported Streamlit columns. Under each table,
**Completed scan reports** shows asset names with direct native download icons,
paged ten assets at a time. Reports are prepared before the button is enabled.
An unavailable report has a disabled action with sanitized error text.

Streamlit 1.62 has no `st.column_config.ButtonColumn`. The former unsupported
column has been removed; the direct action uses `st.download_button` with the
Material download icon and an accessible help label.

## User workflow

1. Open **Scan Center** and select **OpenVAS** or **Nuclei**.
2. Locate the asset under **Completed scan reports** below its live table.
3. Click its download icon to receive that completed job's PDF.

Existing detailed report panels and consolidated reports continue to use the
same client/job resolution described below.

## Consolidation rules

The clicked job is resolved against the exact client workspace using, in order:

1. engine + job ID;
2. engine + report ID;
3. engine + job UUID;
4. latest completed same-engine record for the exact asset IP.

For a dual-engine report, SecureScope adds the latest completed result from the
other engine for the same client and exact asset IP. The PDF shows the scan date
and finding count for each engine, so older supporting evidence is not hidden.

An IP address is target data, not scan identity. The underlying provider report,
job UUID, attempt number, client, and batch remain preserved in PostgreSQL.

## PDF structure

The report layout uses the supplied sample report as a visual hierarchy
reference without copying its brand. The SecureScope PDF contains:

- report title and client metadata;
- target, scan date, scanner engines, and report ID;
- security score and full-width risk banner;
- severity distribution;
- key findings;
- detailed checklist with an Engine column;
- asset and exposure context;
- assessment coverage for OpenVAS and Nuclei;
- detailed findings and remediation;
- prioritized recommendations;
- ISO/IEC 27001:2022 evidence references;
- assessment limitations.

## Arrow serialization fix

Queued Nuclei jobs do not have a runner PID or request count. Previously the
DataFrame mixed integer values with empty strings, producing:

```text
ArrowInvalid: Could not convert '' with type str: tried to convert to int64
```

`Runner PID` and `Requests` now use Pandas nullable `Int64` columns. Missing
values remain null instead of becoming empty strings, so PyArrow receives one
consistent type.
