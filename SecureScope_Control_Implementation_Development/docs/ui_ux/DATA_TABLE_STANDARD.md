# SecureScope Data Table Standard

## Goal

A SecureScope table is a decision surface, not a spreadsheet. It should help a consultant locate a record, understand its status, and open the next action quickly.

## When to use a table

Use a table when users need to compare many records using the same attributes, for example:

- assets
- vulnerabilities/findings
- ISO controls
- interested parties
- evidence records
- gaps and treatment actions
- milestones

Do not use a table for a single record, a small set of summary metrics, or a complex object that is easier to review as a detail card.

## Standard anatomy

```text
Table title                                      Row count
Short description / data source

[ Search __________________ ] [ Status ▾ ] [ More filters ▾ ]    [ + Add ]

┌─────────────────────────────────────────────────────────────────────┐
│ Primary identity │ Status │ Owner │ Updated │ Key metric │ Actions │
├─────────────────────────────────────────────────────────────────────┤
│ ...                                                                 │
└─────────────────────────────────────────────────────────────────────┘

Showing 1–25 of 124                                      25 / page  ›
```

Not every table requires every element. The toolbar appears only when users need search/filter/batch actions.

## Column rules

### 1. Primary identity first

The first meaningful column is the stable business identity.

Examples:

- Asset table: **Asset tag** before IP address.
- Control table: **Control ID** then control title.
- Evidence table: **Evidence name** then source.
- Gap table: **Gap / control** then severity/status.

Database IDs should not be visible unless they are meaningful to the user.

### 2. Limit default columns

Target 5–7 visible columns on a normal desktop view. Move low-priority detail into a detail panel, expanded row, or dedicated page.

### 3. Use predictable formatting

- Dates: one application-wide format.
- Boolean values: `Yes / No` or a clear status, not `True / False`.
- Empty values: `—`, not `None`, `NaN`, or blank ambiguity.
- Counts: right aligned when possible.
- Long descriptions: truncate in the table and show full content in detail view.

### 4. Status is visual but readable

Preferred statuses are short text chips such as:

- Active
- Draft
- Approved
- Pending review
- Gap
- Implemented
- Stale

Color supports the text; it never replaces the text.

## Search and filters

Add search when the register commonly exceeds roughly 10–15 records or the user must locate a known item.

Filters should reflect decisions, not every database field. Typical filters:

- status
- severity
- scope
- owner
- source
- asset type
- assessment state

Keep the most-used filters visible. Put uncommon filters under an advanced filter control.

## Sorting

Sortable tables should use sortable column headers for fields such as:

- date
- severity
- status
- owner
- asset tag
- control ID

The current sorted field and direction must stay visible.

## Row actions

Do not put several full-size buttons in every row.

Preferred pattern:

- clicking the identity opens details, or
- one `…` overflow action menu on the right.

Batch actions appear only after one or more rows are selected.

## Density

Default register density should be approximately a 40–44 px row with 13–14 px text. Use taller rows only where two lines of content are intentionally shown.

Security-operation tables can be slightly denser than Programme Foundation tables, but the application should not look like a raw SIEM console unless that is the purpose of the page.

## Empty state

Do not show an empty grid.

Use:

```text
No interested parties yet
SecureScope can suggest starter parties from the organization profile.

[ Review suggestions ]
```

The empty-state action should match the preferred workflow. For Programme Setup, suggestion/discovery actions are preferred over manual `Add` where possible.

## SecureScope-specific table designs

### Asset Management

Recommended default columns:

```text
Asset tag | Type | Criticality | Lifecycle | IP / Address | Wazuh | Last observed
```

Asset tag is visually dominant. Hostname is optional detail. Technical identifiers do not replace the business identity.

### Vulnerabilities

```text
Finding | Severity | Asset tag | Engine | Status | First seen | Last seen
```

Do not create one dashboard card per asset. The table is for investigation after the aggregate dashboard.

### Control Assurance

```text
Control | Applicability | Assessment | Evidence strength | Technical coverage | Updated
```

The row opens the complete assurance view showing documentary, technical, and human evidence.

### Evidence Hub

```text
Evidence | Source | Mapped controls | Validation | Freshness | Owner | Updated
```

### Gap / Treatment

```text
Control / gap | Severity | Owner | Treatment status | Due date | Verification
```

Overdue state should be visible without reading the date manually.

## Streamlit implementation phases

### Phase 1 — built-in dataframe

Use `st.dataframe` for stable sorting, sizing, keyboard behavior, and low dependency risk. Standardize borders, typography, column names, empty states, and page-level filters.

### Phase 2 — reusable register toolbar

Extend `render_register_table()` with optional title, description, search, filters, row count, and standard column configuration.

### Phase 3 — advanced interactive grid only where justified

For Asset Management, Vulnerabilities, and large Evidence registers, evaluate a dedicated grid component only if requirements exceed Streamlit's built-in table capabilities (pinned identity columns, batch actions, persistent user column settings, server-side pagination).

Do not add a grid dependency globally just for visual appearance.

## Review checklist

Before shipping a table, confirm:

- [ ] Is the first column the identity users actually recognize?
- [ ] Are there 7 or fewer default columns where possible?
- [ ] Are database IDs hidden?
- [ ] Are `None`, `NaN`, and raw booleans removed?
- [ ] Is the primary status easy to scan?
- [ ] Is search present when needed?
- [ ] Are filters task-oriented?
- [ ] Is there only one obvious row-open/action pattern?
- [ ] Does the empty state tell the user what to do next?
- [ ] Does the table still work at laptop width?
