# v5.4.1 — Assurance Experience

Built from the supplied v5.4.0 archive, preserving its services and migrations.

The control register now resolves row-selection events against the active
workspace's current rows before opening a detail panel. A callback selects the
assessment tab and primes its control selector before widget instantiation.
Forms include workspace and profile identity, so a draft cannot populate a
different control's form.

Stateful Streamlit tabs render only their active section. Navigation registries
live in session state instead of a module-global dictionary. The table's JS/CSS
are packaged assets; user and database values remain structured data inserted
with `textContent`. The table adds sorting, stable search/paging state, keyboard
activation, explicit status tones and filtered CSV export.

The following presentation distinctions are preserved:

| Stored status | Display |
| --- | --- |
| Implemented and effective | Implemented |
| Implemented but not verified | Verification Pending |
| Target achieved | Target Achieved |
| Accepted residual risk | Accepted Risk |
| Insufficient evidence | Insufficient Evidence |

`list_control_overview` adds `current_evidence_count` alongside the existing
approved-evidence count. It requires a validated record, an approved mapping,
a Current/Approaching expiration freshness state, and no elapsed expiry time.
The dashboard counts covered controls from that same applicable control set.
No stored assessment or evidence is rewritten by these display changes.

Framework references used for implementation:

- [Streamlit stateful tabs](https://docs.streamlit.io/develop/api-reference/layout/st.tabs)
- [Streamlit Components v2](https://docs.streamlit.io/develop/api-reference/custom-components/st.components.v2.component)
- [Streamlit page navigation](https://docs.streamlit.io/develop/api-reference/navigation/st.page)

The runtime APIs were also inspected in the installed Streamlit 1.62.0 package.
