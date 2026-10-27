"""Product implementation status, separate from client readiness."""

import streamlit as st

PHASE_STATUS = (
    (
        "0 · Build and quality",
        "Coming Soon",
        "Local checks are available. Hosted CI and live database verification "
        "remain pending; the coverage gate is deferred.",
    ),
    (
        "1 · Security",
        "Not Implemented",
        "Local administrator access exists. The complete authentication, MFA, "
        "API authorization and database isolation phase is not complete.",
    ),
    (
        "2 · ISO workflows",
        "Coming Soon",
        "Existing records are available. Configurable risk methodology, formal "
        "scenario acceptance and remaining specialist workflows are unfinished.",
    ),
    (
        "3 · Architecture and data",
        "Not Implemented",
        "The existing architecture is retained. The full planned data and "
        "deployment changes are outstanding.",
    ),
    (
        "4 · User experience",
        "Coming Soon",
        "Assessment, drawers and risk views have improvements. Full "
        "accessibility, localization and portal work remain outstanding.",
    ),
    (
        "5 · Validation",
        "Coming Soon",
        "Local regression tests are available. Complete database, security and "
        "browser verification remain outstanding.",
    ),
)


def render_availability(compact=False):
    st.markdown("#### Product implementation status")
    st.table([{"Phase": name, "Status": status} for name, status, _ in PHASE_STATUS])
    with st.expander("Delivery details and remaining work"):
        st.caption(
            "Product delivery status, not client certification readiness. Coming "
            "Soon does not promise a delivery date."
        )
        for name, status, detail in PHASE_STATUS:
            st.markdown(f"**{name} — {status}**")
            if not compact:
                st.caption(detail)
