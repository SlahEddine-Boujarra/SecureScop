# Known limitations in v5.3.4

- The final visual rendering depends on the Streamlit version installed on the
  Windows host. The project requires `streamlit>=1.49,<2`.
- Browser screenshots could not be captured in the build environment because
  Streamlit is not installed there.
- The section tooltips are presentation enhancements; keyboard users still
  receive the complete tab labels from the DOM.
- This revision does not change application data, scanner behavior,
  remediation behavior, database schema or environment configuration.
