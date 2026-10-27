# SecureScope v5.4.3 menu hotfix

This fixes the navigation/visibility regression in the previous UI-hardening build.

## Install over that build

1. Stop SecureScope in its PowerShell window with Ctrl+C.
2. Back up these two files in your installed application folder:
   src/securescope/ui/securescope_sidebar.py
   src/securescope/ui/styles/sidebar.css
3. Copy this ZIP's src folder into your application folder (beside
   start_securescope.ps1). Accept replacement of the two files.
4. Restart with your usual start_securescope.ps1 launcher and refresh the
   browser with Ctrl+F5.

No dependency installation or database change is part of this hotfix.
If your installed source differs from the previous v5.4.3 UI-hardening build,
use the complete Menu_Fix_Windows build in a new folder instead.

## Corrections

- Native st.page_link navigation replaces st.switch_page calls in callbacks.
  Streamlit suppresses callback rerun control flow, so the old callback could
  leave Command Center selected instead of switching the visible page.
- Removed the blanket data-stale visibility rule which could blank sidebar
  controls during reruns.
- Explicit sidebar text/icon/brand colors prevent white-on-white text.
- Page links retain accessible labels and icons in compact mode; the current
  destination has a highlighted container.

## Verification

291 tests passed; four PostgreSQL tests skipped. The new interaction tests
exercise all 12 visible destinations, check unique page hashes and selected
page rendering, and retain links through collapse/expand and dialog dismissal.
The tests send the page-hash event native links use; they do not simulate
browser pointer clicks. Browser pixel verification remains unavailable because
the cloud browser blocks this local preview address.

The changes.patch file is an alternative developer patch against the previous
UI-hardening build; do not apply it after copying the replacement files.
