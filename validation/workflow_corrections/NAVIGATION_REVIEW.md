# Navigation overlap correction

Inspected the active Control Assurance, Programme Foundation, Risk Management and Evidence navigation paths, and the workbench JavaScript render function. The inspected paths have one top-level navigation call; Foundation Governance/Discovery, Evidence within Control Assurance and control-detail sections have legitimate nested navigation. Workbench render clears the root before rebuilding; control detail replaces the existing bar rather than appending another.

Confirmed in the installed Streamlit 1.62 frontend: each tab renders a React Aria SelectionIndicator with a 200 ms translate transition, and the tablist has an ::after baseline. SecureScope components.css independently paints an active tab border and a tablist baseline. This creates overlapping decorations, even without a duplicate navigation component.

The correction hides only those native decorative layers and retains SecureScope's fixed active underline. Removed app.py's older pill-tab overrides, including the extra tablist margins. No routing, business data, permissions, or nested navigation removed.

Regression checks: repeated Streamlit AppTest selection leaves one tab container, two destinations, and one active content header. Existing canonical state/callback/context tests remain in place. See navigation-* logs for full test and touched-file formatting/lint results.

Limitations: this is a code/runtime-render-tree finding, not a live browser confirmation of the reported animation. Playwright launch in this environment fails because its Chromium executable is unavailable. No claim of real PostgreSQL or live-app screenshot acceptance is made. The prior evidence-link correction and other bug commits still need their documented live end-to-end acceptance. Other outstanding bug-pass items are not marked complete by this navigation correction.
