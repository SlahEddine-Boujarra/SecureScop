# SecureScope v5.3.8.6 — UX Clarity and Table System

## UI clarity

- Removed the tall `Needs attention` panel from the ISO Command Center.
- Expanded programme readiness to the full dashboard width to remove the distorted two-column layout.
- Kept required setup work in the Foundation Work section instead of duplicating it in a second action queue.
- Renamed Command Center actions to task-oriented language: continue foundation, review controls & SoA, review evidence.
- Removed the duplicate five-button `Advanced registers` block from Programme Setup Overview. Formal registers remain available through the persistent Programme Setup navigation.
- Moved `Add site or unit` beside the Sites and organizational units register instead of mixing it with scope-version lifecycle actions.

## Typography

- Added a Windows-first professional UI font stack based on Segoe UI Variable/Segoe UI with system fallbacks.
- Standardized page/section/card/body/button type hierarchy.
- Added font smoothing and consistent UI-control typography.

## Buttons and navigation

- Standardized primary and secondary button height, radius, font weight, focus state, and transitions.
- Removed motion/transform hover behavior from enterprise actions.
- Refined Programme Setup segmented navigation to use a light selected state with visible labels.

## Tables

- Refined default Streamlit dataframe border, header typography, radius, and visual density.
- Added `docs/ui_ux/DATA_TABLE_STANDARD.md` as the implementation contract for the next register/table iteration.
- Added `docs/ui_ux/SECURESCOPE_UI_UX_STANDARD.md` covering typography, action hierarchy, navigation, forms, motion, dashboards, and accessibility.

## Architecture

No scanner, evidence, ISO-assessment, persistence, worker, or control-assurance business logic was removed or changed by this release.
