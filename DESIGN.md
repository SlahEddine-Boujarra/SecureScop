# Design System: SecureScope

## 1. Visual Theme & Atmosphere

A calm, precise enterprise workspace for information security decisions. Use balanced information density, predictable alignment and restrained motion. This is an operational application, not a marketing site. Preserve the seven-section Programme Foundation architecture and all canonical domain ownership.

Existing product requirements override decorative Stitch defaults: equal-height three-column Overview cards are appropriate; forms remain symmetric; no infinite pulse, shimmer, floating elements or staggered page entry. No new framework or business model is introduced.

## 2. Color Palette & Roles

- Canvas Slate (`#F6F8FA`): application background; remove lavender canvas variants.
- Surface White (`#FFFFFF`): cards, forms and navigation surfaces.
- Subtle Slate (`#F1F5F9`): table headers and secondary surfaces.
- Ink Slate (`#172B3A`): primary text.
- Muted Slate (`#526174`): secondary text and metadata; readable on white.
- Structure Slate (`#DCE3EB`): borders; stronger structural border `#B8C4D1` and input border `#7C8DA3`.
- Assurance Teal (`#00685F`): the single interaction accent; hover `#00574F`, selected background `#E8F3F1`.
- Success (`#067647` on `#ECFDF3`), Warning (`#975A16` on `#FFFAEB`), Danger (`#B42318` on `#FEF3F2`), Information (`#175CD3` on `#EFF8FF`): semantic states, always accompanied by text.

Existing risk-matrix scores, thresholds and color bands remain authoritative and are not redesigned by these interaction colors. No color alone implies compliance.

## 3. Typography Rules

Use an offline-safe sans-serif stack: Segoe UI Variable Text, Segoe UI, system-ui, sans-serif. Use Cascadia Code or Consolas for code. These fit the Windows deployment without requiring a downloaded font. Preserve the Material icon font used by Streamlit.

Body: 14px, line height 1.5. Table values: 13px, line height 1.5. Metadata: 12px. Page titles: responsive 24–28px, weight 650. Section titles: 17–20px. KPI values: 26px. Hierarchy comes from weight, position and spacing. Long identities and names wrap instead of becoming clipped.

## 4. Component Stylings

- Buttons: 44px main/touch target, 8px radius, flat fill. Teal primary, bordered white secondary, restrained text action. Disabled controls are neutral and remain readable. Do not recolor document text through global button rules.
- Navigation: one shared native icon-and-label tab component, white surface, bottom border, teal selected text and one fixed 2px underline. Keep native keyboard behavior and overflow controls. Do not paint a second animated selection indicator.
- Cards: 10px radius, 1px structural border, at most a subtle shadow. Overview cards share hierarchy, metrics and bottom action area. Avoid nested decorative cards.
- Tables: subtle slate headers, readable values, compact status badges, restrained hover. Wide tables scroll inside their own shell; the page must not overflow. Row actions retain existing dispatch and permissions.
- Forms: labels above fields, 12px between related controls, 20px between sections. White fields with a visible border; use accent focus indication. Visible Save actions call existing handlers. Keep submission, review and approval distinct.
- Status badges: shared display labels and semantic tones. No new persisted status values. Badge text remains understandable without color.
- Identity: shared escaped identity chip, never an unintended mailto link.
- Empty states: short title, explanation and existing main action; no empty pagination.
- Feedback: operation-specific messages preserved across reruns by existing session notices. Do not manufacture successful outcomes.

## 5. Layout Principles

Maximum main width 1440px; desktop page padding 28–36px and compact responsive padding. Keep the selected client, engagement and scope visible. Use 4/8/12/16/24/32px spacing tokens. A meaningful panel is visible; optional audit or diagnostic detail may expand.

Use shared components rather than page-specific palette copies. Custom Streamlit shadow components load the same token stylesheet as native pages. Keep one authoritative light-sidebar stylesheet. Compatibility styles load before current shared styles.

## 6. Motion & Interaction

No layout or navigation animation on rerun. No infinite motion. Short color/background feedback is sufficient; respect prefers-reduced-motion. Use stable widget and component identities. Investigate duplicate mounting before hiding anything. Optional drawers and dialogs remain existing interactions; their save and permission logic is unchanged.

## 7. Responsive & Accessibility Rules

Below 768px, ordinary card/form grids stack. Calendar's seven-day geometry remains a bounded calendar, and risk matrices remain bounded matrices. Wide editable grids keep contained horizontal scroll. Do not force whole-page horizontal overflow. Main actions wrap, touch targets are at least 44px, labels remain visible and focus is clear.

Check computed color and -webkit-text-fill-color, including nested sidebar text. Test default, hover, focus and disabled states. Preserve native accessible widgets and meaningful icons; hide decorative icons from assistive output.

## 8. Anti-Patterns

No purple/neon interaction palette, gradients, giant hero banners, excess shadows, decorative animation, fake metrics, fake screenshots, hidden basic workflow state or inconsistent Save bars. No duplicate canonical record system. No migration or business-rule changes during this pass. Preserve all methodological disclaimers.

## 9. Stitch Screen Prompt

Design the supplied SecureScope screen using this document. Preserve all visible fields, actions, workflow steps, statuses and domain ownership. Use restrained teal on slate and white, readable compact tables, shared native-style icon tabs, visible workflow state, and consistent Save actions. Do not invent sample results or capabilities. Mark prototype data as illustrative. The result must be practical to implement through the existing Streamlit components and their CSS, including narrow-screen behavior.
