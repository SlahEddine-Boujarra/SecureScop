---
name: SecureScope Assurance
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#3d4947'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#6d7a77'
  outline-variant: '#bcc9c6'
  surface-tint: '#006a61'
  primary: '#00685f'
  on-primary: '#ffffff'
  primary-container: '#008378'
  on-primary-container: '#f4fffc'
  inverse-primary: '#6bd8cb'
  secondary: '#565e74'
  on-secondary: '#ffffff'
  secondary-container: '#dae2fd'
  on-secondary-container: '#5c647a'
  tertiary: '#595c5e'
  on-tertiary: '#ffffff'
  tertiary-container: '#727577'
  on-tertiary-container: '#fbfdff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#89f5e7'
  primary-fixed-dim: '#6bd8cb'
  on-primary-fixed: '#00201d'
  on-primary-fixed-variant: '#005049'
  secondary-fixed: '#dae2fd'
  secondary-fixed-dim: '#bec6e0'
  on-secondary-fixed: '#131b2e'
  on-secondary-fixed-variant: '#3f465c'
  tertiary-fixed: '#e0e3e5'
  tertiary-fixed-dim: '#c4c7c9'
  on-tertiary-fixed: '#191c1e'
  on-tertiary-fixed-variant: '#444749'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  display-md:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.01em
  title-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  title-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '500'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  table-cell:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  container-max: 1440px
  gutter: 24px
  margin-mobile: 16px
  margin-desktop: 32px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 24px
---

## Brand & Style
The design system is engineered for high-stakes enterprise cybersecurity environments. The brand personality is rooted in **precision, transparency, and clinical efficiency**. It must evoke a sense of absolute control and unwavering reliability, transforming complex ISO 27001 compliance data into actionable clarity.

The visual style is **Corporate Modern with a Focus on Information Density**. It prioritizes utilitarian layouts over decorative elements. The interface uses a clean, systematic approach characterized by ample whitespace, rigid grid alignment, and a sophisticated "Assurance-first" hierarchy. By avoiding trends like glassmorphism or heavy gradients, the design system maintains a timeless, institutional authority suitable for C-suite reporting and technical audits.

## Colors
The palette is divided into functional roles to facilitate rapid scanning of security statuses:

- **Primary (Teal):** Used for primary actions, focus states, and active navigation indicators. It provides a modern, professional energy without the aggression of pure blue.
- **Secondary (Navy):** Reserved for high-importance "Assurance Cards," sidebars, and headers to anchor the UI and provide structural contrast.
- **Neutral Surface:** The application background is a clean white, with surfaces using a scale of cool grays to define depth.
- **Semantic Logic:** 
    - **Green:** Compliance met, low risk.
    - **Amber:** Pending evidence, medium risk.
    - **Red:** Non-conformity, critical vulnerability.
- **KPI Backgrounds:** Use muted, low-saturation versions of the semantic colors (10% opacity) for background fills on dashboard widgets to maintain readability.

## Typography
The system uses **Inter** exclusively to ensure maximum legibility across dense data tables and technical documentation. 

- **Hierarchy:** Use `display-md` for main page titles. Section headers within dashboards should utilize `title-md`.
- **Data Density:** `body-md` is the standard for most interface text. For data-heavy tables and property panels, drop to `table-cell` to maximize information visibility without sacrificing readability.
- **Labels:** Use `label-caps` for table headers and small metadata tags to differentiate them from interactive body text.
- **Weight:** Reserve 600 weight for headlines and 500 for sub-headers. Standard body text should always be 400.

## Layout & Spacing
The layout follows a **12-column fluid grid** system optimized for widescreen enterprise monitors while maintaining responsiveness.

- **Grid Logic:** Use a 24px gutter between columns. On desktop, the main content area should have a maximum width of 1440px, centered in the viewport.
- **Vertical Rhythm:** A base 4px/8px rule governs all spacing. Use `stack-md` (16px) for spacing between related components and `stack-lg` (24px) for spacing between major sections or cards.
- **Responsive Behavior:** 
    - **Desktop (1024px+):** Full 12-column layout.
    - **Tablet (768px - 1023px):** Transition to an 8-column layout; sidebars may collapse into icons.
    - **Mobile (Under 768px):** Single-column stack with 16px horizontal margins.

## Elevation & Depth
Elevation in this design system is conveyed through **Tonal Layering and Low-Contrast Outlines** rather than dramatic shadows.

- **Surfaces:** Use `#FFFFFF` for the primary work surface. Use `#F8FAFC` (Slate 50) for the application background to create a subtle distinction for card elements.
- **Borders:** Every card and container must have a 1px solid border in `#E2E8F0`. 
- **Shadows:** Use a single "Restrained Shadow" for floating elements like modals or dropdowns: `0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)`. 
- **Active State:** To indicate an active or focused card, increase the border weight to 2px using the primary teal color, rather than increasing shadow depth.

## Shapes
The shape language balances modern approachability with professional structure.

- **Standard Cards:** Use `rounded-lg` (10px) to give components a soft but contained appearance.
- **Inputs & Buttons:** Use `rounded-md` (6px) to maintain a slightly sharper, more technical feel for interactive elements.
- **Status Chips:** Use a full pill shape (100px) to distinguish them from clickable buttons or static cards.

## Components
Consistent implementation of these components ensures the system feels cohesive:

- **Assurance Cards:** High-priority cards (like Risk Summary) should have a Navy (`#0F172A`) header or left-border accent.
- **Buttons:**
    - **Primary:** Solid Teal (`#0D9488`) with white text.
    - **Secondary:** White fill with Slate border and Navy text.
    - **Ghost:** No fill, Teal text, for low-priority actions.
- **Status Chips:** 
    - Text must be high-contrast against muted background fills (e.g., Dark Green text on 10% Green background).
    - Include a small 6px circle icon inside the chip to assist color-blind users.
- **Input Fields:** 1px solid border (`#CBD5E1`). On focus, transition border to Teal with a 2px outer "halo" at 20% opacity.
- **Tables:** No vertical borders. Use 1px horizontal dividers. Zebra striping is permitted for tables exceeding 10 rows using `#F8FAFC`.
- **KPI Widgets:** Large numerical values in `display-md`, paired with a `label-caps` descriptor. Use the muted pastel background logic for the entire widget container.