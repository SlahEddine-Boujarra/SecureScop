# SecureScope UI/UX Standard

## Purpose

SecureScope is an ISO/IEC 27001 assurance application used by consultants and technical reviewers. The interface must make the next decision obvious without turning the application into a collection of forms, dashboards, or scanner screens.

The UI follows five product rules:

1. **One page, one purpose.** Every page has one primary task.
2. **One primary action per section.** Secondary actions support the task but never compete visually.
3. **Review before edit.** Show the current state first; open forms only when information must be created or changed.
4. **Progressive disclosure.** Summary first, register second, detail/editor last.
5. **Evidence is not compliance.** Technical observations can support an assessment but never visually imply automatic ISO certification.

## Typography

SecureScope uses a native Windows-first professional font stack:

```css
font-family: "Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", Inter,
             system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
```

Why this stack:

- Segoe UI Variable is designed for modern Windows interfaces and remains highly readable at small UI sizes.
- Native/system fallbacks avoid a CDN dependency and keep the Windows release usable offline.
- Inter remains a compatible fallback when installed.

### Type ramp

| Role | Size | Weight | Use |
|---|---:|---:|---|
| Page title | 28–32 px | 650 | One per page |
| Section title | 20–24 px | 650 | Major page regions |
| Card title | 16 px | 600–650 | Panels and tables |
| Body | 14 px | 400 | Default application copy |
| Button | 14 px | 600 | Actions |
| Label | 12–13 px | 600 | Form labels, table headers |
| Caption/meta | 12 px | 400 | Secondary information |

Use sentence case. Avoid all-uppercase labels except very short security severity or protocol abbreviations.

## Page anatomy

Every feature page should follow this order when applicable:

```text
Page title + concise purpose                        [Primary action]

Context / status summary

Primary workspace or register

Secondary information

Advanced / destructive actions
```

Do not put several unrelated primary buttons in the page header.

## Action hierarchy

### Primary

Use for the single next action that advances the current workflow.

Examples:

- Continue programme foundation
- Create scope version
- Start scan
- Save assessment
- Approve reviewed proposal

### Secondary

Use for useful actions that do not define the current workflow.

Examples:

- Approve latest scope version
- Add site or unit
- Export
- Review evidence

### Tertiary / overflow

Use links, popovers, or low-emphasis buttons for rare actions.

Examples:

- Download raw result
- View history
- Duplicate
- Archive

### Destructive

Delete, revoke, reset, and irreversible actions must be isolated from the primary action group and require explicit confirmation.

## Navigation

Navigation is for destinations, not actions.

Do not duplicate the same destinations as tabs, segmented controls, and button grids on one screen. Programme Setup uses the top segmented navigation for formal registers. Its overview should therefore guide the user to Discovery, not repeat five register buttons underneath.

Labels must remain visible. Icons can support recognition but must not be the only clue for important destinations.

## Forms

Forms are an exception path, not the main product experience.

- Use a visible border/background for every input.
- Group related fields into short sections.
- Prefer select/multiselect/checkbox controls when the vocabulary is known.
- Allow `Unknown` where the organization genuinely does not know the answer.
- Prefer dialogs for small edits and dedicated pages for multi-step workflows.
- Do not display more than one strong submit action.
- Do not ask the consultant to re-enter data SecureScope already knows from organization facts, imports, assets, or technical discovery.

## Motion and transitions

SecureScope is an enterprise assurance product, so motion should communicate state rather than decorate it.

- Interaction transitions: 120–160 ms.
- No bouncing, scaling, or moving buttons on hover.
- Use color, border, and shadow changes for hover/focus.
- Preserve layout position during state changes to avoid confusing the reviewer.
- Use toast notifications for successful background-safe actions.
- Use inline error messages next to actions that failed.

## Dashboard rules

Dashboard cards must answer a decision question.

Good:

- Foundation progress
- Controls assessed
- Open control gaps
- Evidence coverage
- Technical assurance coverage

Avoid decorative analytics without a stored historical source.

Do not use a tall `Needs attention` card beside a short dashboard card. Pending work belongs in Foundation Work, programme status, or a compact task summary that does not distort the grid.

## Accessibility

- Maintain at least 4.5:1 contrast for standard text.
- Keep visible focus states.
- Do not communicate status only through color.
- Keep navigation labels visible.
- Use sentence-case labels and concise button verbs.
- Do not put essential information only in hover tooltips.

## Implementation rule

Reusable visual behavior belongs in `src/securescope/ui/components/` or `securescope_ui_theme.py`. Avoid page-specific CSS unless there is no reusable alternative.
