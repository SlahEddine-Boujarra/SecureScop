# Programme Setup Interaction Map

## Goal

Programme Setup should feel like a guided assurance workspace rather than a collection of CRUD forms. The user prepares information once in Discovery, reviews formal records in the ISO registers, and uses manual entry only as an exception path.

## Navigation versus actions

The top Programme Setup segmented control is the only destination navigation:

```text
Overview | Discovery | Engagement | Context | Interested Parties | ISMS Scope | Roles & RACI
```

Buttons inside a page perform work. They must not duplicate these destinations unless they explicitly transition from preparation to a formal register, for example `Open Context register`.

## Screen-by-screen workflow

### Overview

Purpose: understand foundation state and decide what to do next.

Primary action: `Continue discovery`.

The foundation checklist is a decision table, not a second navigation system. It shows requirement, state, owning section, and next action text.

### Discovery

Purpose: capture organization facts once and prepare ISO foundation proposals.

Flow:

```text
Organization profile
        ↓
Foundation preparation status
        ↓
Context suggestions | Interested parties | Scope composer
        ↓
Batch review / Create draft
        ↓
Formal register
```

Only one discovery task is visible at a time. Context and interested-party suggestions are batch reviewed instead of placing an action button on every card.

### Engagement

Purpose: manage the active certification cycle and its delivery milestones.

Primary action: `Add milestone`.

Creating another engagement is an administrative action and lives in a collapsed administration area.

### Context

Purpose: review formal Clause 4.1 records.

Primary action: `Review suggestions`.

Secondary action: `Add manually`.

Climate-change determination is a separate versioned decision and uses a secondary local action.

### Interested Parties

Purpose: maintain formal Clause 4.2 stakeholders and applicable requirements.

Primary action: `Review suggestions`.

Secondary action: `Add manually`.

Requirement creation is subordinate to the selected party and therefore remains secondary.

### ISMS Scope

Purpose: control scope drafting, review, and approval.

Primary action: `Edit scope version` or `Create scope version`.

Secondary preparation action: `Prepare from Discovery`.

Approval is isolated in its own decision card and must remain explicitly human.

### Roles & RACI

Purpose: assign formal ISMS responsibilities.

Primary action: `Assign responsibility`.

Engagement-team roles are supporting administration and appear after the RACI register with a secondary action.

## Register design applied

Programme registers use these rules:

- Business identity is the first column.
- Default tables target 5–7 columns.
- `None`, `NaN`, and raw booleans are normalized to `—` and `Yes/No`.
- Search/filter controls are shown only where users need them.
- Empty states tell the user the preferred next step.
- Tables do not contain repeated full-size row buttons.

## Automation boundary

Discovery can suggest or compose records, but it never silently approves ISO decisions. The flow remains:

```text
Facts / technical discovery / documents
                ↓
             Proposal
                ↓
           Human review
                ↓
          Formal ISO record
```
