# Campaign Milestone Celebration Reliability

Component: `frontend/components/celebration_reliability.tsx`  
Tests: `frontend/components/celebration_reliability.test.tsx`

---

## Overview

`CampaignMilestoneCelebration` is a React overlay that fires exactly once when a
Stellar/Soroban crowdfund campaign crosses a funding milestone (25 %, 50 %, 75 %,
or 100 %). It is designed for reliability, accessibility, and security.

---

## Props

| Prop | Type | Default | Description |
|---|---|---|---|
| `milestone` | `MilestoneInfo \| null \| undefined` | — | Milestone data. `null`/`undefined` renders nothing. |
| `onDismiss` | `(milestoneId: string) => void` | — | Called once when the overlay is dismissed. |
| `autoDismissMs` | `number` | `5000` | Auto-dismiss delay in ms. Pass `0` to disable. |
| `confettiRenderer` | `() => ReactNode` | built-in | Override the confetti animation. |

### MilestoneInfo shape

```ts
interface MilestoneInfo {
  milestoneId: string;          // unique ID — used for deduplication
  threshold: 25 | 50 | 75 | 100;
  label: string;                // e.g. "50% funded"
  campaignTitle?: string;
}
```

---

## Reliability guarantees

- Celebration fires **exactly once** per `milestoneId` — re-renders with the same
  ID are ignored.
- Auto-dismiss timer is **cleared on unmount** — no setState-after-unmount leaks.
- Manual dismiss cancels the auto-dismiss timer to prevent double `onDismiss` calls.
- Invalid thresholds (anything outside 25/50/75/100) render nothing.

---

## Security

- `label` and `campaignTitle` are passed through `sanitizeMilestoneLabel` before
  render: control characters are stripped, whitespace is collapsed, and the string
  is truncated to `MAX_LABEL_LENGTH` (80 chars).
- No `dangerouslySetInnerHTML` is used anywhere in the component.
- No user-supplied HTML is injected.

---

## Accessibility

- Overlay has `role="dialog"`, `aria-modal="true"`, `aria-live="polite"`, and a
  descriptive `aria-label`.
- Dismiss button has an explicit `aria-label="Dismiss milestone celebration"`.
- Decorative emoji and confetti are `aria-hidden="true"`.
- Animation is disabled when `prefers-reduced-motion: reduce` is set.

---

## Exported helpers (unit-testable)

| Export | Purpose |
|---|---|
| `sanitizeMilestoneLabel(raw)` | Strips control chars, collapses whitespace, truncates. |
| `getMilestoneVisuals(threshold)` | Returns `{ emoji, color, label }` for a threshold. |
| `isValidMilestoneThreshold(value)` | Type-guard for the four supported thresholds. |
| `MAX_LABEL_LENGTH` | `80` — maximum label character count. |
| `DEFAULT_AUTO_DISMISS_MS` | `5000` — default auto-dismiss delay. |
| `MILESTONE_THRESHOLDS` | `[25, 50, 75, 100]` — supported thresholds. |

---

## Usage

```tsx
import CampaignMilestoneCelebration from './celebration_reliability';

<CampaignMilestoneCelebration
  milestone={{
    milestoneId: 'campaign-42-50pct',
    threshold: 50,
    label: '50% funded',
    campaignTitle: 'Solar Farm Project',
  }}
  onDismiss={(id) => console.log('dismissed', id)}
  autoDismissMs={5000}
/>
```

---

## Test coverage

Tests live in `celebration_reliability.test.tsx` and cover:

- Pure helper functions (`sanitizeMilestestoneLabel`, `getMilestoneVisuals`, `isValidMilestoneThreshold`)
- Null/undefined milestone renders nothing
- Valid milestone renders overlay, label, emoji, campaign title
- Invalid threshold renders nothing
- Manual dismiss hides overlay and calls `onDismiss` once
- Auto-dismiss fires after delay; respects `autoDismissMs=0`
- Deduplication: same `milestoneId` never re-triggers
- Timer cleanup on unmount (no post-unmount callbacks)
- Accessibility attributes (`role`, `aria-modal`, `aria-live`, `aria-label`, `aria-hidden`)
- Label sanitization in render (truncation, control char stripping)
- Custom confetti renderer injection
- Exported constants shape and values
