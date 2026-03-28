# Celebration Patterns

A milestone celebration overlay component for the Stellar Raise crowdfunding frontend.

## Overview

`CelebrationPatterns` renders a dismissible overlay when a campaign crosses a funding
milestone. It combines a confetti burst, an SVG progress ring, and a text banner — all
driven by props with no external side effects.

## Component

### `CelebrationPatterns`

```tsx
import CelebrationPatterns from "@/components/celebration_patterns";

<CelebrationPatterns
  progressBps={7500}
  milestones={[
    { thresholdBps: 5000, title: "Halfway There!", message: "50% funded." },
    { thresholdBps: 10000, title: "Goal Reached!", message: "Fully funded!" },
  ]}
  onDismiss={() => console.log("dismissed")}
  autoDismissMs={5000}
/>
```

### Props

| Prop           | Type              | Default | Description                                              |
|----------------|-------------------|---------|----------------------------------------------------------|
| `progressBps`  | `number`          | —       | Current progress in basis points (0–10 000)              |
| `milestones`   | `Milestone[]`     | —       | Ordered list of milestone definitions                    |
| `onDismiss`    | `() => void`      | —       | Called on manual or auto dismiss                         |
| `autoDismissMs`| `number`          | `5000`  | Auto-dismiss delay in ms. `0` disables auto-dismiss      |

### Milestone shape

```ts
interface Milestone {
  thresholdBps: number; // 1–10 000
  title: string;        // max 60 chars
  message: string;      // max 160 chars
}
```

## Pure Helpers

All helpers are exported for unit testing.

### `sanitizeCelebrationText(value, maxLen)`

Strips control characters, normalizes whitespace, and truncates to `maxLen`.
Returns an empty string for non-string or blank input.

### `isValidMilestone(m)`

Type guard. Returns `true` when `thresholdBps` is in `[1, 10 000]` and both
`title` and `message` produce non-empty sanitized strings.

### `resolveTriggeredMilestone(progressBps, milestones)`

Returns the highest-threshold milestone that `progressBps` has reached, or `null`.

### `buildConfettiParticles(count)`

Generates `count` (clamped to `[1, 100]`) confetti particle style objects using
a hardcoded color palette. No user-controlled CSS values.

### `computeProgressRingDashOffset(progressBps, circumference)`

Converts basis-point progress to an SVG `stroke-dashoffset` value.

## Constants

| Constant          | Value  | Description                              |
|-------------------|--------|------------------------------------------|
| `MAX_TITLE_LENGTH`| `60`   | Hard limit for milestone title strings   |
| `MAX_MESSAGE_LENGTH`| `160`| Hard limit for milestone message strings |
| `CONFETTI_COUNT`  | `30`   | Particles per burst                      |
| `AUTO_DISMISS_MS` | `5000` | Default auto-dismiss delay               |
| `BPS_SCALE`       | `10000`| Basis-point scale factor                 |

## Security Notes

- All user-supplied strings are rendered as React text nodes — no `dangerouslySetInnerHTML`.
- Milestone text is sanitized (control characters stripped, length capped) before rendering.
- Invalid milestones (bad threshold, empty text) are silently filtered out.
- Confetti colors are hardcoded constants — no user-controlled CSS injection.
- Animation timers are cleared on unmount to prevent memory leaks.

## Accessibility

- The overlay has `role="status"` and `aria-live="polite"` for screen reader announcements.
- `aria-label` on the overlay includes the milestone title.
- The dismiss button has `aria-label="Dismiss celebration"`.
- Confetti elements are `aria-hidden="true"`.
