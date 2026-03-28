# CelebrationPerformance

A performance-optimised milestone celebration overlay for the Stellar Raise crowdfunding dApp. Renders when a campaign milestone is reached and dismisses via user action, backdrop click, Escape key, or an optional auto-dismiss timer.

---

## Overview

`CelebrationPerformance` is designed to minimise unnecessary work:

- Style objects are module-level constants — never re-allocated on render.
- Callbacks are memoised with `useCallback` so child elements never re-render due to a new function reference.
- Tier derivation and accent colour lookups are wrapped in `useMemo`.
- The overlay is only mounted when `milestoneReached` is `true` and the user has not yet dismissed it.
- The auto-dismiss timer ref is always cleared on unmount and on manual dismiss to prevent state updates on unmounted components.

---

## Props

| Prop | Type | Default | Description |
|---|---|---|---|
| `milestoneReached` | `boolean` | — | When `true` the overlay is shown. Flipping `false → true` resets any previous dismissal. |
| `milestoneLabel` | `string` | — | Human-readable label, e.g. `"50% Funded"`. Rendered as plain text. |
| `milestonePercent` | `number` | — | Numeric percentage (0–100) used to derive the tier. Clamped internally. |
| `campaignName` | `string` | — | Campaign display name. Rendered as plain text. |
| `onDismiss` | `() => void` | — | Called when the overlay is dismissed (button, backdrop, Escape, or auto-dismiss). |
| `tier` | `PerformanceTier` | auto-derived | Override the auto-derived tier. |
| `autoDismissMs` | `number` | `0` | Auto-dismiss after this many milliseconds. `0` or negative disables the timer. |
| `className` | `string` | `""` | Extra CSS class names forwarded to the root element. |

### PerformanceTier

| Value | Percent range | Emoji | Accent |
|---|---|---|---|
| `bronze` | < 25 | 🥉 | `#CD7F32` |
| `silver` | 25–49 | 🥈 | `#A8A9AD` |
| `gold` | 50–74 | 🥇 | `#FFD700` |
| `platinum` | ≥ 75 | 🏆 | `#E5E4E2` |

---

## Exported helpers

All pure helpers are exported for independent unit testing.

| Helper | Signature | Description |
|---|---|---|
| `derivePerformanceTier` | `(percent: number) => PerformanceTier` | Derives tier from a percentage. |
| `performanceTierEmoji` | `(tier: PerformanceTier) => string` | Returns the emoji badge for a tier. |
| `performanceTierAccent` | `(tier: PerformanceTier) => string` | Returns the hex accent colour for a tier. |
| `clampMilestonePercent` | `(value: number) => number` | Clamps a value to [0, 100]; non-finite → 0. |

---

## Usage

### Basic

```tsx
import CelebrationPerformance from './celebration_performance';

function CampaignView({ funded, goal, campaignName }) {
  const [show, setShow] = React.useState(false);

  React.useEffect(() => {
    if (funded >= goal) setShow(true);
  }, [funded, goal]);

  return (
    <CelebrationPerformance
      milestoneReached={show}
      milestoneLabel="Goal Reached"
      milestonePercent={100}
      campaignName={campaignName}
      onDismiss={() => setShow(false)}
    />
  );
}
```

### With auto-dismiss

```tsx
<CelebrationPerformance
  milestoneReached={reached}
  milestoneLabel="50% Funded"
  milestonePercent={50}
  campaignName="Solar Farm"
  autoDismissMs={5000}
  onDismiss={() => setReached(false)}
/>
```

### With tier override

```tsx
<CelebrationPerformance
  milestoneReached={reached}
  milestoneLabel="First Backer"
  milestonePercent={5}
  campaignName="My Campaign"
  tier="gold"
  onDismiss={handleDismiss}
/>
```

---

## Security

- `milestoneLabel` and `campaignName` are rendered as React text nodes — no `dangerouslySetInnerHTML` is used, eliminating XSS risk.
- `onDismiss` is a caller-supplied callback; the component has no side-effects beyond local state transitions.
- No network requests are made inside this component.

## Accessibility

- Root element carries `role="dialog"` and `aria-modal="true"`.
- `aria-label` is derived from `milestoneLabel` for screen-reader context.
- Dismiss button receives focus on mount (keyboard-first UX).
- Escape key dismisses the overlay (WCAG 2.1 SC 2.1.2).
- Backdrop click dismisses the overlay for pointer users.
- Decorative emoji carries `aria-hidden="true"`.

## Testing

```bash
npm test -- --testPathPattern=celebration_performance --coverage
```

Expected: all tests pass, ≥ 95% statement/branch/function/line coverage.
