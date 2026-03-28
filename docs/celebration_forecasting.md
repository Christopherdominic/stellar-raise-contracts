# celebration_forecasting

Milestone celebration and funding-velocity forecasting component for the Stellar Raise crowdfunding dApp.

## Overview

`CelebrationForecasting` tracks campaign progress against four milestone thresholds (25 %, 50 %, 75 %, 100 % of goal) and predicts when each unreached milestone will be hit based on the current contribution velocity.

## Files

| File | Purpose |
|---|---|
| `celebration_forecasting.tsx` | React component + exported pure helpers |
| `celebration_forecasting.test.tsx` | Jest / React Testing Library test suite |
| `docs/celebration_forecasting.md` | This document |

## Component API

```tsx
import CelebrationForecasting from "frontend/components/celebration_forecasting";

<CelebrationForecasting
  totalRaised={500}        // tokens raised so far (≥ 0)
  goal={1000}              // campaign funding goal (> 0)
  campaignStartTime={1711584000}  // Unix timestamp (seconds)
  currentTime={1711670400}        // optional; defaults to Date.now()/1000
/>
```

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `totalRaised` | `number` | yes | Tokens raised so far. Negative / non-finite values are treated as 0. |
| `goal` | `number` | yes | Campaign funding goal. Must be > 0; renders an error message otherwise. |
| `campaignStartTime` | `number` | yes | Unix timestamp (seconds) when the campaign started. Used to compute elapsed time and velocity. |
| `currentTime` | `number` | no | Unix timestamp (seconds) representing "now". Defaults to `Math.floor(Date.now() / 1000)`. |

## Forecasting Algorithm

```
elapsed  = currentTime - campaignStartTime   (clamped to ≥ 0)
velocity = totalRaised / elapsed             (tokens / second; 0 when elapsed = 0)

for each milestone M (25 %, 50 %, 75 %, 100 % of goal):
  if totalRaised >= M.targetAmount → reached = true
  else if velocity > 0             → projectedAt = currentTime + (M.targetAmount - totalRaised) / velocity
  else                             → projectedAt = null  ("ETA unavailable")
```

## Exported Helpers

All pure helpers are exported for independent unit testing.

| Export | Signature | Description |
|---|---|---|
| `sanitize` | `(value: number) => number` | Returns 0 for negative, NaN, or Infinity; otherwise returns the value unchanged. |
| `computeVelocity` | `(totalRaised, elapsedSeconds) => number` | Tokens per second; 0 when elapsed ≤ 0. |
| `buildMilestones` | `(totalRaised, goal, velocity, now) => Milestone[]` | Builds the full milestone array with reached status and ETA. |
| `formatEta` | `(ts: number) => string` | Formats a Unix timestamp as a short locale date+time string. |
| `MILESTONE_FRACTIONS` | `readonly [0.25, 0.5, 0.75, 1.0]` | Milestone thresholds as fractions of goal. |

## Accessibility

- Progress bar uses `role="progressbar"` with `aria-valuenow`, `aria-valuemin`, `aria-valuemax` (WCAG 2.1 SC 4.1.2).
- Celebration banners use `role="status"` so screen readers announce them without stealing focus.
- No user-supplied HTML is rendered; all output is plain text or typed React nodes (no XSS risk).

## Security Notes

- Numeric inputs are sanitised via `sanitize()` before any arithmetic, preventing NaN / Infinity propagation.
- `goal = 0` is detected early and renders an error state instead of dividing by zero.
- No external data is fetched; the component is purely presentational and driven by props.

## Running Tests

```bash
# From the workspace root
npx jest frontend/components/celebration_forecasting.test.tsx --coverage
```

Expected output: all tests pass with ≥ 95 % statement coverage.
