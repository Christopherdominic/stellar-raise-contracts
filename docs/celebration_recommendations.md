# celebration_recommendations

Contextual milestone celebration recommendations for the Stellar Raise crowdfunding dApp.

## Overview

`CelebrationRecommendations` generates actionable, phase-aware guidance for campaign creators and contributors based on how far a campaign has progressed toward its funding goal. It complements `celebration_forecasting.tsx` (which shows *when* milestones will be reached) by showing *what to do* at each milestone.

## Files

| File | Purpose |
|---|---|
| `frontend/components/celebration_recommendations.tsx` | React component + exported pure helpers |
| `frontend/components/celebration_recommendations.test.tsx` | Jest / React Testing Library test suite |
| `docs/celebration_recommendations.md` | This document |

## Component API

```tsx
import CelebrationRecommendations from "frontend/components/celebration_recommendations";

<CelebrationRecommendations
  totalRaised={500}   // tokens raised so far (≥ 0)
  goal={1000}         // campaign funding goal (> 0)
  isCreator={true}    // true = creator view, false = contributor view (default: false)
/>
```

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `totalRaised` | `number` | yes | Tokens raised. Negative / non-finite values are treated as 0. |
| `goal` | `number` | yes | Campaign goal. Must be > 0; renders an error message otherwise. |
| `isCreator` | `boolean` | no | Selects creator vs. contributor recommendation set. Defaults to `false`. |

## Campaign Phases

| Phase | Progress range | Example creator recommendation |
|---|---|---|
| `pre_launch` | 0 – 24 % | Share your campaign |
| `early` | 25 – 49 % | Thank your early backers |
| `halfway` | 50 – 74 % | Post a progress update |
| `final_push` | 75 – 99 % | Create urgency |
| `funded` | 100 %+ | Celebrate with your community |

## Exported Helpers

| Export | Signature | Description |
|---|---|---|
| `sanitize` | `(value: number) => number` | Returns 0 for negative, NaN, or Infinity. |
| `derivePhase` | `(progressPct: number) => CampaignPhase` | Maps a progress percentage to a `CampaignPhase`. |
| `getRecommendations` | `(phase, isCreator) => Recommendation[]` | Returns the static recommendation array for a phase and audience. |
| `PHASE_THRESHOLDS` | `{ early: 0.25, halfway: 0.5, finalPush: 0.75, funded: 1.0 }` | Phase boundary constants. |

## Security Notes

- All numeric inputs are sanitised via `sanitize()` before use — no NaN or division-by-zero risk.
- Recommendation strings are static constants — no user input reaches rendered text, eliminating XSS risk.
- `goal = 0` is detected early and renders an error state.

## Accessibility

- Recommendation list uses `role="list"` / `role="listitem"` (WCAG 2.1 SC 1.3.1).
- Decorative emoji icons are wrapped in `aria-hidden="true"`.

## Running Tests

```bash
npx jest frontend/components/celebration_recommendations.test.tsx --coverage
```

Expected: 55 tests pass, 100 % statements / functions / lines, ≥ 94 % branch (the remaining branch is a Jest/Istanbul artefact on the destructured default parameter).
