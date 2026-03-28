# celebration_personalization

Personalized milestone celebration banner for the Stellar Raise crowdfunding frontend.

## Overview

`CelebrationPersonalization` renders an accessible, auto-dismissible banner when a campaign crosses a funding milestone (25 %, 50 %, 75 %, or 100 % of goal). Callers can override the message, emoji, and dismiss timing.

## Usage

```tsx
import CelebrationPersonalization from "@/frontend/components/celebration_personalization";

<CelebrationPersonalization
  tier="goal"
  visible={campaignReachedGoal}
  campaignName="Stellar Fund"
  customMessage="We hit our goal!"
  emoji="🎉"
  autoDismissMs={6000}
  onDismiss={() => console.log("dismissed")}
/>
```

## Props

| Prop | Type | Default | Description |
|---|---|---|---|
| `tier` | `MilestoneTier` | — | Milestone tier: `quarter`, `half`, `threeQuarter`, `goal` |
| `visible` | `boolean` | — | Controls banner visibility |
| `customMessage` | `string` | tier label | Override celebration text (max 120 chars) |
| `emoji` | `MilestoneEmoji` | tier default | Must be one of `ALLOWED_EMOJI` |
| `autoDismissMs` | `number` | `5000` | Auto-hide delay in ms; `0` disables auto-dismiss |
| `onDismiss` | `() => void` | — | Callback fired on dismiss (manual or auto) |
| `campaignName` | `string` | — | Prepended to the message for personalisation |

## Milestone Tiers

| Tier | Default label | Default emoji |
|---|---|---|
| `quarter` | 25% funded! | 🚀 |
| `half` | 50% funded! | 🌟 |
| `threeQuarter` | 75% funded! | 🏆 |
| `goal` | Goal reached! | 🎉 |

## Exported Helpers

| Helper | Purpose |
|---|---|
| `sanitizeCelebrationText(candidate, fallback)` | Strips control chars, collapses whitespace, truncates to 120 chars |
| `resolveEmoji(candidate, tier)` | Validates emoji against `ALLOWED_EMOJI`; falls back to tier default |
| `resolveMilestoneMessage(tier, customMessage?, campaignName?)` | Builds the final display string |

## Security

- All user-supplied strings pass through `sanitizeCelebrationText` before rendering.
- Emoji is restricted to `ALLOWED_EMOJI` — arbitrary Unicode is rejected.
- No `dangerouslySetInnerHTML` is used.
- Static inline styles only — no dynamic CSS injection from user input.

## Accessibility

- `role="status"` + `aria-live="polite"` announces milestones to screen readers without interrupting ongoing narration.
- `aria-atomic="true"` ensures the full message is read as a unit.
- The close button carries `aria-label="Dismiss celebration"` for keyboard and assistive-technology users.

## Testing

```bash
# Run tests
npm test -- --testPathPattern=celebration_personalization

# With coverage
npm run test:coverage -- --testPathPattern=celebration_personalization
```

Coverage target: ≥ 95 % (lines, branches, functions, statements).
