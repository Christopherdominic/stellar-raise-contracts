# MilestoneCelebration

Reusable celebration overlay shown when a campaign milestone is reached.

## Usage

```tsx
<MilestoneCelebration
  visible={goalReached}
  label="50% funded!"
  tier="gold"
  ctaLabel="Share"
  onCta={handleShare}
  onDismiss={() => setGoalReached(false)}
/>
```

## Props

| Prop | Type | Default | Description |
|---|---|---|---|
| `visible` | `boolean` | required | Controls overlay visibility |
| `label` | `string` | required | Milestone description, e.g. "50% funded!" |
| `tier` | `MilestoneTier` | `"gold"` | Visual theme: `bronze`, `silver`, `gold`, `platinum` |
| `emoji` | `string` | tier default | Override the burst emoji |
| `autoDismiss` | `boolean` | `true` | Auto-hide after `duration` ms |
| `duration` | `number` | `4000` | Auto-dismiss delay in ms |
| `onDismiss` | `() => void` | — | Called on dismiss (button or auto) |
| `ctaLabel` | `string` | — | Optional CTA button label |
| `onCta` | `() => void` | — | Called when CTA is clicked |
| `className` | `string` | — | Extra CSS class on root element |

## Security assumptions

1. `label` and `ctaLabel` are rendered as React text nodes — no `innerHTML` path.
2. Callbacks are caller-supplied; this component never submits data or calls external services.
3. The component does not read or write `localStorage` or cookies.
4. Auto-dismiss timer is cleared on unmount to prevent state updates on unmounted components.

## Running tests

```bash
npx jest celebration_reusability --no-coverage
```
