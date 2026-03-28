# Frontend Header Responsive Styling & Optimization

## Overview

The `FrontendHeaderResponsive` is a core UI navigation component for the Stellar Raise platform. It provides a highly optimized, fully responsive header including a brand logo, navigation links, and a dynamic wallet connection status indicator with smart-contract-specific edge-case handling.

The component supports four distinct wallet badge states — **Disconnected**, **Connecting**, **Connected**, and **Pending** — covering the full lifecycle of a Stellar wallet interaction with a smart contract.

## Usage

```tsx
import { FrontendHeaderResponsive } from '../components/frontend_header_responsive';

function AppLayout() {
  const [walletConnected, setWalletConnected] = useState(false);
  const [isPending, setIsPending] = useState(false);

  return (
    <>
      <FrontendHeaderResponsive
        isWalletConnected={walletConnected}
        walletAddress="GABC...XYZ"
        networkName="testnet"
        isTransactionPending={isPending}
        onToggleMenu={(isOpen) => console.log('Menu open:', isOpen)}
      />
      <main>{/* Page content */}</main>
    </>
  );
}
```

## Props Reference

| Prop | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `isWalletConnected` | `boolean` | Yes | — | Controls the wallet badge state (Connected vs Disconnected). |
| `onToggleMenu` | `(isOpen: boolean) => void` | No | — | Callback fired when the mobile hamburger menu is toggled. |
| `walletAddress` | `string` | No | — | Stellar G-address (56 chars). Displayed truncated as `G...XXXX` when connected. Invalid addresses are silently ignored. |
| `networkName` | `string` | No | — | Stellar network name. Validated against an allowlist. Unknown values render as "Unknown Network". |
| `isTransactionPending` | `boolean` | No | `false` | When `true`, shows an orange "Pending..." badge with `aria-busy="true"`. Overrides all other badge states. |
| `isWalletConnecting` | `boolean` | No | `false` | When `true`, shows a blue "Connecting..." badge. Overrides disconnected state. |

## Smart Contract Edge Cases

### Wallet Address Truncation

Long Stellar addresses are truncated to `G...XXXX` format for display. Only valid 56-character G-addresses are displayed; invalid values are silently ignored.

```tsx
// Valid 56-char address shows "G...ABCD"
<FrontendHeaderResponsive isWalletConnected={true} walletAddress={"G" + "A".repeat(51) + "ABCD"} />

// Invalid address - no address shown
<FrontendHeaderResponsive isWalletConnected={true} walletAddress="GABC" />
```

### Network Validation

The `networkName` prop is validated against an allowlist before rendering. Unknown values fall back to "Unknown Network", preventing arbitrary string injection.

Supported networks: `mainnet`, `testnet`, `futurenet`, `localnet`.

```tsx
// Known network shows "testnet"
<FrontendHeaderResponsive isWalletConnected={true} networkName="testnet" />

// Unknown network shows "Unknown Network"
<FrontendHeaderResponsive isWalletConnected={true} networkName="devnet" />
```

### Transaction Pending State

When a smart contract transaction is in-flight, the badge shows "Pending..." with an orange colour scheme and `aria-busy="true"`. This state has the highest priority and overrides all other badge states.

```tsx
<FrontendHeaderResponsive isWalletConnected={true} isTransactionPending={true} />
// Shows orange "Pending..." badge, aria-busy="true"
```

### Wallet Connecting State

An intermediate state between disconnected and connected, shown while the wallet handshake is in progress.

```tsx
<FrontendHeaderResponsive isWalletConnected={false} isWalletConnecting={true} />
// Shows blue "Connecting..." badge
```

### Badge State Priority

`pending` > `connecting` > `connected` > `disconnected`

## Exported Helpers

### `truncateWalletAddress(address)`

Truncates a Stellar address to `G...XXXX` format. Returns `null` for invalid/absent addresses.

### `resolveNetworkLabel(network)`

Validates a network name against the allowlist. Returns the name if valid, `"Unknown Network"` if unrecognised, or `null` if absent.

### `SUPPORTED_NETWORKS`

Readonly tuple: `['mainnet', 'testnet', 'futurenet', 'localnet']`.

## Gas Efficiency Optimizations

- **useCallback**: `handleToggleMenu` is memoized to prevent recreation across re-renders.
- **useMemo**: `navLinks`, `displayAddress`, `displayNetwork`, and `walletBadgeState` are all memoized.
- **Direct CSS styling**: Responsive breakpoints handled via CSS classes, no JS resize listeners.

## Security

- No user-supplied HTML is injected into the DOM; all dynamic content derives from typed props.
- `walletAddress` is truncated before rendering; the full key is never displayed verbatim.
- `networkName` is validated against an allowlist; arbitrary strings render as "Unknown Network".
- `onToggleMenu` is invoked inside the functional `setState` updater, guaranteeing stale-closure safety.
- Link `href` values are hardcoded constants; no user input reaches anchor attributes.

## Testing

Tests are in `frontend_header_responsive.test.tsx` covering 12 describe groups and 80 test cases:

1. Rendering
2. Wallet Status Badge - Basic States
3. Mobile Menu Toggle - State
4. onToggleMenu Callback
5. Accessibility Attributes
6. Edge Cases - Rapid Toggles
7. Edge Cases - Wallet Address Truncation
8. Edge Cases - Network Label Validation
9. Edge Cases - Transaction Pending State
10. Edge Cases - Wallet Connecting State
11. Pure Helper - `truncateWalletAddress`
12. Pure Helper - `resolveNetworkLabel`
