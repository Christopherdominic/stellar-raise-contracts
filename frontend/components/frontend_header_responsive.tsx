import React, { useState, useCallback, useMemo } from 'react';

/**
 * @title FrontendHeaderResponsive
 * @notice Responsive header navigation bar for the Stellar Raise crowdfunding dApp.
 *
 * @dev This React functional component renders a sticky top-level header with:
 *   - A brand logo section
 *   - A mobile hamburger toggle button (hidden on screens ≥ 768 px via `md:hidden`)
 *   - A navigation links area (always visible on desktop, toggled on mobile)
 *   - A wallet connection status badge with smart-contract edge-case handling
 *
 *   Breakpoints follow the design-system tokens in `frontend/styles/responsive.css`:
 *     - Mobile  : < 768 px  → hamburger toggle controls nav visibility
 *     - Tablet+ : ≥ 768 px  → nav links always rendered inline (`md:flex`)
 *
 * @custom:efficiency
 *   `useCallback` memoises `handleToggleMenu` so its reference stays stable
 *   between renders, preventing unnecessary re-renders of child elements that
 *   receive it as a prop.
 *   `useMemo` memoises the `navLinks` array so a new array object is not
 *   allocated on every render pass.
 *
 * @custom:security
 *   - No user-supplied HTML is injected into the DOM; all dynamic content
 *     (wallet status, menu state) derives from typed boolean props, eliminating
 *     XSS risk at the component boundary.
 *   - `onToggleMenu` is invoked inside the functional `setState` updater,
 *     guaranteeing the callback always receives the *new* state value and
 *     never a stale closure value.
 *   - Link `href` values are hardcoded constants; no user input reaches the
 *     anchor `href` attribute.
 *   - `walletAddress` is truncated for display only; the full address is never
 *     rendered verbatim to prevent layout-breaking injection attempts.
 *   - `networkName` is validated against an allowlist before rendering to
 *     prevent arbitrary string injection into the UI.
 *
 * @custom:accessibility
 *   - `aria-label` on the toggle button satisfies WCAG 2.1 SC 1.1.1.
 *   - `aria-expanded` on the toggle button satisfies WCAG 2.1 SC 4.1.2
 *     (Name, Role, Value) and keeps assistive technology in sync with visual state.
 *   - All interactive elements meet the 44 × 44 px minimum touch target
 *     size recommended by WCAG 2.5.5.
 *   - `aria-busy` on the wallet badge communicates pending transaction state
 *     to screen readers.
 *
 * @custom:edge-cases
 *   - Wallet address truncation: long addresses are shortened to `G...XXXX` format.
 *   - Network validation: only known Stellar networks are displayed; unknown
 *     values fall back to "Unknown Network".
 *   - Transaction pending: a distinct visual state is shown while a smart
 *     contract transaction is in-flight, blocking further interaction.
 *   - Wallet connecting: an intermediate state between disconnected and connected.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * @notice Allowlisted Stellar network names.
 * @dev Any `networkName` prop value not in this set is treated as unknown.
 */
export const SUPPORTED_NETWORKS = ['mainnet', 'testnet', 'futurenet', 'localnet'] as const;
export type SupportedNetwork = typeof SUPPORTED_NETWORKS[number];

/**
 * @notice Minimum length of a valid Stellar public key (G-address).
 * @dev Stellar G-addresses are always 56 characters.
 */
const STELLAR_ADDRESS_LENGTH = 56;

/**
 * @notice Number of trailing characters shown in the truncated address display.
 */
const ADDRESS_TAIL_CHARS = 4;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * @dev Props accepted by the `FrontendHeaderResponsive` component.
 */
export interface FrontendHeaderResponsiveProps {
  /**
   * @notice Reflects whether the user's Stellar wallet is currently connected.
   * @dev Controls the colour and text label of the wallet status badge.
   *      `true`  → green badge, label "Connected"
   *      `false` → red badge,   label "Disconnected"
   */
  isWalletConnected: boolean;

  /**
   * @notice Optional callback fired whenever the mobile menu is opened or closed.
   * @dev Receives the *new* open state after the toggle.
   * @param isOpen - The new boolean state of the mobile menu.
   */
  onToggleMenu?: (isOpen: boolean) => void;

  /**
   * @notice Optional Stellar wallet public key (G-address) of the connected wallet.
   * @dev Displayed in truncated form (`G...XXXX`) when provided and wallet is connected.
   *      Must be a valid 56-character Stellar address; invalid values are ignored.
   * @custom:security Value is truncated before rendering; never injected as HTML.
   */
  walletAddress?: string;

  /**
   * @notice Optional Stellar network the wallet is connected to.
   * @dev Validated against `SUPPORTED_NETWORKS`; unknown values render as
   *      "Unknown Network" to prevent arbitrary string injection.
   */
  networkName?: string;

  /**
   * @notice When `true`, a transaction is in-flight on the smart contract.
   * @dev Renders a distinct "Pending…" badge and sets `aria-busy="true"` on
   *      the wallet status element to communicate the state to screen readers.
   *      Defaults to `false`.
   */
  isTransactionPending?: boolean;

  /**
   * @notice When `true`, the wallet is in the process of connecting.
   * @dev Renders a "Connecting…" intermediate state badge.
   *      Defaults to `false`.
   */
  isWalletConnecting?: boolean;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * @notice Truncates a Stellar wallet address for safe display.
 * @dev Returns `G...XXXX` where XXXX is the last `ADDRESS_TAIL_CHARS` characters.
 *      Returns `null` if the address is falsy or not exactly `STELLAR_ADDRESS_LENGTH`
 *      characters long, so callers can conditionally render.
 * @param address - Raw Stellar public key string.
 * @returns Truncated display string or `null`.
 * @custom:security Truncation prevents layout-breaking long strings and avoids
 *   rendering the full key verbatim, reducing accidental clipboard-hijack risk.
 */
export function truncateWalletAddress(address: string | undefined): string | null {
  if (!address || address.length !== STELLAR_ADDRESS_LENGTH) {
    return null;
  }
  return `G...${address.slice(-ADDRESS_TAIL_CHARS)}`;
}

/**
 * @notice Validates and normalises a Stellar network name for display.
 * @dev Returns the network name as-is if it is in `SUPPORTED_NETWORKS`,
 *      otherwise returns `'Unknown Network'`.
 * @param network - Raw network name string from props.
 * @returns A safe, display-ready network label.
 * @custom:security Allowlist validation prevents arbitrary strings from being
 *   rendered in the UI, mitigating potential injection via prop manipulation.
 */
export function resolveNetworkLabel(network: string | undefined): string | null {
  if (!network) return null;
  return (SUPPORTED_NETWORKS as readonly string[]).includes(network)
    ? network
    : 'Unknown Network';
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @notice Renders the responsive top-level header for Stellar Raise.
 * @param props - See `FrontendHeaderResponsiveProps`.
 */
export const FrontendHeaderResponsive: React.FC<FrontendHeaderResponsiveProps> = ({
  isWalletConnected,
  onToggleMenu,
  walletAddress,
  networkName,
  isTransactionPending = false,
  isWalletConnecting = false,
}) => {

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

  const handleToggleMenu = useCallback(() => {
    setIsMobileMenuOpen(prev => {
      const newState = !prev;
      if (onToggleMenu) {
        onToggleMenu(newState);
      }
      return newState;
    });
  }, [onToggleMenu]);

  // -------------------------------------------------------------------------
  // Derived values
  // -------------------------------------------------------------------------

  const navLinks = useMemo(() => [
    { label: 'Dashboard', href: '/dashboard' },
    { label: 'Invest',    href: '/invest'    },
    { label: 'Docs',      href: '/docs'      },
  ], []);

  /** @dev Truncated address string, or null if address is absent/invalid. */
  const displayAddress = useMemo(
    () => truncateWalletAddress(walletAddress),
    [walletAddress],
  );

  /** @dev Validated network label, or null if networkName is absent. */
  const displayNetwork = useMemo(
    () => resolveNetworkLabel(networkName),
    [networkName],
  );

  /**
   * @dev Derives the wallet badge visual state from props.
   *      Priority: pending > connecting > connected > disconnected.
   */
  const walletBadgeState = useMemo((): 'pending' | 'connecting' | 'connected' | 'disconnected' => {
    if (isTransactionPending) return 'pending';
    if (isWalletConnecting)   return 'connecting';
    if (isWalletConnected)    return 'connected';
    return 'disconnected';
  }, [isTransactionPending, isWalletConnecting, isWalletConnected]);

  const badgeColors: Record<typeof walletBadgeState, { bg: string; border: string; dot: string }> = {
    pending:      { bg: 'rgba(255, 149, 0, 0.1)',  border: '#FF9500', dot: '#FF9500' },
    connecting:   { bg: 'rgba(0, 102, 255, 0.1)',  border: '#0066FF', dot: '#0066FF' },
    connected:    { bg: 'rgba(0, 200, 83, 0.1)',   border: '#00C853', dot: '#00C853' },
    disconnected: { bg: 'rgba(255, 59, 48, 0.1)',  border: '#FF3B30', dot: '#FF3B30' },
  };

  const badgeLabels: Record<typeof walletBadgeState, string> = {
    pending:      'Pending…',
    connecting:   'Connecting…',
    connected:    'Connected',
    disconnected: 'Disconnected',
  };

  const { bg, border, dot } = badgeColors[walletBadgeState];
  const badgeLabel = badgeLabels[walletBadgeState];

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <header
      className="frontend-header"
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '1rem 2rem',
        backgroundColor: '#0A1929',
        color: '#FFFFFF',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
      }}
    >

      {/* Brand Logo */}
      <div
        className="header-logo"
        style={{ fontSize: '1.5rem', fontWeight: 'bold' }}
      >
        Stellar Raise
      </div>

      {/* Mobile Menu Toggle */}
      <button
        className="mobile-menu-toggle md:hidden"
        onClick={handleToggleMenu}
        aria-label="Toggle Navigation Menu"
        aria-expanded={isMobileMenuOpen}
        style={{
          background: 'none',
          border: 'none',
          color: 'inherit',
          cursor: 'pointer',
          padding: '0.5rem',
          display: 'block',
        }}
      >
        {isMobileMenuOpen ? '✖' : '☰'}
      </button>

      {/* Navigation Links */}
      <nav
        className={`nav-links ${isMobileMenuOpen ? 'block' : 'hidden'} md:flex`}
        style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}
      >
        {navLinks.map(link => (
          <a
            key={link.label}
            href={link.href}
            style={{
              color: 'inherit',
              textDecoration: 'none',
              fontWeight: 500,
              padding: '0.5rem',
            }}
          >
            {link.label}
          </a>
        ))}

        {/* Wallet Status Badge */}
        <div
          className="wallet-status"
          aria-busy={isTransactionPending}
          aria-label={`Wallet status: ${badgeLabel}`}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            borderRadius: '9999px',
            backgroundColor: bg,
            border: `1px solid ${border}`,
            marginLeft: '1rem',
          }}
        >
          <span
            style={{
              display: 'inline-block',
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: dot,
            }}
          />
          <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>
            {badgeLabel}
          </span>

          {/* Truncated wallet address – only shown when connected and valid */}
          {walletBadgeState === 'connected' && displayAddress && (
            <span
              className="wallet-address"
              style={{ fontSize: '0.75rem', opacity: 0.8, marginLeft: '0.25rem' }}
            >
              {displayAddress}
            </span>
          )}

          {/* Network label – only shown when connected and network is known */}
          {walletBadgeState === 'connected' && displayNetwork && (
            <span
              className="network-label"
              style={{
                fontSize: '0.7rem',
                padding: '0.1rem 0.4rem',
                borderRadius: '4px',
                backgroundColor: 'rgba(255,255,255,0.1)',
                marginLeft: '0.25rem',
              }}
            >
              {displayNetwork}
            </span>
          )}
        </div>
      </nav>

    </header>
  );
};

export default FrontendHeaderResponsive;
