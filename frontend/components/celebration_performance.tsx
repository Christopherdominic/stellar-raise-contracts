/**
 * @title CelebrationPerformance
 * @notice Performance-optimised milestone celebration component for the Stellar Raise
 *         crowdfunding dApp.
 *
 * @dev Design goals:
 *   - Zero unnecessary re-renders: all callbacks are memoised with `useCallback`;
 *     derived values are computed with `useMemo`; style objects are module-level
 *     constants so they are never re-allocated on render.
 *   - Minimal DOM footprint: the overlay is only mounted when `milestoneReached`
 *     is `true` and has not yet been dismissed.
 *   - SSR-safe: no `window` / `document` access at module scope.
 *   - Timer hygiene: the auto-dismiss `setTimeout` ref is always cleared on
 *     unmount and on manual dismiss to prevent state updates on unmounted
 *     components.
 *
 * @custom:security
 *   - `milestoneLabel` and `campaignName` are rendered as plain React text nodes;
 *     no `dangerouslySetInnerHTML` is used, eliminating XSS risk.
 *   - `onDismiss` is a caller-supplied callback; this component has no
 *     side-effects beyond local state transitions.
 *   - No network requests are made inside this component.
 *   - `autoDismissMs` is validated at runtime; non-positive values disable
 *     the timer to prevent accidental immediate dismissal.
 *
 * @custom:accessibility
 *   - Root element carries `role="dialog"` and `aria-modal="true"`.
 *   - `aria-label` is derived from `milestoneLabel` for screen-reader context.
 *   - Dismiss button receives focus on mount (keyboard-first UX).
 *   - Escape key dismisses the overlay (WCAG 2.1 SC 2.1.2).
 *   - Backdrop click dismisses the overlay for pointer users.
 *   - Decorative emoji carries `aria-hidden="true"`.
 *
 * @example
 * ```tsx
 * <CelebrationPerformance
 *   milestoneReached={funded >= goal}
 *   milestoneLabel="Goal Reached"
 *   milestonePercent={100}
 *   campaignName="Clean Water Initiative"
 *   onDismiss={() => setShowCelebration(false)}
 * />
 * ```
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  CSSProperties,
} from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * @notice Performance tier derived from the milestone percentage.
 * @dev Drives accent colour and badge icon without any runtime branching inside
 *      the render path — the tier is resolved once via `useMemo`.
 */
export type PerformanceTier = 'bronze' | 'silver' | 'gold' | 'platinum';

/**
 * @notice Props accepted by `CelebrationPerformance`.
 */
export interface CelebrationPerformanceProps {
  /**
   * @notice When `true` the celebration overlay is shown.
   * @dev Changing this from `false` → `true` resets any previous dismissal so
   *      the overlay re-appears for a new milestone event.
   */
  milestoneReached: boolean;
  /** Human-readable milestone label, e.g. "50% Funded". Rendered as plain text. */
  milestoneLabel: string;
  /** Numeric milestone percentage (0–100) used to derive the performance tier. */
  milestonePercent: number;
  /** Campaign display name shown in the celebration message. Rendered as plain text. */
  campaignName: string;
  /** Called when the user (or auto-dismiss timer) closes the overlay. */
  onDismiss: () => void;
  /** Override the auto-derived performance tier. */
  tier?: PerformanceTier;
  /**
   * @notice Auto-dismiss after this many milliseconds.
   * @dev `0` or any non-positive value disables the timer entirely.
   */
  autoDismissMs?: number;
  /** Additional CSS class names forwarded to the root element. */
  className?: string;
}

// ---------------------------------------------------------------------------
// Module-level constants (allocated once, never re-created on render)
// ---------------------------------------------------------------------------

/**
 * @notice Maps each `PerformanceTier` to its emoji badge.
 * @dev Defined at module scope so the object is never re-allocated.
 */
const TIER_EMOJI: Record<PerformanceTier, string> = {
  bronze: '🥉',
  silver: '🥈',
  gold: '🥇',
  platinum: '🏆',
};

/**
 * @notice Maps each `PerformanceTier` to its accent hex colour.
 * @dev Used in inline styles as a CSS-custom-property fallback for environments
 *      that do not support CSS variables (e.g. older Android WebViews).
 */
const TIER_ACCENT: Record<PerformanceTier, string> = {
  bronze: '#CD7F32',
  silver: '#A8A9AD',
  gold: '#FFD700',
  platinum: '#E5E4E2',
};

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * @notice Derives a `PerformanceTier` from a milestone percentage.
 * @dev Boundary mapping:
 *   - [−∞, 25) → bronze
 *   - [25, 50)  → silver
 *   - [50, 75)  → gold
 *   - [75, +∞]  → platinum
 * @param percent - Raw milestone percentage (may be out of range).
 * @return The corresponding `PerformanceTier`.
 */
export function derivePerformanceTier(percent: number): PerformanceTier {
  if (percent >= 75) return 'platinum';
  if (percent >= 50) return 'gold';
  if (percent >= 25) return 'silver';
  return 'bronze';
}

/**
 * @notice Returns the emoji badge for a given `PerformanceTier`.
 * @param tier - The performance tier.
 * @return An emoji string representing the tier.
 */
export function performanceTierEmoji(tier: PerformanceTier): string {
  return TIER_EMOJI[tier];
}

/**
 * @notice Returns the accent colour hex for a given `PerformanceTier`.
 * @param tier - The performance tier.
 * @return A CSS hex colour string.
 */
export function performanceTierAccent(tier: PerformanceTier): string {
  return TIER_ACCENT[tier];
}

/**
 * @notice Clamps a numeric value to the inclusive range [0, 100].
 * @dev Non-finite values (NaN, ±Infinity) are clamped to 0.
 * @param value - Raw percentage value.
 * @return A number in [0, 100].
 */
export function clampMilestonePercent(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, value));
}

// ---------------------------------------------------------------------------
// Static style objects (module-level — never re-allocated on render)
// ---------------------------------------------------------------------------

const OVERLAY_STYLE: CSSProperties = {
  position: 'fixed',
  inset: 0,
  zIndex: 1000,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
};

const BACKDROP_STYLE: CSSProperties = {
  position: 'fixed',
  inset: 0,
  backgroundColor: 'rgba(0,0,0,0.6)',
  zIndex: 1000,
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @notice Performance-optimised milestone celebration overlay.
 * @dev Renders only when `milestoneReached` is `true` and the user has not yet
 *      dismissed the overlay. All callbacks are memoised; style objects are
 *      module-level constants; tier derivation is wrapped in `useMemo`.
 * @param props - See `CelebrationPerformanceProps`.
 */
export const CelebrationPerformance: React.FC<CelebrationPerformanceProps> = ({
  milestoneReached,
  milestoneLabel,
  milestonePercent,
  campaignName,
  onDismiss,
  tier,
  autoDismissMs = 0,
  className = '',
}) => {
  const [dismissed, setDismissed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dismissBtnRef = useRef<HTMLButtonElement>(null);

  // Reset dismissed state whenever a new milestone event arrives.
  useEffect(() => {
    if (milestoneReached) {
      setDismissed(false);
    }
  }, [milestoneReached]);

  // Derive tier once per relevant prop change — not on every render.
  const resolvedTier = useMemo(
    () => tier ?? derivePerformanceTier(milestonePercent),
    [tier, milestonePercent],
  );

  // Accent colour and emoji are cheap lookups; memoised for referential stability.
  const accentColor = useMemo(() => performanceTierAccent(resolvedTier), [resolvedTier]);
  const emoji = useMemo(() => performanceTierEmoji(resolvedTier), [resolvedTier]);

  // Card style depends only on accentColor — memoised to avoid object churn.
  const cardStyle = useMemo<CSSProperties>(
    () => ({
      position: 'relative',
      zIndex: 1001,
      backgroundColor: '#FFFFFF',
      color: '#0A1929',
      border: `2px solid ${accentColor}`,
      borderRadius: '12px',
      padding: '2rem',
      maxWidth: '420px',
      width: '90%',
      textAlign: 'center',
      boxShadow: '0 8px 32px rgba(0,0,0,0.15)',
    }),
    [accentColor],
  );

  const labelStyle = useMemo<CSSProperties>(
    () => ({
      margin: '0 0 1.5rem',
      fontSize: '0.875rem',
      color: accentColor,
      fontWeight: 600,
    }),
    [accentColor],
  );

  const btnStyle = useMemo<CSSProperties>(
    () => ({
      backgroundColor: accentColor,
      color: '#FFFFFF',
      border: 'none',
      borderRadius: '8px',
      padding: '0.75rem 2rem',
      fontSize: '1rem',
      fontWeight: 700,
      cursor: 'pointer',
      width: '100%',
      minHeight: '44px',
    }),
    [accentColor],
  );

  // Stable dismiss handler — memoised so child elements never re-render due to
  // a new function reference.
  const handleDismiss = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setDismissed(true);
    onDismiss();
  }, [onDismiss]);

  // Focus dismiss button on mount for keyboard-first UX.
  const visible = milestoneReached && !dismissed;
  useEffect(() => {
    if (visible) {
      dismissBtnRef.current?.focus();
    }
  }, [visible]);

  // Auto-dismiss timer — only active when autoDismissMs > 0 and overlay is visible.
  useEffect(() => {
    if (!visible || autoDismissMs <= 0) return;
    timerRef.current = setTimeout(handleDismiss, autoDismissMs);
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [visible, autoDismissMs, handleDismiss]);

  // Escape key handler.
  useEffect(() => {
    if (!visible) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') handleDismiss();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [visible, handleDismiss]);

  if (!visible) return null;

  const clamped = clampMilestonePercent(milestonePercent);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Milestone celebration: ${milestoneLabel}`}
      className={
        `celebration-performance celebration-performance--${resolvedTier} ${className}`.trim()
      }
      data-testid="celebration-performance"
      style={OVERLAY_STYLE}
    >
      {/* Backdrop — dismisses on click for pointer users */}
      <div
        aria-hidden="true"
        data-testid="celebration-performance-backdrop"
        onClick={handleDismiss}
        style={BACKDROP_STYLE}
      />

      {/* Card */}
      <div data-testid="celebration-performance-card" style={cardStyle}>
        {/* Tier badge */}
        <div
          aria-hidden="true"
          data-testid="celebration-performance-badge"
          style={{ fontSize: '3rem', marginBottom: '0.5rem' }}
        >
          {emoji}
        </div>

        {/* Title */}
        <h2
          data-testid="celebration-performance-title"
          style={{ margin: '0 0 0.5rem', fontSize: '1.5rem', fontWeight: 700 }}
        >
          Milestone Reached!
        </h2>

        {/* Campaign name */}
        <p
          data-testid="celebration-performance-campaign"
          style={{ margin: '0 0 0.25rem', fontWeight: 600, fontSize: '1rem' }}
        >
          {campaignName}
        </p>

        {/* Milestone label */}
        <p
          data-testid="celebration-performance-label"
          style={labelStyle}
        >
          {milestoneLabel}
        </p>

        {/* Percentage indicator */}
        <p
          data-testid="celebration-performance-percent"
          style={{ margin: '0 0 1.5rem', fontSize: '0.875rem', color: '#6b7280' }}
        >
          {clamped}% of goal
        </p>

        {/* Dismiss button */}
        <button
          ref={dismissBtnRef}
          data-testid="celebration-performance-dismiss"
          onClick={handleDismiss}
          aria-label="Dismiss milestone celebration"
          type="button"
          style={btnStyle}
        >
          Continue
        </button>
      </div>
    </div>
  );
};

export default CelebrationPerformance;
