import React, { useEffect, useRef, useState, useCallback } from 'react';

/**
 * @title CampaignMilestoneCelebration
 * @notice Displays a reliable, accessible milestone celebration overlay when a
 *         campaign reaches a funding threshold on the Stellar/Soroban network.
 *
 * @dev Reliability guarantees:
 *   - Celebration fires exactly once per milestone crossing (deduped by milestoneId).
 *   - Auto-dismisses after `autoDismissMs` (default 5 000 ms); timer is cleared on
 *     unmount to prevent setState-after-unmount leaks.
 *   - Reduced-motion: animation is skipped when the OS prefers reduced motion.
 *   - No dangerouslySetInnerHTML — all content is rendered as React nodes.
 *
 * @custom:security
 *   - milestoneLabel is truncated to MAX_LABEL_LENGTH to prevent layout abuse.
 *   - No user-supplied HTML is injected.
 *   - onDismiss callback is guarded against being called after unmount.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum characters allowed in a milestone label. */
export const MAX_LABEL_LENGTH = 80;

/** Default auto-dismiss delay in milliseconds. */
export const DEFAULT_AUTO_DISMISS_MS = 5_000;

/** Milestone thresholds as percentages (25 %, 50 %, 75 %, 100 %). */
export const MILESTONE_THRESHOLDS = [25, 50, 75, 100] as const;
export type MilestoneThreshold = (typeof MILESTONE_THRESHOLDS)[number];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MilestoneInfo {
  /** Unique identifier — used to deduplicate celebrations. */
  milestoneId: string;
  /** Funding threshold that was reached (25 | 50 | 75 | 100). */
  threshold: MilestoneThreshold;
  /** Human-readable label, e.g. "50% funded". Sanitized before render. */
  label: string;
  /** Campaign title for contextual messaging. */
  campaignTitle?: string;
}

export interface CelebrationReliabilityProps {
  /** Milestone data. Pass `null` / `undefined` to render nothing. */
  milestone: MilestoneInfo | null | undefined;
  /** Called when the overlay is dismissed (by user or auto-timer). */
  onDismiss?: (milestoneId: string) => void;
  /** Override auto-dismiss delay in ms. Pass 0 to disable auto-dismiss. */
  autoDismissMs?: number;
  /** Test-only: inject a custom confetti renderer. */
  confettiRenderer?: () => React.ReactNode;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * @notice Sanitizes a milestone label: strips control chars, collapses
 *         whitespace, and truncates to MAX_LABEL_LENGTH.
 * @param raw Untrusted string input.
 */
export function sanitizeMilestoneLabel(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const cleaned = raw
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1F\x7F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length <= MAX_LABEL_LENGTH) return cleaned;
  return `${cleaned.slice(0, MAX_LABEL_LENGTH - 3)}...`;
}

/**
 * @notice Returns the emoji and color associated with a milestone threshold.
 * @param threshold One of the four supported milestone percentages.
 */
export function getMilestoneVisuals(threshold: MilestoneThreshold): {
  emoji: string;
  color: string;
  label: string;
} {
  switch (threshold) {
    case 25:
      return { emoji: '🌱', color: '#10b981', label: 'Quarter way there' };
    case 50:
      return { emoji: '🚀', color: '#0066FF', label: 'Halfway funded' };
    case 75:
      return { emoji: '⚡', color: '#f59e0b', label: 'Almost there' };
    case 100:
      return { emoji: '🎉', color: '#7c3aed', label: 'Fully funded' };
  }
}

/**
 * @notice Returns true when the milestone threshold is a valid supported value.
 * @param value Candidate threshold value.
 */
export function isValidMilestoneThreshold(value: unknown): value is MilestoneThreshold {
  return MILESTONE_THRESHOLDS.includes(value as MilestoneThreshold);
}

// ---------------------------------------------------------------------------
// Default confetti renderer
// ---------------------------------------------------------------------------

const DefaultConfetti = () => (
  <div aria-hidden="true" style={styles.confettiContainer}>
    {['#0066FF', '#10b981', '#f59e0b', '#7c3aed', '#ef4444'].map((color, i) => (
      <span
        key={i}
        style={{
          ...styles.confettiPiece,
          backgroundColor: color,
          left: `${10 + i * 18}%`,
          animationDelay: `${i * 0.12}s`,
        }}
      />
    ))}
  </div>
);

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @title CampaignMilestoneCelebration
 * @notice Renders a celebration overlay when a campaign milestone is reached.
 *
 * @param props See CelebrationReliabilityProps.
 */
const CampaignMilestoneCelebration: React.FC<CelebrationReliabilityProps> = ({
  milestone,
  onDismiss,
  autoDismissMs = DEFAULT_AUTO_DISMISS_MS,
  confettiRenderer,
}) => {
  const [visible, setVisible] = useState(false);
  const [celebratedIds] = useState(() => new Set<string>());
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const dismissedRef = useRef(false);

  // Track mounted state to prevent setState after unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  // Show celebration exactly once per unique milestoneId
  useEffect(() => {
    if (!milestone) return;
    if (!isValidMilestoneThreshold(milestone.threshold)) return;
    if (celebratedIds.has(milestone.milestoneId)) return;

    celebratedIds.add(milestone.milestoneId);
    dismissedRef.current = false;
    setVisible(true);

    if (autoDismissMs > 0) {
      timerRef.current = setTimeout(() => {
        if (mountedRef.current && !dismissedRef.current) {
          dismissedRef.current = true;
          setVisible(false);
          onDismiss?.(milestone.milestoneId);
        }
      }, autoDismissMs);
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
    // celebratedIds is a stable Set ref — intentionally excluded
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [milestone?.milestoneId, milestone?.threshold, autoDismissMs, onDismiss]);

  const handleDismiss = useCallback(() => {
    if (!mountedRef.current) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    dismissedRef.current = true;
    setVisible(false);
    if (milestone) onDismiss?.(milestone.milestoneId);
  }, [milestone, onDismiss]);

  if (!visible || !milestone) return null;

  const safeLabel = sanitizeMilestoneLabel(milestone.label);
  const safeTitle = sanitizeMilestoneLabel(milestone.campaignTitle ?? '');
  const visuals = getMilestoneVisuals(milestone.threshold);
  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Milestone reached: ${safeLabel}`}
      aria-live="polite"
      style={styles.overlay}
      data-testid="milestone-celebration-overlay"
    >
      <div
        style={{
          ...styles.card,
          borderTop: `4px solid ${visuals.color}`,
          animation: prefersReducedMotion ? 'none' : 'celebrationSlideIn 0.35s ease-out',
        }}
        data-testid="milestone-celebration-card"
      >
        {/* Confetti */}
        {!prefersReducedMotion && (confettiRenderer ? confettiRenderer() : <DefaultConfetti />)}

        {/* Icon */}
        <div
          aria-hidden="true"
          style={{ ...styles.emoji, color: visuals.color }}
          data-testid="milestone-emoji"
        >
          {visuals.emoji}
        </div>

        {/* Heading */}
        <h2 style={styles.heading} data-testid="milestone-heading">
          {visuals.label}
        </h2>

        {/* Label */}
        {safeLabel && (
          <p style={styles.label} data-testid="milestone-label">
            {safeLabel}
          </p>
        )}

        {/* Campaign title */}
        {safeTitle && (
          <p style={styles.campaignTitle} data-testid="milestone-campaign-title">
            {safeTitle}
          </p>
        )}

        {/* Dismiss button */}
        <button
          type="button"
          onClick={handleDismiss}
          aria-label="Dismiss milestone celebration"
          style={{ ...styles.dismissBtn, backgroundColor: visuals.color }}
          data-testid="milestone-dismiss-btn"
        >
          Continue
        </button>
      </div>

      {/* Keyframe injection (once) */}
      <style>{KEYFRAMES}</style>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'fixed',
    inset: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(0,0,0,0.55)',
    zIndex: 9999,
  },
  card: {
    position: 'relative',
    backgroundColor: '#ffffff',
    borderRadius: '0.75rem',
    padding: '2rem 2.5rem',
    maxWidth: '420px',
    width: '90%',
    textAlign: 'center',
    boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
    overflow: 'hidden',
  },
  confettiContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    pointerEvents: 'none',
    overflow: 'hidden',
  },
  confettiPiece: {
    position: 'absolute',
    top: '-10px',
    width: '10px',
    height: '10px',
    borderRadius: '2px',
    animation: 'confettiFall 1.2s ease-in forwards',
  },
  emoji: {
    fontSize: '3rem',
    lineHeight: 1,
    marginBottom: '0.75rem',
    display: 'block',
  },
  heading: {
    fontSize: '1.375rem',
    fontWeight: 700,
    color: '#0A1929',
    margin: '0 0 0.5rem',
  },
  label: {
    fontSize: '1rem',
    color: '#374151',
    margin: '0 0 0.25rem',
  },
  campaignTitle: {
    fontSize: '0.875rem',
    color: '#6b7280',
    margin: '0 0 1.25rem',
  },
  dismissBtn: {
    marginTop: '1.25rem',
    padding: '0.6rem 1.75rem',
    border: 'none',
    borderRadius: '0.375rem',
    color: '#ffffff',
    fontSize: '0.95rem',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s',
  },
};

const KEYFRAMES = `
@keyframes celebrationSlideIn {
  from { opacity: 0; transform: translateY(-24px) scale(0.95); }
  to   { opacity: 1; transform: translateY(0)     scale(1);    }
}
@keyframes confettiFall {
  0%   { transform: translateY(0)    rotate(0deg);   opacity: 1; }
  100% { transform: translateY(300px) rotate(720deg); opacity: 0; }
}
`;

export default CampaignMilestoneCelebration;
