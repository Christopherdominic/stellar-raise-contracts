import React, { useEffect, useRef, useState } from "react";

/**
 * @title MilestoneCelebration
 * @notice Reusable celebration overlay shown when a campaign milestone is reached.
 * @dev Renders an accessible modal-style banner with an animated emoji burst,
 *      a milestone label, and an optional CTA. Auto-dismisses after `duration` ms
 *      when `autoDismiss` is true. Callers control visibility via `visible`.
 *
 * Security assumptions:
 * 1. `label` and `ctaLabel` are rendered as React text nodes — no innerHTML path.
 * 2. `onDismiss` and `onCta` are caller-supplied callbacks; this component never
 *    submits data or calls external services.
 * 3. The component does not read or write to localStorage / cookies.
 * 4. Auto-dismiss timer is cleared on unmount to prevent state updates on
 *    unmounted components.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/** Milestone tier controls the colour scheme and default emoji. */
export type MilestoneTier = "bronze" | "silver" | "gold" | "platinum";

export interface MilestoneCelebrationProps {
  /** Whether the celebration overlay is visible. */
  visible: boolean;
  /** Short label describing the milestone, e.g. "50% funded!". */
  label: string;
  /** Tier controls the visual theme. Default: "gold". */
  tier?: MilestoneTier;
  /** Emoji shown in the burst. Defaults to the tier emoji. */
  emoji?: string;
  /** When true, the overlay auto-dismisses after `duration` ms. Default: true. */
  autoDismiss?: boolean;
  /** Auto-dismiss delay in milliseconds. Default: 4000. */
  duration?: number;
  /** Called when the overlay is dismissed (button click or auto-dismiss). */
  onDismiss?: () => void;
  /** Optional CTA button label. When omitted the button is not rendered. */
  ctaLabel?: string;
  /** Called when the CTA button is clicked. */
  onCta?: () => void;
  /** Additional CSS class applied to the root element. */
  className?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

export const DEFAULT_DURATION = 4_000;
export const MAX_LABEL_LENGTH = 120;

const TIER_EMOJI: Record<MilestoneTier, string> = {
  bronze: "🥉",
  silver: "🥈",
  gold: "🏆",
  platinum: "💎",
};

const TIER_COLORS: Record<MilestoneTier, { bg: string; border: string; text: string }> = {
  bronze: { bg: "#fdf3e7", border: "#cd7f32", text: "#7c4a03" },
  silver: { bg: "#f4f4f5", border: "#a1a1aa", text: "#3f3f46" },
  gold:   { bg: "#fffbeb", border: "#f59e0b", text: "#92400e" },
  platinum: { bg: "#f0f9ff", border: "#38bdf8", text: "#0c4a6e" },
};

// ── Pure helpers ──────────────────────────────────────────────────────────────

/**
 * @title normalizeMilestoneLabel
 * @notice Sanitizes a milestone label: strips control characters, collapses
 *         whitespace, and truncates to MAX_LABEL_LENGTH.
 * @param candidate  Untrusted input.
 * @param fallback   Returned when candidate is unusable.
 */
export function normalizeMilestoneLabel(candidate: unknown, fallback: string): string {
  if (typeof candidate !== "string") return fallback;
  const cleaned = candidate.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
  if (!cleaned) return fallback;
  if (cleaned.length <= MAX_LABEL_LENGTH) return cleaned;
  return `${cleaned.slice(0, MAX_LABEL_LENGTH - 3)}...`;
}

/**
 * @title resolveTierEmoji
 * @notice Returns the caller-supplied emoji when valid, otherwise the tier default.
 * @param emoji  Caller-supplied emoji string (may be undefined or empty).
 * @param tier   Milestone tier used as fallback.
 */
export function resolveTierEmoji(emoji: string | undefined, tier: MilestoneTier): string {
  if (typeof emoji === "string" && emoji.trim().length > 0) return emoji.trim();
  return TIER_EMOJI[tier];
}

/**
 * @title isCelebrationVisible
 * @notice Returns true when the overlay should be rendered.
 * @param visible  Caller-controlled visibility flag.
 * @param label    Resolved label — overlay is suppressed for empty labels.
 */
export function isCelebrationVisible(visible: boolean, label: string): boolean {
  return visible && label.length > 0;
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * @title MilestoneCelebration
 * @notice Accessible, reusable milestone celebration overlay for campaign pages.
 */
const MilestoneCelebration: React.FC<MilestoneCelebrationProps> = ({
  visible,
  label,
  tier = "gold",
  emoji,
  autoDismiss = true,
  duration = DEFAULT_DURATION,
  onDismiss,
  ctaLabel,
  onCta,
  className,
}) => {
  const [dismissed, setDismissed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resolvedLabel = normalizeMilestoneLabel(label, "Milestone reached!");
  const resolvedEmoji = resolveTierEmoji(emoji, tier);
  const colors = TIER_COLORS[tier];
  const shouldShow = isCelebrationVisible(visible, resolvedLabel) && !dismissed;

  // Reset dismissed state when `visible` flips back to true (new milestone).
  useEffect(() => {
    if (visible) setDismissed(false);
  }, [visible]);

  // Auto-dismiss timer.
  useEffect(() => {
    if (!shouldShow || !autoDismiss) return;
    timerRef.current = setTimeout(() => {
      setDismissed(true);
      onDismiss?.();
    }, duration);
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current);
    };
  }, [shouldShow, autoDismiss, duration, onDismiss]);

  const handleDismiss = () => {
    if (timerRef.current !== null) clearTimeout(timerRef.current);
    setDismissed(true);
    onDismiss?.();
  };

  const handleCta = () => {
    onCta?.();
  };

  if (!shouldShow) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Milestone: ${resolvedLabel}`}
      data-tier={tier}
      data-testid="milestone-celebration"
      className={className}
      style={{
        position: "fixed",
        bottom: "24px",
        right: "24px",
        zIndex: 1000,
        padding: "16px 20px",
        borderRadius: "12px",
        border: `2px solid ${colors.border}`,
        backgroundColor: colors.bg,
        color: colors.text,
        maxWidth: "360px",
        boxShadow: "0 4px 16px rgba(0,0,0,0.12)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
        fontFamily: "sans-serif",
      }}
    >
      {/* Emoji burst */}
      <span
        aria-hidden="true"
        data-testid="celebration-emoji"
        style={{ fontSize: "2rem", lineHeight: 1 }}
      >
        {resolvedEmoji}
      </span>

      {/* Milestone label */}
      <p
        data-testid="celebration-label"
        style={{ margin: 0, fontWeight: 600, fontSize: "1rem" }}
      >
        {resolvedLabel}
      </p>

      {/* Action row */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        {ctaLabel && (
          <button
            onClick={handleCta}
            aria-label={ctaLabel}
            data-testid="celebration-cta"
            style={{
              padding: "6px 14px",
              borderRadius: "6px",
              border: `1px solid ${colors.border}`,
              backgroundColor: colors.border,
              color: "#fff",
              cursor: "pointer",
              fontSize: "0.875rem",
              fontWeight: 600,
            }}
          >
            {ctaLabel}
          </button>
        )}
        <button
          onClick={handleDismiss}
          aria-label="Dismiss milestone celebration"
          data-testid="celebration-dismiss"
          style={{
            padding: "6px 14px",
            borderRadius: "6px",
            border: `1px solid ${colors.border}`,
            backgroundColor: "transparent",
            color: colors.text,
            cursor: "pointer",
            fontSize: "0.875rem",
          }}
        >
          Dismiss
        </button>
      </div>
    </div>
  );
};

export default MilestoneCelebration;
