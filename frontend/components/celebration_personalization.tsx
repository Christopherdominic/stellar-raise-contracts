import React, { useEffect, useRef, useState } from "react";

/**
 * @title CelebrationPersonalization
 * @notice Displays a personalized milestone celebration banner when a campaign
 *         reaches a funding threshold. Supports custom messages, emoji, and
 *         auto-dismiss behaviour.
 * @dev Pure presentational component — no blockchain calls, no side-effects
 *      beyond a single setTimeout for auto-dismiss.
 *      All user-supplied strings are sanitized before rendering.
 *      No dangerouslySetInnerHTML is used anywhere in this file.
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum length for a custom celebration message. */
export const MAX_MESSAGE_LENGTH = 120;

/** Regex matching characters that must not appear in rendered text. */
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/g;

/** Allowed emoji subset for milestone icons. */
export const ALLOWED_EMOJI = ["🎉", "🚀", "🌟", "🏆", "💫", "🎊"] as const;
export type MilestoneEmoji = (typeof ALLOWED_EMOJI)[number];

/** Named milestone tiers with default labels. */
export const MILESTONE_TIERS = {
  quarter: { label: "25% funded!", defaultEmoji: "🚀" as MilestoneEmoji },
  half: { label: "50% funded!", defaultEmoji: "🌟" as MilestoneEmoji },
  threeQuarter: { label: "75% funded!", defaultEmoji: "🏆" as MilestoneEmoji },
  goal: { label: "Goal reached!", defaultEmoji: "🎉" as MilestoneEmoji },
} as const;

export type MilestoneTier = keyof typeof MILESTONE_TIERS;

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * @notice Props for CelebrationPersonalization.
 * @param tier            Which milestone tier triggered the celebration.
 * @param visible         Controls whether the banner is shown.
 * @param customMessage   Optional override for the celebration text.
 * @param emoji           Optional emoji override (must be in ALLOWED_EMOJI).
 * @param autoDismissMs   If > 0, banner auto-hides after this many ms. Default: 5000.
 * @param onDismiss       Callback fired when the banner is dismissed.
 * @param campaignName    Optional campaign name shown in the banner.
 */
export interface CelebrationPersonalizationProps {
  tier: MilestoneTier;
  visible: boolean;
  customMessage?: string;
  emoji?: MilestoneEmoji;
  autoDismissMs?: number;
  onDismiss?: () => void;
  campaignName?: string;
}

// ── Pure helpers (exported for unit testing) ──────────────────────────────────

/**
 * @title sanitizeCelebrationText
 * @notice Strips control characters, collapses whitespace, and truncates to
 *         MAX_MESSAGE_LENGTH. Returns `fallback` when the result is empty.
 * @param candidate  Untrusted input.
 * @param fallback   Returned when candidate is unusable.
 * @security Prevents blank banners and layout-abuse via oversized strings.
 */
export function sanitizeCelebrationText(candidate: unknown, fallback: string): string {
  if (typeof candidate !== "string") return fallback;
  const cleaned = candidate.replace(CONTROL_CHAR_RE, " ").replace(/\s+/g, " ").trim();
  if (!cleaned) return fallback;
  if (cleaned.length <= MAX_MESSAGE_LENGTH) return cleaned;
  return `${cleaned.slice(0, MAX_MESSAGE_LENGTH - 3)}...`;
}

/**
 * @title resolveEmoji
 * @notice Returns `candidate` if it is in ALLOWED_EMOJI, otherwise the tier default.
 * @param candidate  Emoji supplied by the caller.
 * @param tier       Fallback tier.
 * @security Restricts emoji to a known-safe set, preventing unexpected Unicode abuse.
 */
export function resolveEmoji(candidate: unknown, tier: MilestoneTier): MilestoneEmoji {
  if (ALLOWED_EMOJI.includes(candidate as MilestoneEmoji)) {
    return candidate as MilestoneEmoji;
  }
  return MILESTONE_TIERS[tier].defaultEmoji;
}

/**
 * @title resolveMilestoneMessage
 * @notice Builds the final display message for a milestone banner.
 * @param tier          Active milestone tier.
 * @param customMessage Optional caller-supplied override.
 * @param campaignName  Optional campaign name to personalise the message.
 */
export function resolveMilestoneMessage(
  tier: MilestoneTier,
  customMessage?: string,
  campaignName?: string,
): string {
  const base = sanitizeCelebrationText(customMessage, MILESTONE_TIERS[tier].label);
  const safeName = sanitizeCelebrationText(campaignName, "");
  return safeName ? `${safeName}: ${base}` : base;
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * @title CelebrationPersonalization
 * @notice Accessible milestone celebration banner with auto-dismiss and
 *         keyboard-dismissible close button.
 * @dev Uses role="status" + aria-live="polite" so screen readers announce the
 *      milestone without interrupting ongoing narration.
 */
const CelebrationPersonalization = ({
  tier,
  visible,
  customMessage,
  emoji,
  autoDismissMs = 5000,
  onDismiss,
  campaignName,
}: CelebrationPersonalizationProps) => {
  const [dismissed, setDismissed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset dismissed state whenever `visible` flips back to true.
  useEffect(() => {
    if (visible) setDismissed(false);
  }, [visible]);

  // Auto-dismiss timer.
  useEffect(() => {
    if (!visible || dismissed || autoDismissMs <= 0) return;
    timerRef.current = setTimeout(() => {
      setDismissed(true);
      onDismiss?.();
    }, autoDismissMs);
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current);
    };
  }, [visible, dismissed, autoDismissMs, onDismiss]);

  if (!visible || dismissed) return null;

  const resolvedEmoji = resolveEmoji(emoji, tier);
  const message = resolveMilestoneMessage(tier, customMessage, campaignName);

  const handleDismiss = () => {
    if (timerRef.current !== null) clearTimeout(timerRef.current);
    setDismissed(true);
    onDismiss?.();
  };

  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid="celebration-banner"
      data-tier={tier}
      style={bannerStyle}
    >
      <span aria-hidden="true" style={{ fontSize: "1.5rem" }}>
        {resolvedEmoji}
      </span>
      <span style={{ flex: 1 }}>{message}</span>
      <button
        type="button"
        aria-label="Dismiss celebration"
        onClick={handleDismiss}
        style={closeButtonStyle}
      >
        ✕
      </button>
    </div>
  );
};

// ── Styles (static constants — no dynamic CSS injection) ──────────────────────

const bannerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "0.75rem",
  padding: "0.75rem 1rem",
  borderRadius: "8px",
  backgroundColor: "#f0fdf4",
  border: "1px solid #86efac",
  color: "#166534",
  fontWeight: 600,
};

const closeButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  cursor: "pointer",
  fontSize: "1rem",
  color: "#166534",
  lineHeight: 1,
  padding: "0 0.25rem",
};

export default CelebrationPersonalization;
