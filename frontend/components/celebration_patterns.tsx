import React, { useEffect, useRef, useState } from "react";

/**
 * @title CelebrationPatterns
 * @notice Renders a milestone celebration overlay when a crowdfunding campaign
 *         reaches a funding threshold. Supports confetti burst, progress ring,
 *         and a dismissible banner — all driven by pure props with no side effects
 *         outside the component boundary.
 *
 * @dev Security assumptions:
 *   - All user-supplied strings (title, message) are rendered as React text nodes.
 *     No dangerouslySetInnerHTML is used anywhere in this module.
 *   - Milestone thresholds are validated before rendering; invalid values are
 *     silently ignored and the component renders nothing.
 *   - Animation timers are cleaned up on unmount to prevent memory leaks.
 *   - `onDismiss` is the only external callback; it carries no data.
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum length for the celebration title string. */
export const MAX_TITLE_LENGTH = 60;

/** Maximum length for the celebration message string. */
export const MAX_MESSAGE_LENGTH = 160;

/** Number of confetti particles rendered per burst. */
export const CONFETTI_COUNT = 30;

/** Duration (ms) before the celebration auto-dismisses. 0 = no auto-dismiss. */
export const AUTO_DISMISS_MS = 5000;

/** Basis-point scale (10 000 bps = 100 %). */
export const BPS_SCALE = 10_000;

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * @notice A single funding milestone definition.
 * @param thresholdBps  Progress threshold in basis points (1–10 000).
 * @param title         Short celebration heading (max 60 chars).
 * @param message       Supporting copy shown below the heading (max 160 chars).
 */
export interface Milestone {
  thresholdBps: number;
  title: string;
  message: string;
}

/**
 * @notice Props for the CelebrationPatterns component.
 * @param progressBps   Current campaign progress in basis points (0–10 000).
 * @param milestones    Ordered list of milestones to check against.
 * @param onDismiss     Called when the user dismisses the celebration.
 * @param autoDismissMs Override for the auto-dismiss delay. 0 disables it.
 */
export interface CelebrationPatternsProps {
  progressBps: number;
  milestones: Milestone[];
  onDismiss?: () => void;
  autoDismissMs?: number;
}

// ── Pure helpers (exported for unit testing) ──────────────────────────────────

/**
 * @title sanitizeCelebrationText
 * @notice Strips control characters, normalizes whitespace, and truncates to `maxLen`.
 * @param value   Untrusted input.
 * @param maxLen  Hard character limit.
 * @returns       Safe string, or empty string when input is unusable.
 * @security Prevents layout abuse from oversized or malformed strings.
 */
export function sanitizeCelebrationText(value: unknown, maxLen: number): string {
  if (typeof value !== "string") return "";
  const cleaned = value
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) return "";
  return cleaned.length <= maxLen ? cleaned : `${cleaned.slice(0, maxLen - 3)}...`;
}

/**
 * @title isValidMilestone
 * @notice Returns true when a milestone has a valid threshold and non-empty text.
 * @param m  Candidate milestone.
 * @security Rejects milestones with out-of-range thresholds to prevent
 *           celebrations that can never trigger or always trigger.
 */
export function isValidMilestone(m: unknown): m is Milestone {
  if (!m || typeof m !== "object") return false;
  const { thresholdBps, title, message } = m as Partial<Milestone>;
  return (
    typeof thresholdBps === "number" &&
    thresholdBps >= 1 &&
    thresholdBps <= BPS_SCALE &&
    sanitizeCelebrationText(title, MAX_TITLE_LENGTH) !== "" &&
    sanitizeCelebrationText(message, MAX_MESSAGE_LENGTH) !== ""
  );
}

/**
 * @title resolveTriggeredMilestone
 * @notice Returns the highest-threshold milestone that `progressBps` has reached,
 *         or `null` when none apply.
 * @param progressBps  Current progress (0–10 000).
 * @param milestones   Validated milestone list.
 */
export function resolveTriggeredMilestone(
  progressBps: number,
  milestones: Milestone[],
): Milestone | null {
  if (progressBps <= 0) return null;

  let best: Milestone | null = null;
  for (const m of milestones) {
    if (progressBps >= m.thresholdBps) {
      if (!best || m.thresholdBps > best.thresholdBps) {
        best = m;
      }
    }
  }
  return best;
}

/**
 * @title buildConfettiParticles
 * @notice Generates deterministic confetti particle styles for a burst animation.
 * @param count  Number of particles (clamped to [1, 100]).
 * @returns      Array of inline style objects for `<span>` elements.
 * @security Uses only hardcoded color palette — no user-controlled CSS values.
 */
export function buildConfettiParticles(count: number): React.CSSProperties[] {
  const safeCount = Math.max(1, Math.min(100, count));
  const colors = ["#4f46e5", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4"];
  const particles: React.CSSProperties[] = [];

  for (let i = 0; i < safeCount; i++) {
    const angle = (i / safeCount) * 360;
    const distance = 40 + (i % 5) * 12;
    const color = colors[i % colors.length];
    particles.push({
      position: "absolute",
      width: "8px",
      height: "8px",
      borderRadius: "50%",
      backgroundColor: color,
      top: "50%",
      left: "50%",
      transform: `rotate(${angle}deg) translateX(${distance}px)`,
      opacity: 0,
      animation: `confetti-fade 0.8s ease-out ${(i * 20) % 400}ms forwards`,
      pointerEvents: "none",
    });
  }
  return particles;
}

/**
 * @title computeProgressRingDashOffset
 * @notice Converts basis-point progress to an SVG stroke-dashoffset value.
 * @param progressBps  Progress in basis points (0–10 000).
 * @param circumference  Full circle circumference in px.
 * @returns            Dash offset so the arc fills proportionally.
 */
export function computeProgressRingDashOffset(
  progressBps: number,
  circumference: number,
): number {
  const clamped = Math.max(0, Math.min(BPS_SCALE, progressBps));
  return circumference * (1 - clamped / BPS_SCALE);
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * @title CelebrationPatterns
 * @notice Displays a milestone celebration overlay with confetti, a progress ring,
 *         and a dismissible banner when the campaign crosses a threshold.
 */
const CelebrationPatterns = ({
  progressBps,
  milestones,
  onDismiss,
  autoDismissMs = AUTO_DISMISS_MS,
}: CelebrationPatternsProps) => {
  const [dismissed, setDismissed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const validMilestones = milestones.filter(isValidMilestone);
  const triggered = resolveTriggeredMilestone(progressBps, validMilestones);

  // Reset dismissed state when a new milestone triggers.
  const triggeredKey = triggered?.thresholdBps ?? null;
  const prevKeyRef = useRef<number | null>(null);
  if (prevKeyRef.current !== triggeredKey) {
    prevKeyRef.current = triggeredKey;
    if (triggeredKey !== null) setDismissed(false);
  }

  // Auto-dismiss timer.
  useEffect(() => {
    if (!triggered || dismissed || autoDismissMs <= 0) return;
    timerRef.current = setTimeout(() => {
      setDismissed(true);
      onDismiss?.();
    }, autoDismissMs);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [triggered, dismissed, autoDismissMs, onDismiss]);

  if (!triggered || dismissed) return null;

  const title = sanitizeCelebrationText(triggered.title, MAX_TITLE_LENGTH);
  const message = sanitizeCelebrationText(triggered.message, MAX_MESSAGE_LENGTH);
  const particles = buildConfettiParticles(CONFETTI_COUNT);

  // Progress ring geometry.
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = computeProgressRingDashOffset(progressBps, circumference);
  const progressPct = Math.round((progressBps / BPS_SCALE) * 100);

  const handleDismiss = () => {
    setDismissed(true);
    onDismiss?.();
  };

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Milestone reached: ${title}`}
      data-testid="celebration-overlay"
      style={overlayStyle}
    >
      {/* Confetti burst */}
      <div style={confettiWrapStyle} aria-hidden="true">
        {particles.map((style, i) => (
          <span key={i} style={style} />
        ))}
      </div>

      {/* Progress ring */}
      <svg
        width="88"
        height="88"
        viewBox="0 0 88 88"
        aria-hidden="true"
        style={{ display: "block", margin: "0 auto 1rem" }}
      >
        <circle cx="44" cy="44" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="8" />
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke="#4f46e5"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 44 44)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text x="44" y="49" textAnchor="middle" fontSize="14" fontWeight="700" fill="#1e293b">
          {progressPct}%
        </text>
      </svg>

      {/* Banner */}
      <p style={titleStyle}>{title}</p>
      <p style={messageStyle}>{message}</p>

      <button
        type="button"
        onClick={handleDismiss}
        aria-label="Dismiss celebration"
        data-testid="dismiss-btn"
        style={dismissBtnStyle}
      >
        Dismiss
      </button>
    </div>
  );
};

// ── Styles (hardcoded constants — no user-controlled values) ──────────────────

const overlayStyle: React.CSSProperties = {
  position: "relative",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  padding: "2rem",
  borderRadius: "1rem",
  background: "linear-gradient(135deg, #f0f4ff 0%, #fafafa 100%)",
  border: "2px solid #4f46e5",
  maxWidth: "360px",
  margin: "0 auto",
  boxShadow: "0 8px 32px rgba(79,70,229,0.15)",
  overflow: "hidden",
};

const confettiWrapStyle: React.CSSProperties = {
  position: "absolute",
  inset: 0,
  pointerEvents: "none",
};

const titleStyle: React.CSSProperties = {
  margin: "0 0 0.5rem",
  fontSize: "1.25rem",
  fontWeight: 700,
  color: "#1e293b",
  textAlign: "center",
};

const messageStyle: React.CSSProperties = {
  margin: "0 0 1.5rem",
  fontSize: "0.875rem",
  color: "#374151",
  textAlign: "center",
};

const dismissBtnStyle: React.CSSProperties = {
  padding: "0.5rem 1.5rem",
  borderRadius: "0.5rem",
  border: "1px solid #4f46e5",
  background: "#4f46e5",
  color: "#fff",
  fontWeight: 600,
  cursor: "pointer",
  fontSize: "0.875rem",
};

export default CelebrationPatterns;
