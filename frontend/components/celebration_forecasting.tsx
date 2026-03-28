import React, { useMemo } from "react";

/**
 * @title CelebrationForecasting
 * @notice Displays milestone progress and predicts when a crowdfunding campaign
 *         will reach its next funding milestone based on current contribution velocity.
 *
 * @dev Milestone thresholds are expressed as fractions of the campaign goal
 *      (25 %, 50 %, 75 %, 100 %).  Velocity is computed as:
 *
 *        velocity = totalRaised / elapsedSeconds   (tokens per second)
 *
 *      Projected completion time for a milestone M is:
 *
 *        eta = now + (M - totalRaised) / velocity
 *
 *      When velocity is zero (no contributions yet) the ETA is shown as "—".
 *
 * @custom:security
 *   - All numeric inputs are validated and clamped before use; negative or
 *     non-finite values are treated as zero to prevent division-by-zero and
 *     NaN propagation.
 *   - No user-supplied HTML is rendered; all output is plain text or typed
 *     React nodes, eliminating XSS risk.
 *
 * @custom:accessibility
 *   - Progress bars carry `role="progressbar"` with `aria-valuenow`,
 *     `aria-valuemin`, and `aria-valuemax` for screen-reader compatibility
 *     (WCAG 2.1 SC 4.1.2).
 *   - Celebration banners use `role="status"` so assistive technology
 *     announces them without stealing focus.
 */

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * @notice A single resolved milestone with its celebration and forecast data.
 */
export interface Milestone {
  /** Human-readable label, e.g. "25% Funded". */
  label: string;
  /** Token amount this milestone represents. */
  targetAmount: number;
  /** Whether the campaign has already reached this milestone. */
  reached: boolean;
  /** Projected Unix timestamp (seconds) when this milestone will be reached,
   *  or null when velocity is zero or milestone is already reached. */
  projectedAt: number | null;
}

/**
 * @notice Props accepted by CelebrationForecasting.
 *
 * @param totalRaised       Current total tokens raised (≥ 0).
 * @param goal              Campaign funding goal in tokens (> 0).
 * @param campaignStartTime Unix timestamp (seconds) when the campaign started.
 * @param currentTime       Unix timestamp (seconds) representing "now".
 *                          Defaults to `Math.floor(Date.now() / 1000)` when omitted.
 */
export interface CelebrationForecastingProps {
  totalRaised: number;
  goal: number;
  campaignStartTime: number;
  currentTime?: number;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Milestone fractions of the campaign goal. */
export const MILESTONE_FRACTIONS = [0.25, 0.5, 0.75, 1.0] as const;

// ── Pure helpers (exported for unit testing) ─────────────────────────────────

/**
 * @notice Sanitises a numeric value: returns 0 for non-finite or negative inputs.
 * @dev Prevents NaN / Infinity from propagating into forecast calculations.
 */
export function sanitize(value: number): number {
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

/**
 * @notice Computes contribution velocity in tokens per second.
 * @param totalRaised   Tokens raised so far (sanitised).
 * @param elapsedSeconds Seconds since campaign start (sanitised).
 * @returns Velocity ≥ 0; returns 0 when elapsed time is zero.
 */
export function computeVelocity(
  totalRaised: number,
  elapsedSeconds: number
): number {
  if (elapsedSeconds <= 0) return 0;
  return totalRaised / elapsedSeconds;
}

/**
 * @notice Builds the list of milestones with reached status and ETA.
 * @param totalRaised Tokens raised so far.
 * @param goal        Campaign goal.
 * @param velocity    Tokens per second (may be 0).
 * @param now         Current Unix timestamp in seconds.
 * @returns Array of Milestone objects ordered by target amount.
 */
export function buildMilestones(
  totalRaised: number,
  goal: number,
  velocity: number,
  now: number
): Milestone[] {
  return MILESTONE_FRACTIONS.map((fraction) => {
    const targetAmount = goal * fraction;
    const reached = totalRaised >= targetAmount;
    const pct = Math.round(fraction * 100);
    const label = pct === 100 ? "Goal Reached! 🎉" : `${pct}% Funded`;

    let projectedAt: number | null = null;
    if (!reached && velocity > 0) {
      const remaining = targetAmount - totalRaised;
      projectedAt = Math.round(now + remaining / velocity);
    }

    return { label, targetAmount, reached, projectedAt };
  });
}

/**
 * @notice Formats a Unix timestamp as a short locale date+time string.
 * @param ts Unix timestamp in seconds.
 * @returns e.g. "Mar 28, 2026, 10:30 AM"
 */
export function formatEta(ts: number): string {
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

// ── Component ────────────────────────────────────────────────────────────────

/**
 * @notice Renders milestone progress bars and celebration / forecast banners
 *         for a Stellar Raise crowdfunding campaign.
 */
const CelebrationForecasting: React.FC<CelebrationForecastingProps> = ({
  totalRaised,
  goal,
  campaignStartTime,
  currentTime,
}) => {
  const now = sanitize(currentTime ?? Math.floor(Date.now() / 1000));
  const safeRaised = sanitize(totalRaised);
  const safeGoal = sanitize(goal);
  const safeStart = sanitize(campaignStartTime);

  const { milestones, progressPct } = useMemo(() => {
    if (safeGoal === 0) {
      return { milestones: [], progressPct: 0 };
    }
    const elapsed = Math.max(0, now - safeStart);
    const velocity = computeVelocity(safeRaised, elapsed);
    const ms = buildMilestones(safeRaised, safeGoal, velocity, now);
    const pct = Math.min(100, (safeRaised / safeGoal) * 100);
    return { milestones: ms, progressPct: pct };
  }, [safeRaised, safeGoal, safeStart, now]);

  if (safeGoal === 0) {
    return (
      <div className="celebration-forecasting" data-testid="celebration-forecasting">
        <p className="celebration-forecasting__error">Invalid campaign goal.</p>
      </div>
    );
  }

  return (
    <div className="celebration-forecasting" data-testid="celebration-forecasting">
      {/* Overall progress bar */}
      <div className="celebration-forecasting__progress-wrapper">
        <div
          className="celebration-forecasting__progress-bar"
          role="progressbar"
          aria-valuenow={Math.round(progressPct)}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Campaign progress: ${Math.round(progressPct)}%`}
          style={{ width: `${progressPct}%` }}
          data-testid="progress-bar"
        />
      </div>
      <p className="celebration-forecasting__summary" data-testid="progress-summary">
        {safeRaised.toLocaleString()} / {safeGoal.toLocaleString()} tokens raised
        ({Math.round(progressPct)}%)
      </p>

      {/* Milestone list */}
      <ul className="celebration-forecasting__milestones" data-testid="milestones-list">
        {milestones.map((m) => (
          <li
            key={m.label}
            className={`celebration-forecasting__milestone${m.reached ? " celebration-forecasting__milestone--reached" : ""}`}
            data-testid={`milestone-${Math.round((m.targetAmount / safeGoal) * 100)}`}
          >
            {m.reached ? (
              <span role="status" className="celebration-forecasting__celebration">
                🎉 {m.label}
              </span>
            ) : (
              <span className="celebration-forecasting__forecast">
                {m.label}
                {m.projectedAt !== null ? (
                  <> — projected {formatEta(m.projectedAt)}</>
                ) : (
                  <> — ETA unavailable</>
                )}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default CelebrationForecasting;
