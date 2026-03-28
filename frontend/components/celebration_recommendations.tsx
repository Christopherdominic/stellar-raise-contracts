import React, { useMemo } from "react";

/**
 * @title CelebrationRecommendations
 * @notice Generates contextual, actionable recommendations for a campaign
 *         creator based on which funding milestones have been reached.
 *
 * @dev Recommendations are derived entirely from typed props — no user-supplied
 *      HTML is rendered, eliminating XSS risk.  The component is purely
 *      presentational and stateless.
 *
 *      Milestone thresholds mirror those in `celebration_forecasting.tsx`
 *      (25 %, 50 %, 75 %, 100 % of goal) so the two components can be
 *      composed on the same page without duplicating threshold logic.
 *
 * @custom:security
 *   - All numeric inputs are sanitised before use; negative or non-finite
 *     values are treated as 0 to prevent NaN propagation.
 *   - Recommendation strings are static constants — no user input reaches
 *     rendered text.
 *
 * @custom:accessibility
 *   - The recommendation list uses `role="list"` / `role="listitem"` so
 *     screen readers announce it correctly (WCAG 2.1 SC 1.3.1).
 *   - Each recommendation icon is wrapped in `aria-hidden="true"` so it is
 *     skipped by assistive technology.
 */

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * @notice A single actionable recommendation produced by the engine.
 *
 * @param id       Stable identifier used as React key and test selector.
 * @param icon     Decorative emoji (aria-hidden in the component).
 * @param heading  Short imperative heading, e.g. "Share your campaign".
 * @param body     One-sentence elaboration.
 */
export interface Recommendation {
  id: string;
  icon: string;
  heading: string;
  body: string;
}

/**
 * @notice Campaign phase derived from progress percentage.
 * @dev Used internally to select the appropriate recommendation set.
 */
export type CampaignPhase = "pre_launch" | "early" | "halfway" | "final_push" | "funded";

/**
 * @notice Props accepted by CelebrationRecommendations.
 *
 * @param totalRaised  Current total tokens raised (≥ 0).
 * @param goal         Campaign funding goal in tokens (> 0).
 * @param isCreator    When true, creator-specific recommendations are shown.
 *                     When false, contributor-facing recommendations are shown.
 */
export interface CelebrationRecommendationsProps {
  totalRaised: number;
  goal: number;
  isCreator?: boolean;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Milestone fractions that trigger phase transitions. */
export const PHASE_THRESHOLDS = {
  early: 0.25,
  halfway: 0.5,
  finalPush: 0.75,
  funded: 1.0,
} as const;

// ── Pure helpers (exported for unit testing) ─────────────────────────────────

/**
 * @notice Sanitises a numeric value: returns 0 for non-finite or negative inputs.
 */
export function sanitize(value: number): number {
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

/**
 * @notice Derives the campaign phase from a progress percentage.
 *
 * @param progressPct  Progress as a percentage (0–100+).
 * @returns The matching `CampaignPhase`.
 */
export function derivePhase(progressPct: number): CampaignPhase {
  if (progressPct >= 100) return "funded";
  if (progressPct >= 75) return "final_push";
  if (progressPct >= 50) return "halfway";
  if (progressPct >= 25) return "early";
  return "pre_launch";
}

/**
 * @notice Returns the set of recommendations for a given phase and audience.
 *
 * @param phase      Current campaign phase.
 * @param isCreator  Whether to return creator or contributor recommendations.
 * @returns Ordered array of `Recommendation` objects.
 */
export function getRecommendations(
  phase: CampaignPhase,
  isCreator: boolean
): Recommendation[] {
  if (isCreator) {
    return CREATOR_RECOMMENDATIONS[phase];
  }
  return CONTRIBUTOR_RECOMMENDATIONS[phase];
}

// ── Static recommendation tables ─────────────────────────────────────────────

const CREATOR_RECOMMENDATIONS: Record<CampaignPhase, Recommendation[]> = {
  pre_launch: [
    {
      id: "creator-share",
      icon: "📣",
      heading: "Share your campaign",
      body: "Post your campaign link on social media to attract your first backers.",
    },
    {
      id: "creator-story",
      icon: "✍️",
      heading: "Refine your story",
      body: "A compelling description increases backer confidence and conversion.",
    },
  ],
  early: [
    {
      id: "creator-thank",
      icon: "🙏",
      heading: "Thank your early backers",
      body: "A personal message to your first contributors builds community trust.",
    },
    {
      id: "creator-momentum",
      icon: "🚀",
      heading: "Keep the momentum going",
      body: "Share an update post — campaigns with regular updates raise 3× more.",
    },
  ],
  halfway: [
    {
      id: "creator-update",
      icon: "📢",
      heading: "Post a progress update",
      body: "Let backers know you have hit 50 % — social proof attracts new contributors.",
    },
    {
      id: "creator-stretch",
      icon: "🎯",
      heading: "Tease a stretch goal",
      body: "Announcing a stretch goal at the halfway point re-energises your audience.",
    },
  ],
  final_push: [
    {
      id: "creator-urgency",
      icon: "⏰",
      heading: "Create urgency",
      body: "Remind your network of the deadline — scarcity drives last-minute contributions.",
    },
    {
      id: "creator-influencer",
      icon: "🤝",
      heading: "Reach out to influencers",
      body: "A single share from a trusted voice can close the remaining gap.",
    },
  ],
  funded: [
    {
      id: "creator-celebrate",
      icon: "🎉",
      heading: "Celebrate with your community",
      body: "Post a heartfelt thank-you — your backers made this happen.",
    },
    {
      id: "creator-deliver",
      icon: "📦",
      heading: "Share your delivery plan",
      body: "Publish a timeline so backers know what to expect next.",
    },
  ],
};

const CONTRIBUTOR_RECOMMENDATIONS: Record<CampaignPhase, Recommendation[]> = {
  pre_launch: [
    {
      id: "contrib-first",
      icon: "⭐",
      heading: "Be the first backer",
      body: "Early contributions signal confidence and encourage others to follow.",
    },
  ],
  early: [
    {
      id: "contrib-spread",
      icon: "📣",
      heading: "Spread the word",
      body: "Share the campaign with friends — your network can make a real difference.",
    },
  ],
  halfway: [
    {
      id: "contrib-double",
      icon: "💪",
      heading: "Consider increasing your pledge",
      body: "The campaign is halfway there — a top-up now helps cross the finish line.",
    },
  ],
  final_push: [
    {
      id: "contrib-invite",
      icon: "📨",
      heading: "Invite one more person",
      body: "The campaign is in the final stretch — one more backer could make the difference.",
    },
  ],
  funded: [
    {
      id: "contrib-celebrate",
      icon: "🎊",
      heading: "Congratulations!",
      body: "You helped make this campaign a success. Stay tuned for updates from the creator.",
    },
  ],
};

// ── Component ────────────────────────────────────────────────────────────────

/**
 * @notice Renders a contextual list of recommendations for the current
 *         campaign phase, tailored to either the creator or a contributor.
 */
const CelebrationRecommendations: React.FC<CelebrationRecommendationsProps> = ({
  totalRaised,
  goal,
  isCreator = false,
}) => {
  const safeRaised = sanitize(totalRaised);
  const safeGoal = sanitize(goal);

  const { phase, recommendations } = useMemo(() => {
    if (safeGoal === 0) {
      return { phase: "pre_launch" as CampaignPhase, recommendations: [] };
    }
    const pct = Math.min((safeRaised / safeGoal) * 100, 100);
    const p = derivePhase(pct);
    return { phase: p, recommendations: getRecommendations(p, isCreator) };
  }, [safeRaised, safeGoal, isCreator]);

  if (safeGoal === 0) {
    return (
      <div
        className="celebration-recommendations"
        data-testid="celebration-recommendations"
      >
        <p
          className="celebration-recommendations__error"
          data-testid="recommendations-error"
        >
          Invalid campaign goal.
        </p>
      </div>
    );
  }

  return (
    <div
      className="celebration-recommendations"
      data-testid="celebration-recommendations"
    >
      <p
        className="celebration-recommendations__phase"
        data-testid="recommendations-phase"
      >
        {phase}
      </p>
      <ul
        className="celebration-recommendations__list"
        role="list"
        data-testid="recommendations-list"
      >
        {recommendations.map((rec) => (
          <li
            key={rec.id}
            className="celebration-recommendations__item"
            role="listitem"
            data-testid={`recommendation-${rec.id}`}
          >
            <span
              className="celebration-recommendations__icon"
              aria-hidden="true"
            >
              {rec.icon}
            </span>
            <span className="celebration-recommendations__heading">
              {rec.heading}
            </span>
            <span className="celebration-recommendations__body">{rec.body}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default CelebrationRecommendations;
