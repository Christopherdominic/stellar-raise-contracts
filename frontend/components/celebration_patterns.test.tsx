/**
 * @title CelebrationPatterns — Comprehensive Test Suite
 * @notice Covers pure helpers, component rendering, milestone resolution,
 *         auto-dismiss, manual dismiss, and accessibility attributes.
 * @dev Targets ≥ 95% coverage of celebration_patterns.tsx.
 */
import React from "react";
import { render, screen, act, fireEvent } from "@testing-library/react";
import CelebrationPatterns, {
  AUTO_DISMISS_MS,
  BPS_SCALE,
  CONFETTI_COUNT,
  MAX_MESSAGE_LENGTH,
  MAX_TITLE_LENGTH,
  buildConfettiParticles,
  computeProgressRingDashOffset,
  isValidMilestone,
  resolveTriggeredMilestone,
  sanitizeCelebrationText,
  type CelebrationPatternsProps,
  type Milestone,
} from "./celebration_patterns";

// ── Helpers ───────────────────────────────────────────────────────────────────

const MILESTONE_50: Milestone = {
  thresholdBps: 5_000,
  title: "Halfway There!",
  message: "You have reached 50% of your goal.",
};

const MILESTONE_100: Milestone = {
  thresholdBps: 10_000,
  title: "Goal Reached!",
  message: "The campaign has hit its funding goal.",
};

function renderCelebration(props: Partial<CelebrationPatternsProps> = {}) {
  return render(
    <CelebrationPatterns
      progressBps={5_000}
      milestones={[MILESTONE_50]}
      autoDismissMs={0}
      {...props}
    />,
  );
}

// ── sanitizeCelebrationText ───────────────────────────────────────────────────

describe("sanitizeCelebrationText", () => {
  it("returns empty string for non-string input", () => {
    expect(sanitizeCelebrationText(null, 60)).toBe("");
    expect(sanitizeCelebrationText(undefined, 60)).toBe("");
    expect(sanitizeCelebrationText(42, 60)).toBe("");
    expect(sanitizeCelebrationText({}, 60)).toBe("");
  });

  it("returns empty string for blank or whitespace-only strings", () => {
    expect(sanitizeCelebrationText("", 60)).toBe("");
    expect(sanitizeCelebrationText("   ", 60)).toBe("");
    expect(sanitizeCelebrationText("\n\t", 60)).toBe("");
  });

  it("strips control characters and normalizes whitespace", () => {
    expect(sanitizeCelebrationText("Goal\u0000Reached", 60)).toBe("Goal Reached");
    expect(sanitizeCelebrationText("Goal  \n  Reached", 60)).toBe("Goal Reached");
  });

  it("returns the string unchanged when within maxLen", () => {
    const s = "A".repeat(60);
    expect(sanitizeCelebrationText(s, 60)).toBe(s);
  });

  it("truncates strings exceeding maxLen with ellipsis", () => {
    const long = "A".repeat(200);
    const result = sanitizeCelebrationText(long, 60);
    expect(result.length).toBe(60);
    expect(result.endsWith("...")).toBe(true);
  });

  it("respects the maxLen parameter independently", () => {
    const s = "Hello World";
    expect(sanitizeCelebrationText(s, 5)).toBe("He...");
  });
});

// ── isValidMilestone ──────────────────────────────────────────────────────────

describe("isValidMilestone", () => {
  it("returns true for a well-formed milestone", () => {
    expect(isValidMilestone(MILESTONE_50)).toBe(true);
  });

  it("returns false for non-object values", () => {
    expect(isValidMilestone(null)).toBe(false);
    expect(isValidMilestone(undefined)).toBe(false);
    expect(isValidMilestone("string")).toBe(false);
    expect(isValidMilestone(42)).toBe(false);
  });

  it("returns false when thresholdBps is 0", () => {
    expect(isValidMilestone({ ...MILESTONE_50, thresholdBps: 0 })).toBe(false);
  });

  it("returns false when thresholdBps exceeds BPS_SCALE", () => {
    expect(isValidMilestone({ ...MILESTONE_50, thresholdBps: BPS_SCALE + 1 })).toBe(false);
  });

  it("returns false when thresholdBps is negative", () => {
    expect(isValidMilestone({ ...MILESTONE_50, thresholdBps: -1 })).toBe(false);
  });

  it("returns false when title is empty or invalid", () => {
    expect(isValidMilestone({ ...MILESTONE_50, title: "" })).toBe(false);
    expect(isValidMilestone({ ...MILESTONE_50, title: "   " })).toBe(false);
    expect(isValidMilestone({ ...MILESTONE_50, title: 42 })).toBe(false);
  });

  it("returns false when message is empty or invalid", () => {
    expect(isValidMilestone({ ...MILESTONE_50, message: "" })).toBe(false);
    expect(isValidMilestone({ ...MILESTONE_50, message: null })).toBe(false);
  });

  it("accepts thresholdBps = 1 (minimum valid)", () => {
    expect(isValidMilestone({ ...MILESTONE_50, thresholdBps: 1 })).toBe(true);
  });

  it("accepts thresholdBps = BPS_SCALE (maximum valid)", () => {
    expect(isValidMilestone({ ...MILESTONE_50, thresholdBps: BPS_SCALE })).toBe(true);
  });
});

// ── resolveTriggeredMilestone ─────────────────────────────────────────────────

describe("resolveTriggeredMilestone", () => {
  const milestones = [MILESTONE_50, MILESTONE_100];

  it("returns null when progressBps is 0", () => {
    expect(resolveTriggeredMilestone(0, milestones)).toBeNull();
  });

  it("returns null when progressBps is negative", () => {
    expect(resolveTriggeredMilestone(-1, milestones)).toBeNull();
  });

  it("returns null when no milestone threshold is reached", () => {
    expect(resolveTriggeredMilestone(4_999, milestones)).toBeNull();
  });

  it("returns the 50% milestone at exactly 5000 bps", () => {
    expect(resolveTriggeredMilestone(5_000, milestones)).toEqual(MILESTONE_50);
  });

  it("returns the highest reached milestone (100%) at 10000 bps", () => {
    expect(resolveTriggeredMilestone(10_000, milestones)).toEqual(MILESTONE_100);
  });

  it("returns the 50% milestone when progress is between 50% and 100%", () => {
    expect(resolveTriggeredMilestone(7_500, milestones)).toEqual(MILESTONE_50);
  });

  it("returns null for an empty milestones array", () => {
    expect(resolveTriggeredMilestone(10_000, [])).toBeNull();
  });

  it("handles a single milestone correctly", () => {
    expect(resolveTriggeredMilestone(5_000, [MILESTONE_50])).toEqual(MILESTONE_50);
    expect(resolveTriggeredMilestone(4_999, [MILESTONE_50])).toBeNull();
  });
});

// ── buildConfettiParticles ────────────────────────────────────────────────────

describe("buildConfettiParticles", () => {
  it("returns the requested number of particles", () => {
    expect(buildConfettiParticles(CONFETTI_COUNT)).toHaveLength(CONFETTI_COUNT);
  });

  it("clamps count to minimum of 1", () => {
    expect(buildConfettiParticles(0)).toHaveLength(1);
    expect(buildConfettiParticles(-5)).toHaveLength(1);
  });

  it("clamps count to maximum of 100", () => {
    expect(buildConfettiParticles(200)).toHaveLength(100);
  });

  it("each particle has required CSS properties", () => {
    const particles = buildConfettiParticles(5);
    for (const p of particles) {
      expect(p).toHaveProperty("backgroundColor");
      expect(p).toHaveProperty("position", "absolute");
      expect(p).toHaveProperty("pointerEvents", "none");
    }
  });

  it("does not use user-controlled values in backgroundColor", () => {
    const allowed = new Set(["#4f46e5", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4"]);
    const particles = buildConfettiParticles(30);
    for (const p of particles) {
      expect(allowed.has(p.backgroundColor as string)).toBe(true);
    }
  });
});

// ── computeProgressRingDashOffset ────────────────────────────────────────────

describe("computeProgressRingDashOffset", () => {
  const circumference = 2 * Math.PI * 36; // ~226.2

  it("returns full circumference at 0 bps (empty ring)", () => {
    expect(computeProgressRingDashOffset(0, circumference)).toBeCloseTo(circumference);
  });

  it("returns 0 at 10000 bps (full ring)", () => {
    expect(computeProgressRingDashOffset(10_000, circumference)).toBeCloseTo(0);
  });

  it("returns half circumference at 5000 bps", () => {
    expect(computeProgressRingDashOffset(5_000, circumference)).toBeCloseTo(circumference / 2);
  });

  it("clamps negative progressBps to 0", () => {
    expect(computeProgressRingDashOffset(-100, circumference)).toBeCloseTo(circumference);
  });

  it("clamps progressBps above BPS_SCALE to BPS_SCALE", () => {
    expect(computeProgressRingDashOffset(20_000, circumference)).toBeCloseTo(0);
  });
});

// ── CelebrationPatterns component ────────────────────────────────────────────

describe("CelebrationPatterns", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it("renders nothing when no milestone is reached", () => {
    renderCelebration({ progressBps: 100, milestones: [MILESTONE_50] });
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
  });

  it("renders the overlay when a milestone is reached", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50] });
    expect(screen.getByTestId("celebration-overlay")).toBeInTheDocument();
  });

  it("renders the sanitized title and message", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50] });
    expect(screen.getByText("Halfway There!")).toBeInTheDocument();
    expect(screen.getByText("You have reached 50% of your goal.")).toBeInTheDocument();
  });

  it("renders nothing when milestones list is empty", () => {
    renderCelebration({ progressBps: 10_000, milestones: [] });
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
  });

  it("filters out invalid milestones silently", () => {
    const invalid = { thresholdBps: 0, title: "", message: "" } as Milestone;
    renderCelebration({ progressBps: 5_000, milestones: [invalid] });
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
  });

  it("dismisses when the dismiss button is clicked", () => {
    const onDismiss = jest.fn();
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50], onDismiss });
    fireEvent.click(screen.getByTestId("dismiss-btn"));
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("auto-dismisses after autoDismissMs", () => {
    const onDismiss = jest.fn();
    renderCelebration({
      progressBps: 5_000,
      milestones: [MILESTONE_50],
      onDismiss,
      autoDismissMs: 3_000,
    });
    expect(screen.getByTestId("celebration-overlay")).toBeInTheDocument();
    act(() => jest.advanceTimersByTime(3_000));
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("does not auto-dismiss when autoDismissMs is 0", () => {
    renderCelebration({
      progressBps: 5_000,
      milestones: [MILESTONE_50],
      autoDismissMs: 0,
    });
    act(() => jest.advanceTimersByTime(60_000));
    expect(screen.getByTestId("celebration-overlay")).toBeInTheDocument();
  });

  it("shows the highest reached milestone when multiple are triggered", () => {
    renderCelebration({
      progressBps: 10_000,
      milestones: [MILESTONE_50, MILESTONE_100],
      autoDismissMs: 0,
    });
    expect(screen.getByText("Goal Reached!")).toBeInTheDocument();
  });

  it("has correct ARIA role and aria-live attributes", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50] });
    const overlay = screen.getByTestId("celebration-overlay");
    expect(overlay).toHaveAttribute("role", "status");
    expect(overlay).toHaveAttribute("aria-live", "polite");
  });

  it("aria-label includes the milestone title", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50] });
    const overlay = screen.getByTestId("celebration-overlay");
    expect(overlay).toHaveAttribute("aria-label", "Milestone reached: Halfway There!");
  });

  it("dismiss button has accessible aria-label", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50] });
    expect(screen.getByTestId("dismiss-btn")).toHaveAttribute("aria-label", "Dismiss celebration");
  });

  it("re-shows after progress advances to a new milestone", () => {
    const { rerender } = renderCelebration({
      progressBps: 5_000,
      milestones: [MILESTONE_50, MILESTONE_100],
      autoDismissMs: 0,
    });
    fireEvent.click(screen.getByTestId("dismiss-btn"));
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();

    rerender(
      <CelebrationPatterns
        progressBps={10_000}
        milestones={[MILESTONE_50, MILESTONE_100]}
        autoDismissMs={0}
      />,
    );
    expect(screen.getByTestId("celebration-overlay")).toBeInTheDocument();
    expect(screen.getByText("Goal Reached!")).toBeInTheDocument();
  });

  it("renders without onDismiss prop (no crash)", () => {
    renderCelebration({ progressBps: 5_000, milestones: [MILESTONE_50], onDismiss: undefined });
    fireEvent.click(screen.getByTestId("dismiss-btn"));
    expect(screen.queryByTestId("celebration-overlay")).toBeNull();
  });

  it("does not render user input as HTML (XSS guard)", () => {
    const xss: Milestone = {
      thresholdBps: 5_000,
      title: "<script>alert(1)</script>",
      message: "<img src=x onerror=alert(1)>",
    };
    renderCelebration({ progressBps: 5_000, milestones: [xss], autoDismissMs: 0 });
    const overlay = screen.getByTestId("celebration-overlay");
    // React escapes the strings — no live <script> or onerror attribute in the DOM
    expect(overlay.querySelector("script")).toBeNull();
    expect(overlay.querySelector("[onerror]")).toBeNull();
    // The text content is present as escaped plain text, not as executable HTML
    expect(overlay.innerHTML).toContain("&lt;script&gt;");
    expect(overlay.innerHTML).toContain("&lt;img");
  });
});
