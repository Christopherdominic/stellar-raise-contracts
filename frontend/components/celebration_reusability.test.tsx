/**
 * @title MilestoneCelebration — Test Suite
 * @notice Covers pure helpers, rendering, interaction, auto-dismiss,
 *         accessibility, and edge cases. Targets ≥ 95% coverage.
 */
import React from "react";
import { render, screen, fireEvent, act } from "@testing-library/react";
import MilestoneCelebration, {
  normalizeMilestoneLabel,
  resolveTierEmoji,
  isCelebrationVisible,
  DEFAULT_DURATION,
  MAX_LABEL_LENGTH,
  type MilestoneTier,
  type MilestoneCelebrationProps,
} from "./celebration_reusability";

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderCelebration(props: Partial<MilestoneCelebrationProps> = {}) {
  return render(
    <MilestoneCelebration visible={true} label="50% funded!" {...props} />
  );
}

beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.runOnlyPendingTimers());
afterEach(() => jest.useRealTimers());

// ── normalizeMilestoneLabel ───────────────────────────────────────────────────

describe("normalizeMilestoneLabel", () => {
  it("returns fallback for non-string input", () => {
    expect(normalizeMilestoneLabel(null, "fallback")).toBe("fallback");
    expect(normalizeMilestoneLabel(undefined, "fallback")).toBe("fallback");
    expect(normalizeMilestoneLabel(42, "fallback")).toBe("fallback");
    expect(normalizeMilestoneLabel({}, "fallback")).toBe("fallback");
  });

  it("returns fallback for empty or whitespace-only strings", () => {
    expect(normalizeMilestoneLabel("", "fallback")).toBe("fallback");
    expect(normalizeMilestoneLabel("   ", "fallback")).toBe("fallback");
    expect(normalizeMilestoneLabel("\n\t", "fallback")).toBe("fallback");
  });

  it("strips control characters and collapses whitespace", () => {
    expect(normalizeMilestoneLabel("Goal\u0000Reached", "fb")).toBe("Goal Reached");
    expect(normalizeMilestoneLabel("50%   funded", "fb")).toBe("50% funded");
  });

  it("returns the label unchanged when within MAX_LABEL_LENGTH", () => {
    const label = "A".repeat(MAX_LABEL_LENGTH);
    expect(normalizeMilestoneLabel(label, "fb")).toBe(label);
  });

  it("truncates labels exceeding MAX_LABEL_LENGTH with ellipsis", () => {
    const long = "A".repeat(MAX_LABEL_LENGTH + 20);
    const result = normalizeMilestoneLabel(long, "fb");
    expect(result).toHaveLength(MAX_LABEL_LENGTH);
    expect(result.endsWith("...")).toBe(true);
  });
});

// ── resolveTierEmoji ──────────────────────────────────────────────────────────

describe("resolveTierEmoji", () => {
  it("returns the tier default when emoji is undefined", () => {
    expect(resolveTierEmoji(undefined, "gold")).toBe("🏆");
    expect(resolveTierEmoji(undefined, "silver")).toBe("🥈");
    expect(resolveTierEmoji(undefined, "bronze")).toBe("🥉");
    expect(resolveTierEmoji(undefined, "platinum")).toBe("💎");
  });

  it("returns the tier default when emoji is empty string", () => {
    expect(resolveTierEmoji("", "gold")).toBe("🏆");
    expect(resolveTierEmoji("   ", "gold")).toBe("🏆");
  });

  it("returns the caller-supplied emoji when valid", () => {
    expect(resolveTierEmoji("🎉", "gold")).toBe("🎉");
    expect(resolveTierEmoji("  🚀  ", "silver")).toBe("🚀");
  });
});

// ── isCelebrationVisible ──────────────────────────────────────────────────────

describe("isCelebrationVisible", () => {
  it("returns true when visible and label is non-empty", () => {
    expect(isCelebrationVisible(true, "50% funded!")).toBe(true);
  });

  it("returns false when visible is false", () => {
    expect(isCelebrationVisible(false, "50% funded!")).toBe(false);
  });

  it("returns false when label is empty", () => {
    expect(isCelebrationVisible(true, "")).toBe(false);
  });

  it("returns false when both are falsy", () => {
    expect(isCelebrationVisible(false, "")).toBe(false);
  });
});

// ── Rendering ─────────────────────────────────────────────────────────────────

describe("MilestoneCelebration rendering", () => {
  it("renders when visible=true with a valid label", () => {
    renderCelebration();
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
  });

  it("renders nothing when visible=false", () => {
    renderCelebration({ visible: false });
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
  });

  it("renders nothing when label is empty", () => {
    renderCelebration({ label: "" });
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
  });

  it("displays the milestone label", () => {
    renderCelebration({ label: "Goal reached!" });
    expect(screen.getByTestId("celebration-label").textContent).toBe("Goal reached!");
  });

  it("uses fallback label when label is whitespace-only", () => {
    renderCelebration({ label: "   " });
    // whitespace-only normalizes to fallback, so component renders with fallback
    expect(screen.getByTestId("celebration-label").textContent).toBe("Milestone reached!");
  });

  it("shows the dismiss button", () => {
    renderCelebration();
    expect(screen.getByTestId("celebration-dismiss")).toBeTruthy();
  });

  it("does not render CTA button when ctaLabel is omitted", () => {
    renderCelebration();
    expect(screen.queryByTestId("celebration-cta")).toBeNull();
  });

  it("renders CTA button when ctaLabel is provided", () => {
    renderCelebration({ ctaLabel: "Share" });
    expect(screen.getByTestId("celebration-cta")).toBeTruthy();
    expect(screen.getByTestId("celebration-cta").textContent).toBe("Share");
  });

  it("applies custom className to root element", () => {
    renderCelebration({ className: "my-celebration" });
    expect(screen.getByTestId("milestone-celebration").className).toContain("my-celebration");
  });

  it("sets data-tier attribute to the tier value", () => {
    renderCelebration({ tier: "platinum" });
    expect(screen.getByTestId("milestone-celebration").getAttribute("data-tier")).toBe("platinum");
  });
});

// ── Tier emoji defaults ───────────────────────────────────────────────────────

describe("Tier emoji defaults", () => {
  const tiers: MilestoneTier[] = ["bronze", "silver", "gold", "platinum"];
  const expected = ["🥉", "🥈", "🏆", "💎"];

  tiers.forEach((tier, i) => {
    it(`shows correct default emoji for ${tier}`, () => {
      renderCelebration({ tier });
      expect(screen.getByTestId("celebration-emoji").textContent).toBe(expected[i]);
    });
  });

  it("shows custom emoji when provided", () => {
    renderCelebration({ emoji: "🎊" });
    expect(screen.getByTestId("celebration-emoji").textContent).toBe("🎊");
  });
});

// ── Dismiss interaction ───────────────────────────────────────────────────────

describe("Dismiss interaction", () => {
  it("hides the overlay when dismiss button is clicked", () => {
    renderCelebration();
    fireEvent.click(screen.getByTestId("celebration-dismiss"));
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
  });

  it("calls onDismiss when dismiss button is clicked", () => {
    const onDismiss = jest.fn();
    renderCelebration({ onDismiss });
    fireEvent.click(screen.getByTestId("celebration-dismiss"));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("does not throw when onDismiss is not provided", () => {
    renderCelebration();
    expect(() => fireEvent.click(screen.getByTestId("celebration-dismiss"))).not.toThrow();
  });
});

// ── CTA interaction ───────────────────────────────────────────────────────────

describe("CTA interaction", () => {
  it("calls onCta when CTA button is clicked", () => {
    const onCta = jest.fn();
    renderCelebration({ ctaLabel: "Share", onCta });
    fireEvent.click(screen.getByTestId("celebration-cta"));
    expect(onCta).toHaveBeenCalledTimes(1);
  });

  it("does not throw when onCta is not provided", () => {
    renderCelebration({ ctaLabel: "Share" });
    expect(() => fireEvent.click(screen.getByTestId("celebration-cta"))).not.toThrow();
  });
});

// ── Auto-dismiss ──────────────────────────────────────────────────────────────

describe("Auto-dismiss", () => {
  it("auto-dismisses after DEFAULT_DURATION", () => {
    const onDismiss = jest.fn();
    renderCelebration({ onDismiss });
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
    act(() => jest.advanceTimersByTime(DEFAULT_DURATION));
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("auto-dismisses after a custom duration", () => {
    const onDismiss = jest.fn();
    renderCelebration({ duration: 1000, onDismiss });
    act(() => jest.advanceTimersByTime(999));
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
    act(() => jest.advanceTimersByTime(1));
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
  });

  it("does NOT auto-dismiss when autoDismiss=false", () => {
    const onDismiss = jest.fn();
    renderCelebration({ autoDismiss: false, onDismiss });
    act(() => jest.advanceTimersByTime(DEFAULT_DURATION * 2));
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("clears the timer when dismiss button is clicked before timeout", () => {
    const onDismiss = jest.fn();
    renderCelebration({ onDismiss });
    fireEvent.click(screen.getByTestId("celebration-dismiss"));
    act(() => jest.advanceTimersByTime(DEFAULT_DURATION));
    // onDismiss called once (from click), not twice
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

// ── Visibility re-show ────────────────────────────────────────────────────────

describe("Visibility re-show", () => {
  it("re-shows when visible flips from false to true", () => {
    const { rerender } = renderCelebration({ visible: false });
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
    rerender(<MilestoneCelebration visible={true} label="New milestone!" />);
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
  });

  it("re-shows after dismiss when visible cycles true→false→true", () => {
    const { rerender } = renderCelebration();
    fireEvent.click(screen.getByTestId("celebration-dismiss"));
    expect(screen.queryByTestId("milestone-celebration")).toBeNull();
    rerender(<MilestoneCelebration visible={false} label="50% funded!" />);
    rerender(<MilestoneCelebration visible={true} label="50% funded!" />);
    expect(screen.getByTestId("milestone-celebration")).toBeTruthy();
  });
});

// ── Accessibility ─────────────────────────────────────────────────────────────

describe("Accessibility", () => {
  it("has role='status' on the root element", () => {
    renderCelebration();
    expect(screen.getByRole("status")).toBeTruthy();
  });

  it("has aria-live='polite'", () => {
    renderCelebration();
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
  });

  it("has aria-label containing the milestone label", () => {
    renderCelebration({ label: "Goal hit!" });
    expect(screen.getByRole("status").getAttribute("aria-label")).toContain("Goal hit!");
  });

  it("emoji span is aria-hidden", () => {
    renderCelebration();
    expect(screen.getByTestId("celebration-emoji").getAttribute("aria-hidden")).toBe("true");
  });

  it("dismiss button has aria-label", () => {
    renderCelebration();
    expect(
      screen.getByTestId("celebration-dismiss").getAttribute("aria-label")
    ).toBe("Dismiss milestone celebration");
  });

  it("CTA button has aria-label matching ctaLabel", () => {
    renderCelebration({ ctaLabel: "View campaign" });
    expect(
      screen.getByTestId("celebration-cta").getAttribute("aria-label")
    ).toBe("View campaign");
  });
});

// ── Constants ─────────────────────────────────────────────────────────────────

describe("Constants", () => {
  it("DEFAULT_DURATION is 4000ms", () => {
    expect(DEFAULT_DURATION).toBe(4000);
  });

  it("MAX_LABEL_LENGTH is 120", () => {
    expect(MAX_LABEL_LENGTH).toBe(120);
  });
});
