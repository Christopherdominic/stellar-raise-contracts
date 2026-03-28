/**
 * @title CelebrationPersonalization — Comprehensive Test Suite
 * @notice Covers sanitization helpers, emoji resolution, message building,
 *         component rendering, auto-dismiss, manual dismiss, and accessibility.
 * @dev Targets ≥ 95% coverage of celebration_personalization.tsx.
 */
import React from "react";
import { render, screen, act, fireEvent } from "@testing-library/react";
import CelebrationPersonalization, {
  ALLOWED_EMOJI,
  MAX_MESSAGE_LENGTH,
  MILESTONE_TIERS,
  resolveEmoji,
  resolveMilestoneMessage,
  sanitizeCelebrationText,
  type CelebrationPersonalizationProps,
  type MilestoneEmoji,
  type MilestoneTier,
} from "./celebration_personalization";

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderBanner(props: Partial<CelebrationPersonalizationProps> = {}) {
  return render(
    <CelebrationPersonalization tier="goal" visible={true} {...props} />,
  );
}

const ALL_TIERS = Object.keys(MILESTONE_TIERS) as MilestoneTier[];

// ── sanitizeCelebrationText ───────────────────────────────────────────────────

describe("sanitizeCelebrationText", () => {
  it("returns fallback for non-string values", () => {
    expect(sanitizeCelebrationText(undefined, "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText(null, "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText(42, "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText({}, "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText(true, "fallback")).toBe("fallback");
  });

  it("returns fallback for empty or whitespace-only strings", () => {
    expect(sanitizeCelebrationText("", "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText("   ", "fallback")).toBe("fallback");
    expect(sanitizeCelebrationText("\n\t", "fallback")).toBe("fallback");
  });

  it("strips control characters and normalizes whitespace", () => {
    expect(sanitizeCelebrationText("Hello\u0000World", "fb")).toBe("Hello World");
    expect(sanitizeCelebrationText("A\u001FB", "fb")).toBe("A B");
    expect(sanitizeCelebrationText("A   \n   B", "fb")).toBe("A B");
  });

  it("returns the string unchanged when within MAX_MESSAGE_LENGTH", () => {
    const msg = "A".repeat(MAX_MESSAGE_LENGTH);
    expect(sanitizeCelebrationText(msg, "fb")).toBe(msg);
  });

  it("truncates strings exceeding MAX_MESSAGE_LENGTH with ellipsis", () => {
    const long = "A".repeat(200);
    const result = sanitizeCelebrationText(long, "fb");
    expect(result).toHaveLength(MAX_MESSAGE_LENGTH);
    expect(result.endsWith("...")).toBe(true);
  });

  it("treats markup-like strings as plain text (no HTML injection)", () => {
    const xss = "<script>alert(1)</script>";
    expect(sanitizeCelebrationText(xss, "fb")).toBe(xss);
  });
});

// ── resolveEmoji ──────────────────────────────────────────────────────────────

describe("resolveEmoji", () => {
  it("returns the candidate when it is in ALLOWED_EMOJI", () => {
    ALLOWED_EMOJI.forEach((e) => {
      expect(resolveEmoji(e, "goal")).toBe(e);
    });
  });

  it("returns the tier default for unknown emoji", () => {
    expect(resolveEmoji("😈", "goal")).toBe(MILESTONE_TIERS.goal.defaultEmoji);
    expect(resolveEmoji("😈", "half")).toBe(MILESTONE_TIERS.half.defaultEmoji);
  });

  it("returns the tier default for non-string values", () => {
    expect(resolveEmoji(undefined, "quarter")).toBe(MILESTONE_TIERS.quarter.defaultEmoji);
    expect(resolveEmoji(null, "threeQuarter")).toBe(MILESTONE_TIERS.threeQuarter.defaultEmoji);
    expect(resolveEmoji(42, "goal")).toBe(MILESTONE_TIERS.goal.defaultEmoji);
  });

  it("covers every tier's default emoji", () => {
    ALL_TIERS.forEach((tier) => {
      expect(resolveEmoji(undefined, tier)).toBe(MILESTONE_TIERS[tier].defaultEmoji);
    });
  });
});

// ── resolveMilestoneMessage ───────────────────────────────────────────────────

describe("resolveMilestoneMessage", () => {
  it("returns the tier default label when no overrides are given", () => {
    ALL_TIERS.forEach((tier) => {
      expect(resolveMilestoneMessage(tier)).toBe(MILESTONE_TIERS[tier].label);
    });
  });

  it("uses customMessage when provided", () => {
    expect(resolveMilestoneMessage("goal", "We did it!")).toBe("We did it!");
  });

  it("prepends campaignName when provided", () => {
    expect(resolveMilestoneMessage("goal", undefined, "My Campaign")).toBe(
      "My Campaign: Goal reached!",
    );
  });

  it("combines customMessage and campaignName", () => {
    expect(resolveMilestoneMessage("half", "Halfway there!", "Stellar Fund")).toBe(
      "Stellar Fund: Halfway there!",
    );
  });

  it("ignores blank campaignName", () => {
    expect(resolveMilestoneMessage("goal", undefined, "   ")).toBe("Goal reached!");
  });

  it("sanitizes customMessage", () => {
    expect(resolveMilestoneMessage("goal", "Bad\u0000Msg")).toBe("Bad Msg");
  });
});

// ── Component rendering ───────────────────────────────────────────────────────

describe("CelebrationPersonalization rendering", () => {
  it("renders the banner when visible=true", () => {
    renderBanner({ visible: true });
    expect(screen.getByTestId("celebration-banner")).toBeInTheDocument();
  });

  it("renders nothing when visible=false", () => {
    renderBanner({ visible: false });
    expect(screen.queryByTestId("celebration-banner")).not.toBeInTheDocument();
  });

  it("displays the correct default message for each tier", () => {
    ALL_TIERS.forEach((tier) => {
      const { unmount } = renderBanner({ tier });
      expect(screen.getByText(MILESTONE_TIERS[tier].label)).toBeInTheDocument();
      unmount();
    });
  });

  it("displays a custom message", () => {
    renderBanner({ customMessage: "Amazing milestone!" });
    expect(screen.getByText("Amazing milestone!")).toBeInTheDocument();
  });

  it("displays the campaign name in the message", () => {
    renderBanner({ campaignName: "Stellar Fund" });
    expect(screen.getByText(/Stellar Fund/)).toBeInTheDocument();
  });

  it("renders the correct emoji for each tier", () => {
    ALL_TIERS.forEach((tier) => {
      const { unmount } = renderBanner({ tier });
      const banner = screen.getByTestId("celebration-banner");
      expect(banner.textContent).toContain(MILESTONE_TIERS[tier].defaultEmoji);
      unmount();
    });
  });

  it("renders a custom allowed emoji", () => {
    renderBanner({ emoji: "🚀" });
    expect(screen.getByTestId("celebration-banner").textContent).toContain("🚀");
  });

  it("falls back to tier default for disallowed emoji", () => {
    renderBanner({ tier: "goal", emoji: "😈" as MilestoneEmoji });
    expect(screen.getByTestId("celebration-banner").textContent).toContain(
      MILESTONE_TIERS.goal.defaultEmoji,
    );
  });

  it("sets data-tier attribute correctly", () => {
    renderBanner({ tier: "half" });
    expect(screen.getByTestId("celebration-banner")).toHaveAttribute("data-tier", "half");
  });
});

// ── Accessibility ─────────────────────────────────────────────────────────────

describe("accessibility", () => {
  it("has role=status and aria-live=polite", () => {
    renderBanner();
    const banner = screen.getByTestId("celebration-banner");
    expect(banner).toHaveAttribute("role", "status");
    expect(banner).toHaveAttribute("aria-live", "polite");
    expect(banner).toHaveAttribute("aria-atomic", "true");
  });

  it("close button has an accessible label", () => {
    renderBanner();
    expect(screen.getByRole("button", { name: /dismiss celebration/i })).toBeInTheDocument();
  });
});

// ── Manual dismiss ────────────────────────────────────────────────────────────

describe("manual dismiss", () => {
  it("hides the banner when the close button is clicked", () => {
    renderBanner();
    fireEvent.click(screen.getByRole("button", { name: /dismiss celebration/i }));
    expect(screen.queryByTestId("celebration-banner")).not.toBeInTheDocument();
  });

  it("calls onDismiss when the close button is clicked", () => {
    const onDismiss = jest.fn();
    renderBanner({ onDismiss });
    fireEvent.click(screen.getByRole("button", { name: /dismiss celebration/i }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("works without an onDismiss callback (no crash)", () => {
    renderBanner({ onDismiss: undefined });
    expect(() =>
      fireEvent.click(screen.getByRole("button", { name: /dismiss celebration/i })),
    ).not.toThrow();
  });
});

// ── Auto-dismiss ──────────────────────────────────────────────────────────────

describe("auto-dismiss", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it("auto-hides after autoDismissMs", () => {
    renderBanner({ autoDismissMs: 3000 });
    expect(screen.getByTestId("celebration-banner")).toBeInTheDocument();
    act(() => jest.advanceTimersByTime(3000));
    expect(screen.queryByTestId("celebration-banner")).not.toBeInTheDocument();
  });

  it("calls onDismiss after auto-dismiss", () => {
    const onDismiss = jest.fn();
    renderBanner({ autoDismissMs: 2000, onDismiss });
    act(() => jest.advanceTimersByTime(2000));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("does not auto-dismiss when autoDismissMs=0", () => {
    renderBanner({ autoDismissMs: 0 });
    act(() => jest.advanceTimersByTime(10_000));
    expect(screen.getByTestId("celebration-banner")).toBeInTheDocument();
  });

  it("resets dismissed state when visible flips back to true", () => {
    const { rerender } = renderBanner({ visible: true, autoDismissMs: 1000 });
    act(() => jest.advanceTimersByTime(1000));
    expect(screen.queryByTestId("celebration-banner")).not.toBeInTheDocument();

    rerender(
      <CelebrationPersonalization tier="goal" visible={false} autoDismissMs={1000} />,
    );
    rerender(
      <CelebrationPersonalization tier="goal" visible={true} autoDismissMs={1000} />,
    );
    expect(screen.getByTestId("celebration-banner")).toBeInTheDocument();
  });

  it("clears the timer on unmount (no memory leak)", () => {
    const clearSpy = jest.spyOn(globalThis, "clearTimeout");
    const { unmount } = renderBanner({ autoDismissMs: 5000 });
    unmount();
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });
});

// ── Edge cases ────────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("renders without optional props", () => {
    render(<CelebrationPersonalization tier="quarter" visible={true} />);
    expect(screen.getByTestId("celebration-banner")).toBeInTheDocument();
  });

  it("sanitizes a control-character-laden customMessage", () => {
    renderBanner({ customMessage: "Win\u0007ner!" });
    expect(screen.getByText("Win ner!")).toBeInTheDocument();
  });

  it("truncates an excessively long customMessage", () => {
    renderBanner({ customMessage: "A".repeat(200) });
    const banner = screen.getByTestId("celebration-banner");
    expect(banner.textContent).toContain("...");
  });

  it("sanitizes a control-character-laden campaignName", () => {
    renderBanner({ campaignName: "Fund\u0000Me" });
    expect(screen.getByText(/Fund Me/)).toBeInTheDocument();
  });
});
