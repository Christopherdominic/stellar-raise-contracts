/**
 * @title CelebrationOverlay — Comprehensive Test Suite
 * @notice Covers pure helpers, rendering, accessibility, and edge cases.
 * @dev Targets ≥ 95% coverage of celebration_optimization.tsx.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import CelebrationOverlay, {
  isMilestoneReached,
  getMilestonePercent,
  normalizeCelebrationMessage,
  createParticle,
  stepParticle,
  type CelebrationOverlayProps,
} from "./celebration_optimization";

// ── Canvas mock ───────────────────────────────────────────────────────────────

const mockCtx = {
  clearRect: jest.fn(),
  save: jest.fn(),
  restore: jest.fn(),
  translate: jest.fn(),
  rotate: jest.fn(),
  fillRect: jest.fn(),
  fillStyle: "",
};

beforeAll(() => {
  HTMLCanvasElement.prototype.getContext = jest.fn(() => mockCtx as unknown as CanvasRenderingContext2D);
});

beforeEach(() => jest.clearAllMocks());

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderOverlay(props: Partial<CelebrationOverlayProps> = {}) {
  return render(
    <CelebrationOverlay raised={1000} goal={1000} {...props} />
  );
}

// ── isMilestoneReached ────────────────────────────────────────────────────────

describe("isMilestoneReached", () => {
  it("returns true when raised equals goal", () => {
    expect(isMilestoneReached(1000, 1000)).toBe(true);
  });

  it("returns true when raised exceeds goal", () => {
    expect(isMilestoneReached(1500, 1000)).toBe(true);
  });

  it("returns false when raised is below goal", () => {
    expect(isMilestoneReached(999, 1000)).toBe(false);
  });

  it("returns false when goal is zero", () => {
    expect(isMilestoneReached(0, 0)).toBe(false);
  });

  it("returns false when goal is negative", () => {
    expect(isMilestoneReached(100, -1)).toBe(false);
  });

  it("returns false for NaN inputs", () => {
    expect(isMilestoneReached(NaN, 1000)).toBe(false);
    expect(isMilestoneReached(1000, NaN)).toBe(false);
  });

  it("returns false for Infinity inputs", () => {
    expect(isMilestoneReached(Infinity, 1000)).toBe(false);
    expect(isMilestoneReached(1000, Infinity)).toBe(false);
  });
});

// ── getMilestonePercent ───────────────────────────────────────────────────────

describe("getMilestonePercent", () => {
  it("returns 100 when raised equals goal", () => {
    expect(getMilestonePercent(1000, 1000)).toBe(100);
  });

  it("returns 100 when raised exceeds goal (clamped)", () => {
    expect(getMilestonePercent(2000, 1000)).toBe(100);
  });

  it("returns 50 for half-funded campaign", () => {
    expect(getMilestonePercent(500, 1000)).toBe(50);
  });

  it("returns 0 when raised is 0", () => {
    expect(getMilestonePercent(0, 1000)).toBe(0);
  });

  it("returns 0 when goal is 0", () => {
    expect(getMilestonePercent(500, 0)).toBe(0);
  });

  it("returns 0 for NaN inputs", () => {
    expect(getMilestonePercent(NaN, 1000)).toBe(0);
    expect(getMilestonePercent(500, NaN)).toBe(0);
  });

  it("rounds to nearest integer", () => {
    expect(getMilestonePercent(1, 3)).toBe(33);
  });
});

// ── normalizeCelebrationMessage ───────────────────────────────────────────────

describe("normalizeCelebrationMessage", () => {
  it("returns the message when valid", () => {
    expect(normalizeCelebrationMessage("Goal Reached!", "fallback")).toBe("Goal Reached!");
  });

  it("returns fallback for empty string", () => {
    expect(normalizeCelebrationMessage("", "fallback")).toBe("fallback");
  });

  it("returns fallback for whitespace-only string", () => {
    expect(normalizeCelebrationMessage("   ", "fallback")).toBe("fallback");
  });

  it("returns fallback for non-string values", () => {
    expect(normalizeCelebrationMessage(null, "fallback")).toBe("fallback");
    expect(normalizeCelebrationMessage(undefined, "fallback")).toBe("fallback");
    expect(normalizeCelebrationMessage(42, "fallback")).toBe("fallback");
    expect(normalizeCelebrationMessage({}, "fallback")).toBe("fallback");
  });

  it("trims surrounding whitespace", () => {
    expect(normalizeCelebrationMessage("  Hello  ", "fallback")).toBe("Hello");
  });
});

// ── createParticle ────────────────────────────────────────────────────────────

describe("createParticle", () => {
  it("returns a particle with expected shape", () => {
    const p = createParticle(800);
    expect(typeof p.x).toBe("number");
    expect(typeof p.y).toBe("number");
    expect(typeof p.vx).toBe("number");
    expect(typeof p.vy).toBe("number");
    expect(typeof p.color).toBe("string");
    expect(p.color).toMatch(/^#/);
    expect(p.size).toBeGreaterThan(0);
  });

  it("places particle within canvas width", () => {
    for (let i = 0; i < 20; i++) {
      const p = createParticle(500);
      expect(p.x).toBeGreaterThanOrEqual(0);
      expect(p.x).toBeLessThan(500);
    }
  });

  it("starts particle above the canvas (negative y)", () => {
    for (let i = 0; i < 20; i++) {
      const p = createParticle(500);
      expect(p.y).toBeLessThanOrEqual(0);
    }
  });
});

// ── stepParticle ──────────────────────────────────────────────────────────────

describe("stepParticle", () => {
  it("advances position by velocity", () => {
    const p = createParticle(800);
    const next = stepParticle(p);
    expect(next.x).toBeCloseTo(p.x + p.vx);
    expect(next.y).toBeCloseTo(p.y + p.vy);
  });

  it("applies gravity to vy", () => {
    const p = createParticle(800);
    const next = stepParticle(p);
    expect(next.vy).toBeGreaterThan(p.vy);
  });

  it("advances rotation", () => {
    const p = createParticle(800);
    const next = stepParticle(p);
    expect(next.rotation).toBeCloseTo(p.rotation + p.rotationSpeed);
  });

  it("does not mutate the original particle", () => {
    const p = createParticle(800);
    const origY = p.y;
    stepParticle(p);
    expect(p.y).toBe(origY);
  });
});

// ── CelebrationOverlay rendering ──────────────────────────────────────────────

describe("CelebrationOverlay", () => {
  it("renders nothing when goal not reached", () => {
    const { container } = render(
      <CelebrationOverlay raised={500} goal={1000} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders overlay when goal is reached", () => {
    renderOverlay();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("renders overlay when raised exceeds goal", () => {
    renderOverlay({ raised: 1500, goal: 1000 });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("displays default message when none provided", () => {
    renderOverlay();
    expect(screen.getByText("🎉 Goal Reached!")).toBeInTheDocument();
  });

  it("displays custom message when provided", () => {
    renderOverlay({ message: "Amazing!" });
    expect(screen.getByText("Amazing!")).toBeInTheDocument();
  });

  it("falls back to default message for empty string", () => {
    renderOverlay({ message: "" });
    expect(screen.getByText("🎉 Goal Reached!")).toBeInTheDocument();
  });

  it("shows funding percentage and amounts", () => {
    renderOverlay({ raised: 500, goal: 500 });
    expect(screen.getByText(/100%/)).toBeInTheDocument();
  });

  it("renders dismiss button when onDismiss provided", () => {
    renderOverlay({ onDismiss: jest.fn() });
    expect(screen.getByRole("button", { name: /dismiss/i })).toBeInTheDocument();
  });

  it("does not render dismiss button when onDismiss is absent", () => {
    renderOverlay();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("calls onDismiss when Continue button is clicked", () => {
    const onDismiss = jest.fn();
    renderOverlay({ onDismiss });
    fireEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("has correct ARIA attributes", () => {
    renderOverlay();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", "Campaign milestone celebration");
  });

  it("canvas is aria-hidden", () => {
    renderOverlay();
    const canvas = document.querySelector("canvas");
    expect(canvas).toHaveAttribute("aria-hidden", "true");
  });

  it("renders nothing for zero goal (guard against division by zero)", () => {
    const { container } = render(
      <CelebrationOverlay raised={0} goal={0} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing for NaN inputs", () => {
    const { container } = render(
      <CelebrationOverlay raised={NaN} goal={1000} />
    );
    expect(container.firstChild).toBeNull();
  });
});
