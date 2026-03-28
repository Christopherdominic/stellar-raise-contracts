import React from "react";
import { render, screen } from "@testing-library/react";
import CelebrationForecasting, {
  sanitize,
  computeVelocity,
  buildMilestones,
  formatEta,
  MILESTONE_FRACTIONS,
  type CelebrationForecastingProps,
} from "./celebration_forecasting";

// ── Helper ───────────────────────────────────────────────────────────────────

/** Renders the component with sensible defaults that can be overridden. */
function renderComponent(overrides: Partial<CelebrationForecastingProps> = {}) {
  const defaults: CelebrationForecastingProps = {
    totalRaised: 500,
    goal: 1000,
    campaignStartTime: 1000,
    currentTime: 2000, // 1000 s elapsed
    ...overrides,
  };
  return render(<CelebrationForecasting {...defaults} />);
}

// ── sanitize ─────────────────────────────────────────────────────────────────

describe("sanitize", () => {
  it("returns the value when finite and non-negative", () => {
    expect(sanitize(42)).toBe(42);
    expect(sanitize(0)).toBe(0);
  });

  it("returns 0 for negative values", () => {
    expect(sanitize(-1)).toBe(0);
    expect(sanitize(-Infinity)).toBe(0);
  });

  it("returns 0 for NaN", () => {
    expect(sanitize(NaN)).toBe(0);
  });

  it("returns 0 for Infinity", () => {
    expect(sanitize(Infinity)).toBe(0);
  });
});

// ── computeVelocity ──────────────────────────────────────────────────────────

describe("computeVelocity", () => {
  it("returns tokens/second when elapsed > 0", () => {
    expect(computeVelocity(500, 1000)).toBe(0.5);
  });

  it("returns 0 when elapsed is 0", () => {
    expect(computeVelocity(500, 0)).toBe(0);
  });

  it("returns 0 when elapsed is negative", () => {
    expect(computeVelocity(500, -100)).toBe(0);
  });

  it("returns 0 when totalRaised is 0", () => {
    expect(computeVelocity(0, 1000)).toBe(0);
  });
});

// ── buildMilestones ──────────────────────────────────────────────────────────

describe("buildMilestones", () => {
  const goal = 1000;
  const now = 2000;

  it("produces one milestone per MILESTONE_FRACTIONS entry", () => {
    const ms = buildMilestones(0, goal, 0, now);
    expect(ms).toHaveLength(MILESTONE_FRACTIONS.length);
  });

  it("marks milestones as reached when totalRaised >= targetAmount", () => {
    const ms = buildMilestones(500, goal, 0.5, now);
    expect(ms[0].reached).toBe(true);  // 25 %
    expect(ms[1].reached).toBe(true);  // 50 %
    expect(ms[2].reached).toBe(false); // 75 %
    expect(ms[3].reached).toBe(false); // 100 %
  });

  it("sets projectedAt to null for reached milestones", () => {
    const ms = buildMilestones(500, goal, 0.5, now);
    expect(ms[0].projectedAt).toBeNull();
    expect(ms[1].projectedAt).toBeNull();
  });

  it("computes projectedAt correctly for unreached milestones", () => {
    // velocity = 0.5 tok/s; 75 % target = 750; remaining = 250; eta = 2000 + 500 = 2500
    const ms = buildMilestones(500, goal, 0.5, now);
    expect(ms[2].projectedAt).toBe(2500);
  });

  it("sets projectedAt to null when velocity is 0", () => {
    const ms = buildMilestones(0, goal, 0, now);
    ms.forEach((m) => expect(m.projectedAt).toBeNull());
  });

  it("labels the 100 % milestone as 'Goal Reached! 🎉' when reached", () => {
    const ms = buildMilestones(1000, goal, 1, now);
    expect(ms[3].label).toBe("Goal Reached! 🎉");
    expect(ms[3].reached).toBe(true);
  });

  it("labels intermediate milestones with percentage", () => {
    const ms = buildMilestones(0, goal, 0, now);
    expect(ms[0].label).toBe("25% Funded");
    expect(ms[1].label).toBe("50% Funded");
    expect(ms[2].label).toBe("75% Funded");
  });

  it("handles totalRaised exactly equal to a milestone target", () => {
    const ms = buildMilestones(250, goal, 0.5, now);
    expect(ms[0].reached).toBe(true);
    expect(ms[0].projectedAt).toBeNull();
  });
});

// ── formatEta ────────────────────────────────────────────────────────────────

describe("formatEta", () => {
  it("returns a non-empty string for a valid timestamp", () => {
    const result = formatEta(1711584000); // some fixed timestamp
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

// ── CelebrationForecasting component ─────────────────────────────────────────

describe("CelebrationForecasting", () => {
  it("renders the root element", () => {
    renderComponent();
    expect(screen.getByTestId("celebration-forecasting")).toBeInTheDocument();
  });

  it("shows an error message when goal is 0", () => {
    renderComponent({ goal: 0 });
    expect(screen.getByText("Invalid campaign goal.")).toBeInTheDocument();
  });

  it("renders the progress bar with correct aria attributes", () => {
    renderComponent({ totalRaised: 500, goal: 1000 });
    const bar = screen.getByTestId("progress-bar");
    expect(bar).toHaveAttribute("aria-valuenow", "50");
    expect(bar).toHaveAttribute("aria-valuemin", "0");
    expect(bar).toHaveAttribute("aria-valuemax", "100");
  });

  it("renders the progress summary text", () => {
    renderComponent({ totalRaised: 500, goal: 1000 });
    expect(screen.getByTestId("progress-summary")).toHaveTextContent("500");
    expect(screen.getByTestId("progress-summary")).toHaveTextContent("1,000");
    expect(screen.getByTestId("progress-summary")).toHaveTextContent("50%");
  });

  it("renders four milestone items", () => {
    renderComponent();
    expect(screen.getByTestId("milestones-list").children).toHaveLength(4);
  });

  it("shows celebration status for reached milestones", () => {
    // 500/1000 → 25 % and 50 % reached
    renderComponent({ totalRaised: 500, goal: 1000 });
    const m25 = screen.getByTestId("milestone-25");
    const m50 = screen.getByTestId("milestone-50");
    expect(m25.querySelector("[role='status']")).toBeInTheDocument();
    expect(m50.querySelector("[role='status']")).toBeInTheDocument();
  });

  it("shows forecast text for unreached milestones", () => {
    renderComponent({ totalRaised: 500, goal: 1000 });
    const m75 = screen.getByTestId("milestone-75");
    expect(m75).toHaveTextContent("75% Funded");
  });

  it("shows 'ETA unavailable' when velocity is zero", () => {
    // campaignStartTime === currentTime → elapsed = 0 → velocity = 0
    renderComponent({ totalRaised: 0, goal: 1000, campaignStartTime: 2000, currentTime: 2000 });
    expect(screen.getAllByText(/ETA unavailable/i).length).toBeGreaterThan(0);
  });

  it("shows projected ETA text when velocity > 0 and milestone not reached", () => {
    renderComponent({ totalRaised: 500, goal: 1000, campaignStartTime: 1000, currentTime: 2000 });
    // 75 % and 100 % not reached; velocity = 0.5 tok/s → ETA should appear
    expect(screen.getAllByText(/projected/i).length).toBeGreaterThan(0);
  });

  it("clamps progress to 100 % when totalRaised exceeds goal", () => {
    renderComponent({ totalRaised: 1500, goal: 1000 });
    const bar = screen.getByTestId("progress-bar");
    expect(bar).toHaveAttribute("aria-valuenow", "100");
  });

  it("handles negative totalRaised gracefully (sanitised to 0)", () => {
    renderComponent({ totalRaised: -100, goal: 1000 });
    expect(screen.getByTestId("progress-bar")).toHaveAttribute("aria-valuenow", "0");
  });

  it("handles negative goal gracefully (shows error)", () => {
    renderComponent({ goal: -500 });
    expect(screen.getByText("Invalid campaign goal.")).toBeInTheDocument();
  });

  it("handles NaN totalRaised gracefully", () => {
    renderComponent({ totalRaised: NaN, goal: 1000 });
    expect(screen.getByTestId("progress-bar")).toHaveAttribute("aria-valuenow", "0");
  });

  it("renders all milestones as reached when goal is fully met", () => {
    renderComponent({ totalRaised: 1000, goal: 1000 });
    const list = screen.getByTestId("milestones-list");
    const statuses = list.querySelectorAll("[role='status']");
    expect(statuses).toHaveLength(4);
  });

  it("uses current system time when currentTime prop is omitted", () => {
    // Should not throw and should render the root element
    render(
      <CelebrationForecasting
        totalRaised={100}
        goal={1000}
        campaignStartTime={Math.floor(Date.now() / 1000) - 3600}
      />
    );
    expect(screen.getByTestId("celebration-forecasting")).toBeInTheDocument();
  });
});
