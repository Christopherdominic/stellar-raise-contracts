import React from "react";
import { render, screen } from "@testing-library/react";
import CelebrationRecommendations, {
  sanitize,
  derivePhase,
  getRecommendations,
  PHASE_THRESHOLDS,
  type CelebrationRecommendationsProps,
} from "./celebration_recommendations";

// ── Helper ───────────────────────────────────────────────────────────────────

function renderComponent(overrides: Partial<CelebrationRecommendationsProps> = {}) {
  const defaults: CelebrationRecommendationsProps = {
    totalRaised: 0,
    goal: 1000,
    isCreator: false,
    ...overrides,
  };
  return render(<CelebrationRecommendations {...defaults} />);
}

// ── sanitize ─────────────────────────────────────────────────────────────────

describe("sanitize", () => {
  it("returns the value when finite and non-negative", () => {
    expect(sanitize(100)).toBe(100);
    expect(sanitize(0)).toBe(0);
  });

  it("returns 0 for negative values", () => {
    expect(sanitize(-1)).toBe(0);
  });

  it("returns 0 for NaN", () => {
    expect(sanitize(NaN)).toBe(0);
  });

  it("returns 0 for Infinity", () => {
    expect(sanitize(Infinity)).toBe(0);
  });
});

// ── derivePhase ───────────────────────────────────────────────────────────────

describe("derivePhase", () => {
  it("returns pre_launch below 25 %", () => {
    expect(derivePhase(0)).toBe("pre_launch");
    expect(derivePhase(24.9)).toBe("pre_launch");
  });

  it("returns early at exactly 25 %", () => {
    expect(derivePhase(25)).toBe("early");
  });

  it("returns early between 25 % and 49.9 %", () => {
    expect(derivePhase(40)).toBe("early");
  });

  it("returns halfway at exactly 50 %", () => {
    expect(derivePhase(50)).toBe("halfway");
  });

  it("returns halfway between 50 % and 74.9 %", () => {
    expect(derivePhase(60)).toBe("halfway");
  });

  it("returns final_push at exactly 75 %", () => {
    expect(derivePhase(75)).toBe("final_push");
  });

  it("returns final_push between 75 % and 99.9 %", () => {
    expect(derivePhase(90)).toBe("final_push");
  });

  it("returns funded at exactly 100 %", () => {
    expect(derivePhase(100)).toBe("funded");
  });

  it("returns funded above 100 %", () => {
    expect(derivePhase(150)).toBe("funded");
  });
});

// ── getRecommendations ────────────────────────────────────────────────────────

describe("getRecommendations", () => {
  const phases = ["pre_launch", "early", "halfway", "final_push", "funded"] as const;

  phases.forEach((phase) => {
    it(`returns non-empty creator recommendations for phase "${phase}"`, () => {
      const recs = getRecommendations(phase, true);
      expect(recs.length).toBeGreaterThan(0);
    });

    it(`returns non-empty contributor recommendations for phase "${phase}"`, () => {
      const recs = getRecommendations(phase, false);
      expect(recs.length).toBeGreaterThan(0);
    });

    it(`all creator recommendations for "${phase}" have required fields`, () => {
      getRecommendations(phase, true).forEach((r) => {
        expect(typeof r.id).toBe("string");
        expect(r.id.length).toBeGreaterThan(0);
        expect(typeof r.icon).toBe("string");
        expect(typeof r.heading).toBe("string");
        expect(typeof r.body).toBe("string");
      });
    });
  });

  it("creator and contributor recommendations differ for the same phase", () => {
    const creator = getRecommendations("early", true);
    const contributor = getRecommendations("early", false);
    expect(creator[0].id).not.toBe(contributor[0].id);
  });
});

// ── PHASE_THRESHOLDS ──────────────────────────────────────────────────────────

describe("PHASE_THRESHOLDS", () => {
  it("has expected values", () => {
    expect(PHASE_THRESHOLDS.early).toBe(0.25);
    expect(PHASE_THRESHOLDS.halfway).toBe(0.5);
    expect(PHASE_THRESHOLDS.finalPush).toBe(0.75);
    expect(PHASE_THRESHOLDS.funded).toBe(1.0);
  });
});

// ── CelebrationRecommendations component ──────────────────────────────────────

describe("CelebrationRecommendations", () => {
  it("renders the root element", () => {
    renderComponent();
    expect(screen.getByTestId("celebration-recommendations")).toBeInTheDocument();
  });

  it("shows error when goal is 0", () => {
    renderComponent({ goal: 0 });
    expect(screen.getByTestId("recommendations-error")).toBeInTheDocument();
  });

  it("shows error when goal is negative (sanitised to 0)", () => {
    renderComponent({ goal: -500 });
    expect(screen.getByTestId("recommendations-error")).toBeInTheDocument();
  });

  it("shows error when goal is NaN", () => {
    renderComponent({ goal: NaN });
    expect(screen.getByTestId("recommendations-error")).toBeInTheDocument();
  });

  it("renders phase label", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toBeInTheDocument();
  });

  it("renders recommendations list", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    expect(screen.getByTestId("recommendations-list")).toBeInTheDocument();
  });

  it("shows pre_launch phase when totalRaised is 0", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("pre_launch");
  });

  it("shows early phase at 25 %", () => {
    renderComponent({ totalRaised: 250, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("early");
  });

  it("shows halfway phase at 50 %", () => {
    renderComponent({ totalRaised: 500, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("halfway");
  });

  it("shows final_push phase at 75 %", () => {
    renderComponent({ totalRaised: 750, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("final_push");
  });

  it("shows funded phase at 100 %", () => {
    renderComponent({ totalRaised: 1000, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("funded");
  });

  it("shows funded phase when totalRaised exceeds goal", () => {
    renderComponent({ totalRaised: 1500, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("funded");
  });

  it("renders creator recommendations when isCreator is true", () => {
    renderComponent({ totalRaised: 0, goal: 1000, isCreator: true });
    const recs = getRecommendations("pre_launch", true);
    expect(screen.getByTestId(`recommendation-${recs[0].id}`)).toBeInTheDocument();
  });

  it("renders contributor recommendations when isCreator is false", () => {
    renderComponent({ totalRaised: 0, goal: 1000, isCreator: false });
    const recs = getRecommendations("pre_launch", false);
    expect(screen.getByTestId(`recommendation-${recs[0].id}`)).toBeInTheDocument();
  });

  it("defaults isCreator to false", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    const contribRecs = getRecommendations("pre_launch", false);
    expect(screen.getByTestId(`recommendation-${contribRecs[0].id}`)).toBeInTheDocument();
  });

  it("each recommendation item has role listitem", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    const items = screen.getAllByRole("listitem");
    expect(items.length).toBeGreaterThan(0);
  });

  it("recommendation list has role list", () => {
    renderComponent({ totalRaised: 0, goal: 1000 });
    expect(screen.getByRole("list")).toBeInTheDocument();
  });

  it("renders heading text for each recommendation", () => {
    renderComponent({ totalRaised: 0, goal: 1000, isCreator: true });
    const recs = getRecommendations("pre_launch", true);
    recs.forEach((r) => {
      expect(screen.getByText(r.heading)).toBeInTheDocument();
    });
  });

  it("renders body text for each recommendation", () => {
    renderComponent({ totalRaised: 0, goal: 1000, isCreator: true });
    const recs = getRecommendations("pre_launch", true);
    recs.forEach((r) => {
      expect(screen.getByText(r.body)).toBeInTheDocument();
    });
  });

  it("handles negative totalRaised gracefully (sanitised to 0)", () => {
    renderComponent({ totalRaised: -100, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("pre_launch");
  });

  it("handles NaN totalRaised gracefully", () => {
    renderComponent({ totalRaised: NaN, goal: 1000 });
    expect(screen.getByTestId("recommendations-phase")).toHaveTextContent("pre_launch");
  });

  it("shows funded recommendations for creator at 100 %", () => {
    renderComponent({ totalRaised: 1000, goal: 1000, isCreator: true });
    const recs = getRecommendations("funded", true);
    expect(screen.getByTestId(`recommendation-${recs[0].id}`)).toBeInTheDocument();
  });

  it("shows funded recommendations for contributor at 100 %", () => {
    renderComponent({ totalRaised: 1000, goal: 1000, isCreator: false });
    const recs = getRecommendations("funded", false);
    expect(screen.getByTestId(`recommendation-${recs[0].id}`)).toBeInTheDocument();
  });

  it("does not render recommendations list when goal is 0", () => {
    renderComponent({ goal: 0 });
    expect(screen.queryByTestId("recommendations-list")).not.toBeInTheDocument();
  });

  it("does not render phase label when goal is 0", () => {
    renderComponent({ goal: 0 });
    expect(screen.queryByTestId("recommendations-phase")).not.toBeInTheDocument();
  });
});
