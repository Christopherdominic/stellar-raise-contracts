import React, { useEffect, useRef, useCallback } from "react";

/**
 * @title CelebrationOptimization
 * @notice Renders a lightweight milestone celebration overlay when a crowdfunding
 *         campaign reaches or exceeds its funding goal.
 * @dev Optimised for performance:
 *   - Canvas-based confetti: no DOM node per particle, single rAF loop.
 *   - Auto-stops after `durationMs` to avoid indefinite CPU usage.
 *   - Cleans up the animation frame and canvas on unmount.
 *   - No external dependencies beyond React.
 * @security
 *   - `message` is rendered as a React text node — no dangerouslySetInnerHTML.
 *   - Canvas drawing uses only numeric constants; no user input reaches the
 *     canvas API.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * @notice Props for CelebrationOverlay.
 * @param raised       Total amount raised (in stroops or display units).
 * @param goal         Campaign funding goal (same unit as `raised`).
 * @param message      Optional override for the celebration headline.
 * @param durationMs   How long the confetti runs (default: 3000 ms).
 * @param onDismiss    Called when the user dismisses the overlay.
 */
export interface CelebrationOverlayProps {
  raised: number;
  goal: number;
  message?: string;
  durationMs?: number;
  onDismiss?: () => void;
}

// ── Constants ─────────────────────────────────────────────────────────────────

/** @notice Particle count kept low for performance on mid-range devices. */
const PARTICLE_COUNT = 80;
const GRAVITY = 0.25;
const CONFETTI_COLORS = ["#4f46e5", "#16a34a", "#f59e0b", "#ec4899", "#06b6d4"];
const DEFAULT_DURATION_MS = 3000;
const DEFAULT_MESSAGE = "🎉 Goal Reached!";

// ── Pure helpers (exported for unit testing) ──────────────────────────────────

/**
 * @title isMilestoneReached
 * @notice Returns true when `raised` is greater than or equal to `goal` and
 *         both values are finite positive numbers.
 * @param raised  Amount raised.
 * @param goal    Funding goal.
 */
export function isMilestoneReached(raised: number, goal: number): boolean {
  return (
    Number.isFinite(raised) &&
    Number.isFinite(goal) &&
    goal > 0 &&
    raised >= goal
  );
}

/**
 * @title getMilestonePercent
 * @notice Returns the funding percentage clamped to [0, 100].
 * @param raised  Amount raised.
 * @param goal    Funding goal.
 */
export function getMilestonePercent(raised: number, goal: number): number {
  if (!Number.isFinite(goal) || goal <= 0) return 0;
  if (!Number.isFinite(raised) || raised <= 0) return 0;
  return Math.min(100, Math.round((raised / goal) * 100));
}

/**
 * @title normalizeCelebrationMessage
 * @notice Returns a safe, non-empty celebration message.
 *         Rejects non-strings and trims whitespace.
 * @param candidate  Untrusted input.
 * @param fallback   Returned when candidate is unusable.
 */
export function normalizeCelebrationMessage(
  candidate: unknown,
  fallback: string
): string {
  if (typeof candidate !== "string") return fallback;
  const trimmed = candidate.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

// ── Particle helpers ──────────────────────────────────────────────────────────

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: string;
  size: number;
  rotation: number;
  rotationSpeed: number;
}

/** @notice Creates a single confetti particle at a random position along the top. */
export function createParticle(canvasWidth: number): Particle {
  return {
    x: Math.random() * canvasWidth,
    y: Math.random() * -20,
    vx: (Math.random() - 0.5) * 4,
    vy: Math.random() * 3 + 1,
    color: CONFETTI_COLORS[Math.floor(Math.random() * CONFETTI_COLORS.length)],
    size: Math.random() * 8 + 4,
    rotation: Math.random() * Math.PI * 2,
    rotationSpeed: (Math.random() - 0.5) * 0.2,
  };
}

/** @notice Advances a particle by one frame, applying gravity. */
export function stepParticle(p: Particle): Particle {
  return {
    ...p,
    x: p.x + p.vx,
    y: p.y + p.vy,
    vy: p.vy + GRAVITY,
    rotation: p.rotation + p.rotationSpeed,
  };
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * @title CelebrationOverlay
 * @notice Displays a full-screen celebration overlay with canvas confetti when
 *         the campaign milestone is reached. Renders nothing when the goal has
 *         not been met.
 */
const CelebrationOverlay: React.FC<CelebrationOverlayProps> = ({
  raised,
  goal,
  message,
  durationMs = DEFAULT_DURATION_MS,
  onDismiss,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const particlesRef = useRef<Particle[]>([]);
  const startTimeRef = useRef<number>(0);

  const safeMessage = normalizeCelebrationMessage(message, DEFAULT_MESSAGE);
  const percent = getMilestonePercent(raised, goal);
  const reached = isMilestoneReached(raised, goal);

  const stopAnimation = useCallback(() => {
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = 0;
    }
  }, []);

  useEffect(() => {
    if (!reached) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    particlesRef.current = Array.from({ length: PARTICLE_COUNT }, () =>
      createParticle(canvas.width)
    );
    startTimeRef.current = performance.now();

    const draw = (now: number) => {
      if (now - startTimeRef.current > durationMs) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        stopAnimation();
        return;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particlesRef.current = particlesRef.current
        .map(stepParticle)
        .filter((p) => p.y < canvas.height + 20);

      for (const p of particlesRef.current) {
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rotation);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
        ctx.restore();
      }

      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);
    return stopAnimation;
  }, [reached, durationMs, stopAnimation]);

  if (!reached) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Campaign milestone celebration"
      style={styles.overlay}
    >
      <canvas ref={canvasRef} style={styles.canvas} aria-hidden="true" />
      <div style={styles.card}>
        <p style={styles.headline}>{safeMessage}</p>
        <p style={styles.sub}>
          {percent}% funded — {raised.toLocaleString()} / {goal.toLocaleString()}
        </p>
        {onDismiss && (
          <button onClick={onDismiss} style={styles.btn} aria-label="Dismiss celebration">
            Continue
          </button>
        )}
      </div>
    </div>
  );
};

// ── Styles ────────────────────────────────────────────────────────────────────

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: "fixed",
    inset: 0,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(0,0,0,0.55)",
    zIndex: 9999,
  },
  canvas: {
    position: "absolute",
    inset: 0,
    width: "100%",
    height: "100%",
    pointerEvents: "none",
  },
  card: {
    position: "relative",
    backgroundColor: "#ffffff",
    borderRadius: "1rem",
    padding: "2rem 2.5rem",
    textAlign: "center",
    boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
    maxWidth: "360px",
    width: "90%",
  },
  headline: {
    fontSize: "1.75rem",
    fontWeight: 700,
    margin: "0 0 0.5rem",
    color: "#1e293b",
  },
  sub: {
    fontSize: "1rem",
    color: "#64748b",
    margin: "0 0 1.5rem",
  },
  btn: {
    backgroundColor: "#4f46e5",
    color: "#ffffff",
    border: "none",
    borderRadius: "0.5rem",
    padding: "0.625rem 1.5rem",
    fontSize: "1rem",
    fontWeight: 600,
    cursor: "pointer",
  },
};

export default CelebrationOverlay;
