import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import CampaignMilestoneCelebration, {
  sanitizeMilestoneLabel,
  getMilestoneVisuals,
  isValidMilestoneThreshold,
  MAX_LABEL_LENGTH,
  DEFAULT_AUTO_DISMISS_MS,
  MILESTONE_THRESHOLDS,
  MilestoneInfo,
} from './celebration_reliability';

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeAll(() => {
  jest.useFakeTimers();
  // Stub matchMedia (jsdom doesn't implement it)
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  });
});

afterAll(() => {
  jest.useRealTimers();
});

afterEach(() => {
  jest.clearAllTimers();
  jest.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeMilestone = (overrides: Partial<MilestoneInfo> = {}): MilestoneInfo => ({
  milestoneId: 'ms-001',
  threshold: 50,
  label: '50% funded',
  campaignTitle: 'Solar Farm Project',
  ...overrides,
});

// ---------------------------------------------------------------------------
// sanitizeMilestoneLabel
// ---------------------------------------------------------------------------

describe('sanitizeMilestoneLabel', () => {
  it('returns empty string for non-string input', () => {
    expect(sanitizeMilestoneLabel(null)).toBe('');
    expect(sanitizeMilestoneLabel(undefined)).toBe('');
    expect(sanitizeMilestoneLabel(42)).toBe('');
    expect(sanitizeMilestoneLabel({})).toBe('');
  });

  it('returns the string unchanged when within limit', () => {
    expect(sanitizeMilestoneLabel('50% funded')).toBe('50% funded');
  });

  it('strips control characters', () => {
    expect(sanitizeMilestoneLabel('hello\x00world')).toBe('hello world');
    expect(sanitizeMilestoneLabel('test\x1Fvalue')).toBe('test value');
  });

  it('collapses multiple whitespace', () => {
    expect(sanitizeMilestoneLabel('hello   world')).toBe('hello world');
  });

  it('trims leading and trailing whitespace', () => {
    expect(sanitizeMilestoneLabel('  hello  ')).toBe('hello');
  });

  it('truncates strings exceeding MAX_LABEL_LENGTH', () => {
    const long = 'a'.repeat(MAX_LABEL_LENGTH + 10);
    const result = sanitizeMilestoneLabel(long);
    expect(result.length).toBe(MAX_LABEL_LENGTH);
    expect(result.endsWith('...')).toBe(true);
  });

  it('returns string exactly at MAX_LABEL_LENGTH unchanged', () => {
    const exact = 'b'.repeat(MAX_LABEL_LENGTH);
    expect(sanitizeMilestoneLabel(exact)).toBe(exact);
  });

  it('handles empty string', () => {
    expect(sanitizeMilestoneLabel('')).toBe('');
  });

  it('handles string with only whitespace', () => {
    expect(sanitizeMilestoneLabel('   ')).toBe('');
  });
});

// ---------------------------------------------------------------------------
// getMilestoneVisuals
// ---------------------------------------------------------------------------

describe('getMilestoneVisuals', () => {
  it('returns correct visuals for 25%', () => {
    const v = getMilestoneVisuals(25);
    expect(v.emoji).toBe('🌱');
    expect(v.color).toBeTruthy();
    expect(v.label).toBeTruthy();
  });

  it('returns correct visuals for 50%', () => {
    const v = getMilestoneVisuals(50);
    expect(v.emoji).toBe('🚀');
  });

  it('returns correct visuals for 75%', () => {
    const v = getMilestoneVisuals(75);
    expect(v.emoji).toBe('⚡');
  });

  it('returns correct visuals for 100%', () => {
    const v = getMilestoneVisuals(100);
    expect(v.emoji).toBe('🎉');
  });

  it('each threshold returns a non-empty color string', () => {
    MILESTONE_THRESHOLDS.forEach((t) => {
      expect(getMilestoneVisuals(t).color).toMatch(/^#[0-9a-fA-F]{6}$/);
    });
  });

  it('each threshold returns a non-empty label string', () => {
    MILESTONE_THRESHOLDS.forEach((t) => {
      expect(getMilestoneVisuals(t).label.length).toBeGreaterThan(0);
    });
  });
});

// ---------------------------------------------------------------------------
// isValidMilestoneThreshold
// ---------------------------------------------------------------------------

describe('isValidMilestoneThreshold', () => {
  it('returns true for all valid thresholds', () => {
    MILESTONE_THRESHOLDS.forEach((t) => {
      expect(isValidMilestoneThreshold(t)).toBe(true);
    });
  });

  it('returns false for invalid numbers', () => {
    expect(isValidMilestoneThreshold(0)).toBe(false);
    expect(isValidMilestoneThreshold(10)).toBe(false);
    expect(isValidMilestoneThreshold(101)).toBe(false);
    expect(isValidMilestoneThreshold(-1)).toBe(false);
  });

  it('returns false for non-number types', () => {
    expect(isValidMilestoneThreshold('50')).toBe(false);
    expect(isValidMilestoneThreshold(null)).toBe(false);
    expect(isValidMilestoneThreshold(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Rendering — null / undefined milestone
// ---------------------------------------------------------------------------

describe('Rendering with no milestone', () => {
  it('renders nothing when milestone is null', () => {
    const { container } = render(
      <CampaignMilestoneCelebration milestone={null} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when milestone is undefined', () => {
    const { container } = render(
      <CampaignMilestoneCelebration milestone={undefined} />,
    );
    expect(container.firstChild).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Rendering — valid milestone
// ---------------------------------------------------------------------------

describe('Rendering with valid milestone', () => {
  it('shows the overlay when a valid milestone is provided', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByTestId('milestone-celebration-overlay')).toBeTruthy();
  });

  it('renders the milestone label', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone({ label: '50% funded' })} />);
    expect(screen.getByTestId('milestone-label').textContent).toBe('50% funded');
  });

  it('renders the campaign title', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone({ campaignTitle: 'Solar Farm' })} />);
    expect(screen.getByTestId('milestone-campaign-title').textContent).toBe('Solar Farm');
  });

  it('renders the correct emoji for each threshold', () => {
    const emojis: Record<number, string> = { 25: '🌱', 50: '🚀', 75: '⚡', 100: '🎉' };
    MILESTONE_THRESHOLDS.forEach((t) => {
      const { unmount } = render(
        <CampaignMilestoneCelebration
          milestone={makeMilestone({ threshold: t, milestoneId: `ms-${t}` })}
        />,
      );
      expect(screen.getByTestId('milestone-emoji').textContent).toBe(emojis[t]);
      unmount();
    });
  });

  it('renders the dismiss button', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByTestId('milestone-dismiss-btn')).toBeTruthy();
  });

  it('does not render campaign title when omitted', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ campaignTitle: undefined })}
      />,
    );
    expect(screen.queryByTestId('milestone-campaign-title')).toBeNull();
  });

  it('does not render label when label is empty after sanitization', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ label: '   ' })}
      />,
    );
    expect(screen.queryByTestId('milestone-label')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Invalid threshold — renders nothing
// ---------------------------------------------------------------------------

describe('Invalid milestone threshold', () => {
  it('renders nothing for an invalid threshold', () => {
    const { container } = render(
      <CampaignMilestoneCelebration
        milestone={{ milestoneId: 'bad', threshold: 33 as any, label: 'bad' }}
      />,
    );
    expect(container.firstChild).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Dismiss — manual
// ---------------------------------------------------------------------------

describe('Manual dismiss', () => {
  it('hides the overlay when dismiss button is clicked', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    fireEvent.click(screen.getByTestId('milestone-dismiss-btn'));
    expect(screen.queryByTestId('milestone-celebration-overlay')).toBeNull();
  });

  it('calls onDismiss with the milestoneId when dismissed', () => {
    const onDismiss = jest.fn();
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ milestoneId: 'ms-abc' })}
        onDismiss={onDismiss}
      />,
    );
    fireEvent.click(screen.getByTestId('milestone-dismiss-btn'));
    expect(onDismiss).toHaveBeenCalledWith('ms-abc');
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('does not throw when onDismiss is not provided', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(() => fireEvent.click(screen.getByTestId('milestone-dismiss-btn'))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Auto-dismiss
// ---------------------------------------------------------------------------

describe('Auto-dismiss', () => {
  it('auto-dismisses after the default delay', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByTestId('milestone-celebration-overlay')).toBeTruthy();
    act(() => { jest.advanceTimersByTime(DEFAULT_AUTO_DISMISS_MS); });
    expect(screen.queryByTestId('milestone-celebration-overlay')).toBeNull();
  });

  it('calls onDismiss after auto-dismiss', () => {
    const onDismiss = jest.fn();
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ milestoneId: 'auto-ms' })}
        onDismiss={onDismiss}
        autoDismissMs={2000}
      />,
    );
    act(() => { jest.advanceTimersByTime(2000); });
    expect(onDismiss).toHaveBeenCalledWith('auto-ms');
  });

  it('does NOT auto-dismiss when autoDismissMs is 0', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone()}
        autoDismissMs={0}
      />,
    );
    act(() => { jest.advanceTimersByTime(60_000); });
    expect(screen.getByTestId('milestone-celebration-overlay')).toBeTruthy();
  });

  it('respects a custom autoDismissMs value', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone()}
        autoDismissMs={1000}
      />,
    );
    act(() => { jest.advanceTimersByTime(999); });
    expect(screen.getByTestId('milestone-celebration-overlay')).toBeTruthy();
    act(() => { jest.advanceTimersByTime(1); });
    expect(screen.queryByTestId('milestone-celebration-overlay')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Deduplication — fires exactly once per milestoneId
// ---------------------------------------------------------------------------

describe('Deduplication', () => {
  it('does not re-show celebration for the same milestoneId after dismiss', () => {
    const ms = makeMilestone({ milestoneId: 'dedup-1' });
    const { rerender } = render(
      <CampaignMilestoneCelebration milestone={ms} autoDismissMs={0} />,
    );
    fireEvent.click(screen.getByTestId('milestone-dismiss-btn'));
    // Re-render with same milestone — should NOT reappear
    rerender(<CampaignMilestoneCelebration milestone={ms} autoDismissMs={0} />);
    expect(screen.queryByTestId('milestone-celebration-overlay')).toBeNull();
  });

  it('shows celebration for a new milestoneId after a previous one was dismissed', () => {
    const ms1 = makeMilestone({ milestoneId: 'dedup-a', threshold: 25 });
    const ms2 = makeMilestone({ milestoneId: 'dedup-b', threshold: 50 });
    const { rerender } = render(
      <CampaignMilestoneCelebration milestone={ms1} autoDismissMs={0} />,
    );
    fireEvent.click(screen.getByTestId('milestone-dismiss-btn'));
    rerender(<CampaignMilestoneCelebration milestone={ms2} autoDismissMs={0} />);
    expect(screen.getByTestId('milestone-celebration-overlay')).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Timer cleanup on unmount
// ---------------------------------------------------------------------------

describe('Timer cleanup on unmount', () => {
  it('does not call onDismiss after unmount', () => {
    const onDismiss = jest.fn();
    const { unmount } = render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone()}
        onDismiss={onDismiss}
        autoDismissMs={3000}
      />,
    );
    unmount();
    act(() => { jest.advanceTimersByTime(3000); });
    expect(onDismiss).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Accessibility
// ---------------------------------------------------------------------------

describe('Accessibility', () => {
  it('overlay has role="dialog"', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByRole('dialog')).toBeTruthy();
  });

  it('overlay has aria-modal="true"', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByRole('dialog').getAttribute('aria-modal')).toBe('true');
  });

  it('overlay has a descriptive aria-label', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ label: '50% funded' })}
      />,
    );
    expect(screen.getByRole('dialog').getAttribute('aria-label')).toContain('50% funded');
  });

  it('overlay has aria-live="polite"', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByRole('dialog').getAttribute('aria-live')).toBe('polite');
  });

  it('dismiss button has aria-label', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(
      screen.getByTestId('milestone-dismiss-btn').getAttribute('aria-label'),
    ).toBe('Dismiss milestone celebration');
  });

  it('emoji container is aria-hidden', () => {
    render(<CampaignMilestoneCelebration milestone={makeMilestone()} />);
    expect(screen.getByTestId('milestone-emoji').getAttribute('aria-hidden')).toBe('true');
  });
});

// ---------------------------------------------------------------------------
// Label sanitization in render
// ---------------------------------------------------------------------------

describe('Label sanitization in render', () => {
  it('truncates an oversized label in the rendered output', () => {
    const long = 'x'.repeat(MAX_LABEL_LENGTH + 20);
    render(<CampaignMilestoneCelebration milestone={makeMilestone({ label: long })} />);
    const el = screen.getByTestId('milestone-label');
    expect(el.textContent!.length).toBe(MAX_LABEL_LENGTH);
  });

  it('strips control characters from label in render', () => {
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone({ label: 'hello\x00world' })}
      />,
    );
    expect(screen.getByTestId('milestone-label').textContent).toBe('hello world');
  });
});

// ---------------------------------------------------------------------------
// Custom confetti renderer
// ---------------------------------------------------------------------------

describe('Custom confetti renderer', () => {
  it('renders custom confetti when provided', () => {
    const CustomConfetti = () => <div data-testid="custom-confetti">🎊</div>;
    render(
      <CampaignMilestoneCelebration
        milestone={makeMilestone()}
        confettiRenderer={() => <CustomConfetti />}
      />,
    );
    expect(screen.getByTestId('custom-confetti')).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('Exported constants', () => {
  it('MAX_LABEL_LENGTH is a positive integer', () => {
    expect(typeof MAX_LABEL_LENGTH).toBe('number');
    expect(MAX_LABEL_LENGTH).toBeGreaterThan(0);
  });

  it('DEFAULT_AUTO_DISMISS_MS is a positive integer', () => {
    expect(typeof DEFAULT_AUTO_DISMISS_MS).toBe('number');
    expect(DEFAULT_AUTO_DISMISS_MS).toBeGreaterThan(0);
  });

  it('MILESTONE_THRESHOLDS contains exactly [25, 50, 75, 100]', () => {
    expect([...MILESTONE_THRESHOLDS]).toEqual([25, 50, 75, 100]);
  });
});
