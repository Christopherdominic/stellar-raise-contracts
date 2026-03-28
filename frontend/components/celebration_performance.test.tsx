/**
 * @file celebration_performance.test.tsx
 * @title Test Suite — CelebrationPerformance
 *
 * @notice Comprehensive unit tests for the CelebrationPerformance component
 *         and its exported pure helpers.
 *
 * @dev Coverage targets (≥ 95%):
 *   - Pure helpers: derivePerformanceTier, performanceTierEmoji,
 *     performanceTierAccent, clampMilestonePercent
 *   - Rendering: milestone reached / not reached, all tiers, props forwarding
 *   - Dismissal: button click, backdrop click, Escape key
 *   - Auto-dismiss: fires, does not fire at 0, clears on unmount
 *   - Edge cases: null-like data, rapid successive triggers, out-of-range percent
 *   - Accessibility: role, aria-modal, aria-label, focus management
 *   - Security: no dangerouslySetInnerHTML, plain-text rendering
 *
 * Run: `npm test -- --testPathPattern=celebration_performance --coverage`
 */

import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import CelebrationPerformance, {
  CelebrationPerformanceProps,
  derivePerformanceTier,
  performanceTierEmoji,
  performanceTierAccent,
  clampMilestonePercent,
  PerformanceTier,
} from './celebration_performance';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function buildProps(
  overrides: Partial<CelebrationPerformanceProps> = {},
): CelebrationPerformanceProps {
  return {
    milestoneReached: true,
    milestoneLabel: '50% Funded',
    milestonePercent: 50,
    campaignName: 'Ocean Cleanup Fund',
    onDismiss: jest.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. derivePerformanceTier()
// ---------------------------------------------------------------------------

describe('1. derivePerformanceTier()', () => {
  it('1.1 returns bronze for 0', () => expect(derivePerformanceTier(0)).toBe('bronze'));
  it('1.2 returns bronze for 24', () => expect(derivePerformanceTier(24)).toBe('bronze'));
  it('1.3 returns silver for 25', () => expect(derivePerformanceTier(25)).toBe('silver'));
  it('1.4 returns silver for 49', () => expect(derivePerformanceTier(49)).toBe('silver'));
  it('1.5 returns gold for 50', () => expect(derivePerformanceTier(50)).toBe('gold'));
  it('1.6 returns gold for 74', () => expect(derivePerformanceTier(74)).toBe('gold'));
  it('1.7 returns platinum for 75', () => expect(derivePerformanceTier(75)).toBe('platinum'));
  it('1.8 returns platinum for 100', () => expect(derivePerformanceTier(100)).toBe('platinum'));
  it('1.9 returns bronze for negative percent', () => expect(derivePerformanceTier(-5)).toBe('bronze'));
  it('1.10 returns platinum for percent > 100', () => expect(derivePerformanceTier(200)).toBe('platinum'));
});

// ---------------------------------------------------------------------------
// 2. performanceTierEmoji()
// ---------------------------------------------------------------------------

describe('2. performanceTierEmoji()', () => {
  const cases: [PerformanceTier, string][] = [
    ['bronze', '🥉'],
    ['silver', '🥈'],
    ['gold', '🥇'],
    ['platinum', '🏆'],
  ];
  it.each(cases)('2.%# returns correct emoji for %s', (tier, expected) => {
    expect(performanceTierEmoji(tier)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// 3. performanceTierAccent()
// ---------------------------------------------------------------------------

describe('3. performanceTierAccent()', () => {
  it('3.1 returns a non-empty string for every tier', () => {
    const tiers: PerformanceTier[] = ['bronze', 'silver', 'gold', 'platinum'];
    tiers.forEach((t) => expect(performanceTierAccent(t).length).toBeGreaterThan(0));
  });

  it('3.2 returns distinct colours for each tier', () => {
    const colors = (['bronze', 'silver', 'gold', 'platinum'] as PerformanceTier[]).map(
      performanceTierAccent,
    );
    expect(new Set(colors).size).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// 4. clampMilestonePercent()
// ---------------------------------------------------------------------------

describe('4. clampMilestonePercent()', () => {
  it('4.1 returns 0 for negative values', () => {
    expect(clampMilestonePercent(-1)).toBe(0);
    expect(clampMilestonePercent(-999)).toBe(0);
  });

  it('4.2 returns 100 for values above 100', () => {
    expect(clampMilestonePercent(101)).toBe(100);
    expect(clampMilestonePercent(9999)).toBe(100);
  });

  it('4.3 returns the value unchanged when in range', () => {
    expect(clampMilestonePercent(0)).toBe(0);
    expect(clampMilestonePercent(50)).toBe(50);
    expect(clampMilestonePercent(100)).toBe(100);
  });

  it('4.4 returns 0 for NaN', () => expect(clampMilestonePercent(NaN)).toBe(0));

  it('4.5 returns 0 for Infinity', () => {
    expect(clampMilestonePercent(Infinity)).toBe(0);
    expect(clampMilestonePercent(-Infinity)).toBe(0);
  });

  it('4.6 handles decimal values correctly', () => {
    expect(clampMilestonePercent(33.5)).toBeCloseTo(33.5);
    expect(clampMilestonePercent(99.9)).toBeCloseTo(99.9);
  });
});

// ---------------------------------------------------------------------------
// 5. Rendering — milestone reached
// ---------------------------------------------------------------------------

describe('5. Rendering — milestone reached', () => {
  it('5.1 renders the overlay when milestoneReached is true', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    expect(screen.getByTestId('celebration-performance')).toBeInTheDocument();
  });

  it('5.2 renders the card', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    expect(screen.getByTestId('celebration-performance-card')).toBeInTheDocument();
  });

  it('5.3 renders the backdrop', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    expect(screen.getByTestId('celebration-performance-backdrop')).toBeInTheDocument();
  });

  it('5.4 renders the dismiss button', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    expect(screen.getByTestId('celebration-performance-dismiss')).toBeInTheDocument();
  });

  it('5.5 displays the campaign name', () => {
    render(<CelebrationPerformance {...buildProps({ campaignName: 'Solar Power Initiative' })} />);
    expect(screen.getByTestId('celebration-performance-campaign')).toHaveTextContent(
      'Solar Power Initiative',
    );
  });

  it('5.6 displays the milestone label', () => {
    render(<CelebrationPerformance {...buildProps({ milestoneLabel: '75% Funded' })} />);
    expect(screen.getByTestId('celebration-performance-label')).toHaveTextContent('75% Funded');
  });

  it('5.7 displays the clamped percentage', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 50 })} />);
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('50% of goal');
  });

  it('5.8 applies the correct tier class for gold (50%)', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 50 })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass(
      'celebration-performance--gold',
    );
  });

  it('5.9 applies the correct tier class for platinum (80%)', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 80 })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass(
      'celebration-performance--platinum',
    );
  });

  it('5.10 applies tier override when tier prop is provided', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 80, tier: 'bronze' })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass(
      'celebration-performance--bronze',
    );
  });

  it('5.11 forwards extra className to root element', () => {
    render(<CelebrationPerformance {...buildProps({ className: 'my-extra-class' })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass('my-extra-class');
  });

  it('5.12 has role="dialog" and aria-modal="true"', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
  });

  it('5.13 has aria-label derived from milestoneLabel', () => {
    render(<CelebrationPerformance {...buildProps({ milestoneLabel: '25% Funded' })} />);
    expect(screen.getByRole('dialog')).toHaveAttribute(
      'aria-label',
      'Milestone celebration: 25% Funded',
    );
  });

  it('5.14 renders the tier badge emoji', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 100 })} />);
    expect(screen.getByTestId('celebration-performance-badge')).toHaveTextContent('🏆');
  });
});

// ---------------------------------------------------------------------------
// 6. Rendering — milestone NOT reached
// ---------------------------------------------------------------------------

describe('6. Rendering — milestone not reached', () => {
  it('6.1 does not render when milestoneReached is false', () => {
    render(<CelebrationPerformance {...buildProps({ milestoneReached: false })} />);
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });

  it('6.2 renders nothing when milestoneReached transitions false → false', () => {
    const { rerender } = render(
      <CelebrationPerformance {...buildProps({ milestoneReached: false })} />,
    );
    rerender(<CelebrationPerformance {...buildProps({ milestoneReached: false })} />);
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// 7. Dismissal
// ---------------------------------------------------------------------------

describe('7. Dismissal', () => {
  it('7.1 calls onDismiss when dismiss button is clicked', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss })} />);
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('7.2 unmounts overlay after dismiss button click', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });

  it('7.3 calls onDismiss when backdrop is clicked', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss })} />);
    fireEvent.click(screen.getByTestId('celebration-performance-backdrop'));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('7.4 unmounts overlay after backdrop click', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    fireEvent.click(screen.getByTestId('celebration-performance-backdrop'));
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });

  it('7.5 calls onDismiss on Escape key press', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss })} />);
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('7.6 does NOT call onDismiss on non-Escape key press', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss })} />);
    fireEvent.keyDown(window, { key: 'Enter' });
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it('7.7 does not throw when Escape is pressed after dismiss', () => {
    render(<CelebrationPerformance {...buildProps()} />);
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));
    expect(() => fireEvent.keyDown(window, { key: 'Escape' })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 8. Auto-dismiss
// ---------------------------------------------------------------------------

describe('8. Auto-dismiss', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('8.1 auto-dismisses after autoDismissMs', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss, autoDismissMs: 3000 })} />);
    expect(screen.getByTestId('celebration-performance')).toBeInTheDocument();
    act(() => jest.advanceTimersByTime(3000));
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });

  it('8.2 does NOT auto-dismiss when autoDismissMs is 0', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss, autoDismissMs: 0 })} />);
    act(() => jest.advanceTimersByTime(10_000));
    expect(onDismiss).not.toHaveBeenCalled();
    expect(screen.getByTestId('celebration-performance')).toBeInTheDocument();
  });

  it('8.3 does NOT auto-dismiss when autoDismissMs is negative', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss, autoDismissMs: -1 })} />);
    act(() => jest.advanceTimersByTime(10_000));
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it('8.4 clears the timer on unmount (no memory leak)', () => {
    const onDismiss = jest.fn();
    const { unmount } = render(
      <CelebrationPerformance {...buildProps({ onDismiss, autoDismissMs: 5000 })} />,
    );
    unmount();
    act(() => jest.advanceTimersByTime(5000));
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it('8.5 manual dismiss before auto-dismiss fires onDismiss only once', () => {
    const onDismiss = jest.fn();
    render(<CelebrationPerformance {...buildProps({ onDismiss, autoDismissMs: 3000 })} />);
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));
    act(() => jest.advanceTimersByTime(3000));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 9. Re-trigger (rapid successive milestones)
// ---------------------------------------------------------------------------

describe('9. Re-trigger — rapid successive milestones', () => {
  it('9.1 re-shows overlay when milestoneReached flips false → true after dismiss', () => {
    const onDismiss = jest.fn();
    const { rerender } = render(<CelebrationPerformance {...buildProps({ onDismiss })} />);

    // Dismiss
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();

    // New milestone event
    rerender(
      <CelebrationPerformance
        {...buildProps({ onDismiss, milestoneReached: false })}
      />,
    );
    rerender(
      <CelebrationPerformance
        {...buildProps({ onDismiss, milestoneReached: true, milestoneLabel: '75% Funded' })}
      />,
    );
    expect(screen.getByTestId('celebration-performance')).toBeInTheDocument();
    expect(screen.getByTestId('celebration-performance-label')).toHaveTextContent('75% Funded');
  });

  it('9.2 does not show overlay when milestoneReached stays true after dismiss', () => {
    const { rerender } = render(<CelebrationPerformance {...buildProps()} />);
    fireEvent.click(screen.getByTestId('celebration-performance-dismiss'));

    // milestoneReached stays true — overlay should remain hidden
    rerender(<CelebrationPerformance {...buildProps({ milestoneReached: true })} />);
    expect(screen.queryByTestId('celebration-performance')).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// 10. Edge cases
// ---------------------------------------------------------------------------

describe('10. Edge cases', () => {
  it('10.1 renders with empty campaignName without crashing', () => {
    render(<CelebrationPerformance {...buildProps({ campaignName: '' })} />);
    expect(screen.getByTestId('celebration-performance-campaign')).toHaveTextContent('');
  });

  it('10.2 renders with empty milestoneLabel without crashing', () => {
    render(<CelebrationPerformance {...buildProps({ milestoneLabel: '' })} />);
    expect(screen.getByTestId('celebration-performance-label')).toHaveTextContent('');
  });

  it('10.3 renders correctly at 0% (bronze tier)', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 0 })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass(
      'celebration-performance--bronze',
    );
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('0% of goal');
  });

  it('10.4 renders correctly at 100% (platinum tier)', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 100 })} />);
    expect(screen.getByTestId('celebration-performance')).toHaveClass(
      'celebration-performance--platinum',
    );
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('100% of goal');
  });

  it('10.5 clamps negative milestonePercent to 0 in display', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: -10 })} />);
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('0% of goal');
  });

  it('10.6 clamps milestonePercent > 100 to 100 in display', () => {
    render(<CelebrationPerformance {...buildProps({ milestonePercent: 150 })} />);
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('100% of goal');
  });

  it('10.7 handles NaN milestonePercent without crashing', () => {
    expect(() =>
      render(<CelebrationPerformance {...buildProps({ milestonePercent: NaN })} />),
    ).not.toThrow();
    expect(screen.getByTestId('celebration-performance-percent')).toHaveTextContent('0% of goal');
  });

  it('10.8 handles Infinity milestonePercent without crashing', () => {
    expect(() =>
      render(<CelebrationPerformance {...buildProps({ milestonePercent: Infinity })} />),
    ).not.toThrow();
  });

  it('10.9 does not use dangerouslySetInnerHTML', () => {
    const { container } = render(<CelebrationPerformance {...buildProps()} />);
    expect(container.querySelectorAll('[dangerouslySetInnerHTML]')).toHaveLength(0);
  });

  it('10.10 renders XSS-like campaignName as plain text (not HTML)', () => {
    const xss = '<script>alert(1)</script>';
    render(<CelebrationPerformance {...buildProps({ campaignName: xss })} />);
    expect(screen.getByTestId('celebration-performance-campaign')).toHaveTextContent(xss);
    // Ensure no actual script element was injected
    expect(document.querySelector('script[data-xss]')).toBeNull();
  });

  it('10.11 renders XSS-like milestoneLabel as plain text', () => {
    const xss = '<img src=x onerror=alert(1)>';
    render(<CelebrationPerformance {...buildProps({ milestoneLabel: xss })} />);
    expect(screen.getByTestId('celebration-performance-label')).toHaveTextContent(xss);
  });
});

// ---------------------------------------------------------------------------
// 11. All four tiers render correctly
// ---------------------------------------------------------------------------

describe('11. All four tiers', () => {
  const tierCases: [number, PerformanceTier, string][] = [
    [10, 'bronze', '🥉'],
    [30, 'silver', '🥈'],
    [60, 'gold', '🥇'],
    [90, 'platinum', '🏆'],
  ];

  it.each(tierCases)(
    '11.%# milestonePercent=%i → tier=%s, emoji=%s',
    (percent, expectedTier, expectedEmoji) => {
      render(
        <CelebrationPerformance
          {...buildProps({ milestonePercent: percent })}
        />,
      );
      expect(screen.getByTestId('celebration-performance')).toHaveClass(
        `celebration-performance--${expectedTier}`,
      );
      expect(screen.getByTestId('celebration-performance-badge')).toHaveTextContent(expectedEmoji);
    },
  );
});
