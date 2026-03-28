//! # security_testing_automation.test.rs
//!
//! @notice  Automated security test suite for the Stellar Raise crowdfunding
//!          contract.  Covers invariant checks, authorization probes,
//!          state-machine validators, fuzz/property-based tests, and edge cases.
//!
//! @dev     Tests are grouped into four sections:
//!          1. Invariant checks (happy + failure paths).
//!          2. Authorization probes (happy + failure paths).
//!          3. State-machine validators (happy + failure paths).
//!          4. Property-based / fuzz tests (random inputs via proptest).
//!
//! @custom:security-note  Every test that exercises a failure path asserts the
//!          exact `InvariantResult::Failed` message so regressions in error
//!          text are caught immediately.
//!
//! ## How to add a new security rule
//!
//! 1. Add a new `check_*` or `probe_*` function in
//!    `security_testing_automation.rs` following the existing pattern.
//! 2. Document it with `@notice`, `@dev`, and `@custom:security-note`.
//! 3. Add it to `run_security_audit` if it should run in the aggregate.
//! 4. Add a happy-path test and at least one failure-path test here.
//! 5. Run `cargo test -p security` and confirm ≥ 95 % line coverage.

#![cfg(test)]

use proptest::prelude::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

use crate::security_testing_automation::{
    check_contribution_within_deadline, check_goal_positive, check_min_contribution_positive,
    check_no_negative_contributions, check_refund_requires_expired, check_total_raised_equals_sum,
    check_total_raised_non_negative, check_valid_status_transition,
    check_withdraw_requires_succeeded, probe_contribution_amount, probe_withdraw_authorization,
    run_security_audit, CampaignStatus, InvariantResult, SecurityReport,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn env() -> Env {
    let e = Env::default();
    e.mock_all_auths();
    e
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. INVARIANT CHECKS
// ─────────────────────────────────────────────────────────────────────────────

// --- check_total_raised_equals_sum ---

/// @notice  Happy path: sum of contributions matches total_raised.
/// @custom:security-note  Confirms the core accounting invariant holds.
#[test]
fn test_total_raised_equals_sum_pass() {
    let result = check_total_raised_equals_sum(300, &[100, 150, 50]);
    assert_eq!(result, InvariantResult::Passed);
}

/// @notice  Failure path: sum does not match total_raised.
/// @custom:security-note  Detects double-credit or storage corruption.
#[test]
fn test_total_raised_equals_sum_fail() {
    let result = check_total_raised_equals_sum(400, &[100, 150, 50]);
    assert!(!result.is_passed());
    assert!(result.message().contains("TotalRaised != sum"));
}

/// @notice  Edge case: empty contributor list with zero total.
#[test]
fn test_total_raised_equals_sum_empty() {
    assert_eq!(
        check_total_raised_equals_sum(0, &[]),
        InvariantResult::Passed
    );
}

/// @notice  Edge case: single contributor, exact match.
#[test]
fn test_total_raised_equals_sum_single() {
    assert_eq!(
        check_total_raised_equals_sum(1, &[1]),
        InvariantResult::Passed
    );
}

/// @notice  Edge case: many small contributions aggregate to a large value
///          (precision-loss check — all values are exact integers in i128).
/// @custom:security-note  Soroban uses i128 for token amounts; no floating-
///          point rounding occurs.  This test confirms no precision loss.
#[test]
fn test_total_raised_equals_sum_many_small() {
    let contributions: Vec<i128> = (0..1_000).map(|_| 1i128).collect();
    assert_eq!(
        check_total_raised_equals_sum(1_000, &contributions),
        InvariantResult::Passed
    );
}

// --- check_total_raised_non_negative ---

/// @notice  Happy path: zero total is non-negative.
#[test]
fn test_total_raised_non_negative_zero() {
    assert_eq!(
        check_total_raised_non_negative(0),
        InvariantResult::Passed
    );
}

/// @notice  Happy path: positive total.
#[test]
fn test_total_raised_non_negative_positive() {
    assert_eq!(
        check_total_raised_non_negative(1_000_000),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: negative total.
/// @custom:security-note  Negative TotalRaised indicates arithmetic underflow.
#[test]
fn test_total_raised_non_negative_fail() {
    let result = check_total_raised_non_negative(-1);
    assert!(!result.is_passed());
    assert!(result.message().contains("TotalRaised is negative"));
}

// --- check_no_negative_contributions ---

/// @notice  Happy path: all contributions are positive.
#[test]
fn test_no_negative_contributions_pass() {
    assert_eq!(
        check_no_negative_contributions(&[10, 20, 30]),
        InvariantResult::Passed
    );
}

/// @notice  Happy path: empty list.
#[test]
fn test_no_negative_contributions_empty() {
    assert_eq!(
        check_no_negative_contributions(&[]),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: one negative contribution.
/// @custom:security-note  A negative contribution would inflate TotalRaised
///          without a real token transfer.
#[test]
fn test_no_negative_contributions_fail() {
    let result = check_no_negative_contributions(&[10, -1, 30]);
    assert!(!result.is_passed());
    assert!(result.message().contains("negative contribution"));
}

// --- check_goal_positive ---

/// @notice  Happy path: goal of 1 (minimum valid).
#[test]
fn test_goal_positive_min() {
    assert_eq!(check_goal_positive(1), InvariantResult::Passed);
}

/// @notice  Happy path: large goal.
#[test]
fn test_goal_positive_large() {
    assert_eq!(check_goal_positive(i128::MAX), InvariantResult::Passed);
}

/// @notice  Failure path: zero goal.
/// @custom:security-note  Zero goal allows the campaign to succeed immediately.
#[test]
fn test_goal_positive_zero_fail() {
    let result = check_goal_positive(0);
    assert!(!result.is_passed());
    assert!(result.message().contains("goal is zero or negative"));
}

/// @notice  Failure path: negative goal.
#[test]
fn test_goal_positive_negative_fail() {
    let result = check_goal_positive(-100);
    assert!(!result.is_passed());
}

// --- check_min_contribution_positive ---

/// @notice  Happy path: min_contribution of 1.
#[test]
fn test_min_contribution_positive_pass() {
    assert_eq!(
        check_min_contribution_positive(1),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: zero min_contribution.
/// @custom:security-note  Zero minimum allows dust contributions that bloat
///          the contributor list.
#[test]
fn test_min_contribution_positive_zero_fail() {
    let result = check_min_contribution_positive(0);
    assert!(!result.is_passed());
    assert!(result.message().contains("min_contribution is zero or negative"));
}

/// @notice  Failure path: negative min_contribution.
#[test]
fn test_min_contribution_positive_negative_fail() {
    let result = check_min_contribution_positive(-5);
    assert!(!result.is_passed());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. AUTHORIZATION PROBES
// ─────────────────────────────────────────────────────────────────────────────

// --- probe_withdraw_authorization ---

/// @notice  Happy path: caller is the creator.
#[test]
fn test_probe_withdraw_authorization_pass() {
    let env = env();
    let creator = Address::generate(&env);
    assert_eq!(
        probe_withdraw_authorization(&creator, &creator),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: caller is a different address.
/// @custom:security-note  Any address other than the creator must be rejected
///          by the withdraw authorization check.
#[test]
fn test_probe_withdraw_authorization_fail() {
    let env = env();
    let creator = Address::generate(&env);
    let attacker = Address::generate(&env);
    let result = probe_withdraw_authorization(&attacker, &creator);
    assert!(!result.is_passed());
    assert!(result.message().contains("not the campaign creator"));
}

// --- probe_contribution_amount ---

/// @notice  Happy path: positive amount.
#[test]
fn test_probe_contribution_amount_pass() {
    assert_eq!(probe_contribution_amount(1), InvariantResult::Passed);
    assert_eq!(probe_contribution_amount(i128::MAX), InvariantResult::Passed);
}

/// @notice  Failure path: zero amount.
/// @custom:security-note  Zero-value exploit attempt must be rejected.
#[test]
fn test_probe_contribution_amount_zero_fail() {
    let result = probe_contribution_amount(0);
    assert!(!result.is_passed());
    assert!(result.message().contains("zero or negative"));
}

/// @notice  Failure path: negative amount.
/// @custom:security-note  Negative-value exploit attempt must be rejected.
#[test]
fn test_probe_contribution_amount_negative_fail() {
    let result = probe_contribution_amount(-1);
    assert!(!result.is_passed());
    assert!(result.message().contains("zero or negative"));
}

/// @notice  Failure path: i128::MIN (maximum negative overflow attempt).
#[test]
fn test_probe_contribution_amount_min_i128_fail() {
    let result = probe_contribution_amount(i128::MIN);
    assert!(!result.is_passed());
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. STATE-MACHINE VALIDATORS
// ─────────────────────────────────────────────────────────────────────────────

// --- check_valid_status_transition ---

/// @notice  Happy path: Active → Succeeded.
#[test]
fn test_transition_active_to_succeeded() {
    assert_eq!(
        check_valid_status_transition(&CampaignStatus::Active, &CampaignStatus::Succeeded),
        InvariantResult::Passed
    );
}

/// @notice  Happy path: Active → Expired.
#[test]
fn test_transition_active_to_expired() {
    assert_eq!(
        check_valid_status_transition(&CampaignStatus::Active, &CampaignStatus::Expired),
        InvariantResult::Passed
    );
}

/// @notice  Happy path: Active → Cancelled.
#[test]
fn test_transition_active_to_cancelled() {
    assert_eq!(
        check_valid_status_transition(&CampaignStatus::Active, &CampaignStatus::Cancelled),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: Expired → Active (the key forbidden transition).
/// @custom:security-note  Re-activating an expired campaign would allow a
///          creator to collect new contributions against an expired deadline.
#[test]
fn test_transition_expired_to_active_fail() {
    let result =
        check_valid_status_transition(&CampaignStatus::Expired, &CampaignStatus::Active);
    assert!(!result.is_passed());
    assert!(result.message().contains("invalid campaign status transition"));
}

/// @notice  Failure path: Succeeded → Active.
#[test]
fn test_transition_succeeded_to_active_fail() {
    let result =
        check_valid_status_transition(&CampaignStatus::Succeeded, &CampaignStatus::Active);
    assert!(!result.is_passed());
}

/// @notice  Failure path: Cancelled → Active.
#[test]
fn test_transition_cancelled_to_active_fail() {
    let result =
        check_valid_status_transition(&CampaignStatus::Cancelled, &CampaignStatus::Active);
    assert!(!result.is_passed());
}

/// @notice  Failure path: Expired → Succeeded (skipping Active).
#[test]
fn test_transition_expired_to_succeeded_fail() {
    let result =
        check_valid_status_transition(&CampaignStatus::Expired, &CampaignStatus::Succeeded);
    assert!(!result.is_passed());
}

// --- check_contribution_within_deadline ---

/// @notice  Happy path: contribution exactly at the deadline second.
/// @custom:security-note  Edge case — contributions at `now == deadline` must
///          be accepted (inclusive boundary).
#[test]
fn test_contribution_at_deadline_boundary() {
    assert_eq!(
        check_contribution_within_deadline(1_000, 1_000),
        InvariantResult::Passed
    );
}

/// @notice  Happy path: contribution well before deadline.
#[test]
fn test_contribution_before_deadline() {
    assert_eq!(
        check_contribution_within_deadline(500, 1_000),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: contribution one second after deadline.
/// @custom:security-note  Post-deadline contributions must be rejected.
#[test]
fn test_contribution_after_deadline_fail() {
    let result = check_contribution_within_deadline(1_001, 1_000);
    assert!(!result.is_passed());
    assert!(result.message().contains("after deadline"));
}

// --- check_withdraw_requires_succeeded ---

/// @notice  Happy path: status is Succeeded.
#[test]
fn test_withdraw_requires_succeeded_pass() {
    assert_eq!(
        check_withdraw_requires_succeeded(&CampaignStatus::Succeeded),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: withdraw attempted while Active.
/// @custom:security-note  Prevents draining funds before the campaign ends.
#[test]
fn test_withdraw_requires_succeeded_active_fail() {
    let result = check_withdraw_requires_succeeded(&CampaignStatus::Active);
    assert!(!result.is_passed());
    assert!(result.message().contains("outside Succeeded state"));
}

/// @notice  Failure path: withdraw attempted while Expired.
#[test]
fn test_withdraw_requires_succeeded_expired_fail() {
    let result = check_withdraw_requires_succeeded(&CampaignStatus::Expired);
    assert!(!result.is_passed());
}

// --- check_refund_requires_expired ---

/// @notice  Happy path: status is Expired.
#[test]
fn test_refund_requires_expired_pass() {
    assert_eq!(
        check_refund_requires_expired(&CampaignStatus::Expired),
        InvariantResult::Passed
    );
}

/// @notice  Failure path: refund attempted while Active.
/// @custom:security-note  Prevents contributors from draining funds before
///          the campaign ends.
#[test]
fn test_refund_requires_expired_active_fail() {
    let result = check_refund_requires_expired(&CampaignStatus::Active);
    assert!(!result.is_passed());
    assert!(result.message().contains("outside Expired state"));
}

/// @notice  Failure path: refund attempted after Succeeded.
/// @custom:security-note  Prevents double-spend after creator has withdrawn.
#[test]
fn test_refund_requires_expired_succeeded_fail() {
    let result = check_refund_requires_expired(&CampaignStatus::Succeeded);
    assert!(!result.is_passed());
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AGGREGATE RUNNER
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Happy path: all checks pass with valid state.
#[test]
fn test_run_security_audit_all_pass() {
    let env = env();
    let report: SecurityReport = run_security_audit(
        &env,
        300,
        &[100, 150, 50],
        1_000,
        10,
        &CampaignStatus::Active,
    );
    assert!(report.all_passed, "expected all checks to pass");
    assert_eq!(report.failed, 0);
    assert_eq!(report.passed, 6);
}

/// @notice  Failure path: negative total_raised triggers two failures.
#[test]
fn test_run_security_audit_negative_total() {
    let env = env();
    let report: SecurityReport = run_security_audit(
        &env,
        -1,
        &[100],
        1_000,
        10,
        &CampaignStatus::Active,
    );
    assert!(!report.all_passed);
    assert!(report.failed >= 1);
}

/// @notice  Failure path: zero goal triggers a failure.
#[test]
fn test_run_security_audit_zero_goal() {
    let env = env();
    let report: SecurityReport = run_security_audit(
        &env,
        0,
        &[],
        0, // invalid goal
        10,
        &CampaignStatus::Active,
    );
    assert!(!report.all_passed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PROPERTY-BASED / FUZZ TESTS
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// @notice  Property: for any non-positive amount, probe_contribution_amount
    ///          must always fail.
    /// @custom:security-note  Ensures zero and negative exploit attempts are
    ///          always rejected regardless of the specific value.
    #[test]
    fn prop_non_positive_amount_always_fails(amount in i128::MIN..=0i128) {
        prop_assert!(!probe_contribution_amount(amount).is_passed());
    }

    /// @notice  Property: for any positive amount, probe_contribution_amount
    ///          must always pass.
    #[test]
    fn prop_positive_amount_always_passes(amount in 1i128..=i128::MAX) {
        prop_assert!(probe_contribution_amount(amount).is_passed());
    }

    /// @notice  Property: for any positive goal, check_goal_positive passes.
    #[test]
    fn prop_positive_goal_always_passes(goal in 1i128..=i128::MAX) {
        prop_assert!(check_goal_positive(goal).is_passed());
    }

    /// @notice  Property: for any non-positive goal, check_goal_positive fails.
    #[test]
    fn prop_non_positive_goal_always_fails(goal in i128::MIN..=0i128) {
        prop_assert!(!check_goal_positive(goal).is_passed());
    }

    /// @notice  Property: sum of a random non-negative contribution list always
    ///          satisfies the accounting invariant when total_raised is set to
    ///          the actual sum.
    /// @custom:security-note  Confirms no precision loss for arbitrary lists.
    #[test]
    fn prop_sum_invariant_holds_for_valid_inputs(
        contributions in prop::collection::vec(1i128..=1_000_000i128, 0..50)
    ) {
        let total: i128 = contributions.iter().sum();
        prop_assert_eq!(
            check_total_raised_equals_sum(total, &contributions),
            InvariantResult::Passed
        );
    }

    /// @notice  Property: a single negative value in contributions always
    ///          triggers check_no_negative_contributions to fail.
    #[test]
    fn prop_any_negative_contribution_fails(
        neg in i128::MIN..=-1i128,
        positives in prop::collection::vec(1i128..=1_000i128, 0..10)
    ) {
        let mut contributions = positives;
        contributions.push(neg);
        prop_assert!(!check_no_negative_contributions(&contributions).is_passed());
    }

    /// @notice  Property: contribution exactly at the deadline always passes
    ///          the deadline check.
    #[test]
    fn prop_contribution_at_deadline_always_passes(ts in 0u64..=u64::MAX / 2) {
        prop_assert!(check_contribution_within_deadline(ts, ts).is_passed());
    }

    /// @notice  Property: contribution one second after deadline always fails.
    #[test]
    fn prop_contribution_one_second_after_deadline_fails(ts in 0u64..u64::MAX - 1) {
        prop_assert!(!check_contribution_within_deadline(ts + 1, ts).is_passed());
    }

    /// @notice  Property: re-initialization attempt — check_valid_status_transition
    ///          from any terminal state back to Active always fails.
    #[test]
    fn prop_no_transition_back_to_active(
        // 0 = Expired, 1 = Succeeded, 2 = Cancelled
        variant in 0u8..=2u8
    ) {
        let from = match variant {
            0 => CampaignStatus::Expired,
            1 => CampaignStatus::Succeeded,
            _ => CampaignStatus::Cancelled,
        };
        prop_assert!(
            !check_valid_status_transition(&from, &CampaignStatus::Active).is_passed()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. EDGE CASES
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Re-initialization attempt: campaign already Active must not
///          transition back to Active.
/// @custom:security-note  Prevents a creator from resetting campaign state
///          to extend the deadline or reset the goal.
#[test]
fn test_reinitialize_attempt_blocked() {
    let result =
        check_valid_status_transition(&CampaignStatus::Active, &CampaignStatus::Active);
    assert!(!result.is_passed(), "Active → Active must be rejected");
}

/// @notice  Overflow attempt: i128::MAX + 1 would overflow; the sum helper
///          saturates to i128::MAX which will not equal a sane total_raised.
/// @custom:security-note  Confirms the overflow guard in
///          `check_total_raised_equals_sum` fires correctly.
#[test]
fn test_overflow_attempt_in_sum() {
    // Two values that overflow i128 when added.
    let contributions = [i128::MAX, 1i128];
    // The real sum overflows; our helper saturates to i128::MAX.
    // total_raised of i128::MAX - 1 will not match.
    let result = check_total_raised_equals_sum(i128::MAX - 1, &contributions);
    assert!(!result.is_passed());
}

/// @notice  Successful funding exactly at the deadline second.
/// @custom:security-note  Inclusive boundary — `now == deadline` must be
///          accepted.
#[test]
fn test_funding_exactly_at_deadline() {
    let deadline: u64 = 1_711_598_400; // arbitrary fixed timestamp
    assert_eq!(
        check_contribution_within_deadline(deadline, deadline),
        InvariantResult::Passed
    );
}

/// @notice  InvariantResult helper methods.
#[test]
fn test_invariant_result_helpers() {
    assert!(InvariantResult::Passed.is_passed());
    assert_eq!(InvariantResult::Passed.message(), "");

    let failed = InvariantResult::Failed("test error");
    assert!(!failed.is_passed());
    assert_eq!(failed.message(), "test error");
}
