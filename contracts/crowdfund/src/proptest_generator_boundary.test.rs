//! # ProptestGeneratorBoundary — On-Chain Contract Test Suite
//!
//! @title   ProptestGeneratorBoundary Tests
//! @notice  Validates boundary constants, clamping, validation, and the new
//!          frontend UI edge cases introduced in Issue #423.
//! @dev     Uses the Soroban test environment and the generated client.
//!
//! ## Coverage
//!
//! - Constant sanity checks
//! - Deadline offset validation (boundary values + edge cases)
//! - Goal validation (boundary values + edge cases)
//! - Min-contribution validation
//! - Contribution amount validation
//! - Fee bps validation
//! - Generator batch size validation
//! - Clamping functions
//! - Derived calculations (progress, fee, display percent, net payout)
//! - **New (Issue #423)**: UI-displayable progress, contribution UI safety,
//!   deadline UI state, display percent, net payout edge cases
//! - Property-based tests (256 cases each)
//! - Regression seeds

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use soroban_sdk::{Env, Symbol};

    use crate::proptest_generator_boundary::{
        clamp_progress_bps, compute_display_percent, compute_net_payout, compute_progress_bps,
        deadline_ui_state, is_contribution_ui_safe, is_ui_displayable_progress,
        is_valid_contribution_amount, is_valid_deadline_offset, is_valid_goal,
        is_valid_min_contribution, DeadlineUiState, ProptestGeneratorBoundary,
        ProptestGeneratorBoundaryClient, DEADLINE_ENDING_SOON_THRESHOLD, DEADLINE_OFFSET_MAX,
        DEADLINE_OFFSET_MIN, FEE_BPS_CAP, GENERATOR_BATCH_MAX, GOAL_MAX, GOAL_MIN,
        MAX_TOKEN_DECIMALS, MIN_CONTRIBUTION_FLOOR, PROGRESS_BPS_CAP, PROPTEST_CASES_MAX,
        PROPTEST_CASES_MIN,
    };

    // ── Setup ─────────────────────────────────────────────────────────────────

    fn setup() -> (Env, ProptestGeneratorBoundaryClient<'static>) {
        let env = Env::default();
        let contract_id = env.register(ProptestGeneratorBoundary, ());
        let client = ProptestGeneratorBoundaryClient::new(&env, &contract_id);
        (env, client)
    }

    // ── Constant Sanity ───────────────────────────────────────────────────────

    #[test]
    fn test_constants_are_ordered_correctly() {
        assert!(DEADLINE_OFFSET_MIN < DEADLINE_OFFSET_MAX);
        assert!(GOAL_MIN < GOAL_MAX);
        assert!(PROPTEST_CASES_MIN < PROPTEST_CASES_MAX);
        assert!(PROGRESS_BPS_CAP > 0);
        assert!(FEE_BPS_CAP > 0);
        assert!(GENERATOR_BATCH_MAX > 0);
        assert!(MAX_TOKEN_DECIMALS > 0);
        assert!(DEADLINE_ENDING_SOON_THRESHOLD > 0);
        assert!(DEADLINE_ENDING_SOON_THRESHOLD < DEADLINE_OFFSET_MIN);
    }

    #[test]
    fn test_contract_constants_match_rust_constants() {
        let (_env, client) = setup();
        assert_eq!(client.deadline_offset_min(), DEADLINE_OFFSET_MIN);
        assert_eq!(client.deadline_offset_max(), DEADLINE_OFFSET_MAX);
        assert_eq!(client.goal_min(), GOAL_MIN);
        assert_eq!(client.goal_max(), GOAL_MAX);
        assert_eq!(client.min_contribution_floor(), MIN_CONTRIBUTION_FLOOR);
        assert_eq!(client.progress_bps_cap(), PROGRESS_BPS_CAP);
        assert_eq!(client.fee_bps_cap(), FEE_BPS_CAP);
        assert_eq!(client.proptest_cases_min(), PROPTEST_CASES_MIN);
        assert_eq!(client.proptest_cases_max(), PROPTEST_CASES_MAX);
        assert_eq!(client.generator_batch_max(), GENERATOR_BATCH_MAX);
        assert_eq!(client.max_token_decimals(), MAX_TOKEN_DECIMALS);
        assert_eq!(
            client.deadline_ending_soon_threshold(),
            DEADLINE_ENDING_SOON_THRESHOLD
        );
    }

    // ── Deadline Offset Validation ────────────────────────────────────────────

    #[test]
    fn test_is_valid_deadline_offset_boundary_values() {
        let (_env, client) = setup();
        assert!(client.is_valid_deadline_offset(&DEADLINE_OFFSET_MIN));
        assert!(!client.is_valid_deadline_offset(&(DEADLINE_OFFSET_MIN - 1)));
        assert!(client.is_valid_deadline_offset(&DEADLINE_OFFSET_MAX));
        assert!(!client.is_valid_deadline_offset(&(DEADLINE_OFFSET_MAX + 1)));
        assert!(client.is_valid_deadline_offset(&500_000));
    }

    #[test]
    fn test_is_valid_deadline_offset_edge_cases() {
        let (_env, client) = setup();
        assert!(!client.is_valid_deadline_offset(&0));
        assert!(!client.is_valid_deadline_offset(&999));
        assert!(!client.is_valid_deadline_offset(&u64::MAX));
    }

    // ── Goal Validation ───────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_goal_boundary_values() {
        let (_env, client) = setup();
        assert!(client.is_valid_goal(&GOAL_MIN));
        assert!(!client.is_valid_goal(&(GOAL_MIN - 1)));
        assert!(client.is_valid_goal(&GOAL_MAX));
        assert!(!client.is_valid_goal(&(GOAL_MAX + 1)));
        assert!(client.is_valid_goal(&50_000_000));
    }

    #[test]
    fn test_is_valid_goal_edge_cases() {
        let (_env, client) = setup();
        assert!(!client.is_valid_goal(&0));
        assert!(!client.is_valid_goal(&-1));
        assert!(!client.is_valid_goal(&999));
        assert!(!client.is_valid_goal(&i128::MIN));
    }

    // ── Min Contribution Validation ───────────────────────────────────────────

    #[test]
    fn test_is_valid_min_contribution() {
        let (_env, client) = setup();
        let goal = 1_000_000i128;
        assert!(client.is_valid_min_contribution(&MIN_CONTRIBUTION_FLOOR, &goal));
        assert!(client.is_valid_min_contribution(&500_000, &goal));
        assert!(client.is_valid_min_contribution(&goal, &goal));
        assert!(!client.is_valid_min_contribution(&0, &goal));
        assert!(!client.is_valid_min_contribution(&(goal + 1), &goal));
        assert!(!client.is_valid_min_contribution(&-1, &goal));
    }

    #[test]
    fn test_is_valid_min_contribution_with_min_goal() {
        let (_env, client) = setup();
        assert!(client.is_valid_min_contribution(&MIN_CONTRIBUTION_FLOOR, &GOAL_MIN));
        assert!(!client.is_valid_min_contribution(&(GOAL_MIN + 1), &GOAL_MIN));
    }

    // ── Contribution Amount Validation ────────────────────────────────────────

    #[test]
    fn test_is_valid_contribution_amount() {
        let (_env, client) = setup();
        let min = 1_000i128;
        assert!(client.is_valid_contribution_amount(&min, &min));
        assert!(client.is_valid_contribution_amount(&(min + 1), &min));
        assert!(client.is_valid_contribution_amount(&1_000_000, &min));
        assert!(!client.is_valid_contribution_amount(&(min - 1), &min));
        assert!(!client.is_valid_contribution_amount(&0, &min));
        assert!(!client.is_valid_contribution_amount(&-1, &min));
    }

    // ── Fee Bps Validation ────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_fee_bps() {
        let (_env, client) = setup();
        assert!(client.is_valid_fee_bps(&0));
        assert!(client.is_valid_fee_bps(&5_000));
        assert!(client.is_valid_fee_bps(&FEE_BPS_CAP));
        assert!(!client.is_valid_fee_bps(&(FEE_BPS_CAP + 1)));
        assert!(!client.is_valid_fee_bps(&u32::MAX));
    }

    // ── Generator Batch Size Validation ───────────────────────────────────────

    #[test]
    fn test_is_valid_generator_batch_size() {
        let (_env, client) = setup();
        assert!(client.is_valid_generator_batch_size(&1));
        assert!(client.is_valid_generator_batch_size(&256));
        assert!(client.is_valid_generator_batch_size(&GENERATOR_BATCH_MAX));
        assert!(!client.is_valid_generator_batch_size(&0));
        assert!(!client.is_valid_generator_batch_size(&(GENERATOR_BATCH_MAX + 1)));
    }

    // ── Clamping ──────────────────────────────────────────────────────────────

    #[test]
    fn test_clamp_proptest_cases() {
        let (_env, client) = setup();
        assert_eq!(client.clamp_proptest_cases(&0), PROPTEST_CASES_MIN);
        assert_eq!(client.clamp_proptest_cases(&1), PROPTEST_CASES_MIN);
        assert_eq!(client.clamp_proptest_cases(&64), 64);
        assert_eq!(client.clamp_proptest_cases(&128), 128);
        assert_eq!(client.clamp_proptest_cases(&PROPTEST_CASES_MAX), PROPTEST_CASES_MAX);
        assert_eq!(client.clamp_proptest_cases(&1_000), PROPTEST_CASES_MAX);
        assert_eq!(client.clamp_proptest_cases(&u32::MAX), PROPTEST_CASES_MAX);
    }

    #[test]
    fn test_clamp_progress_bps() {
        let (_env, client) = setup();
        assert_eq!(client.clamp_progress_bps(&-1_000), 0);
        assert_eq!(client.clamp_progress_bps(&-1), 0);
        assert_eq!(client.clamp_progress_bps(&0), 0);
        assert_eq!(client.clamp_progress_bps(&5_000), 5_000);
        assert_eq!(client.clamp_progress_bps(&10_000), PROGRESS_BPS_CAP);
        assert_eq!(client.clamp_progress_bps(&10_001), PROGRESS_BPS_CAP);
        assert_eq!(client.clamp_progress_bps(&i128::MAX), PROGRESS_BPS_CAP);
    }

    // ── compute_progress_bps ──────────────────────────────────────────────────

    #[test]
    fn test_compute_progress_bps_basic() {
        let (_env, client) = setup();
        assert_eq!(client.compute_progress_bps(&500, &1_000), 5_000);
        assert_eq!(client.compute_progress_bps(&1_000, &1_000), 10_000);
        assert_eq!(client.compute_progress_bps(&2_000, &1_000), 10_000);
    }

    #[test]
    fn test_compute_progress_bps_edge_cases() {
        let (_env, client) = setup();
        assert_eq!(client.compute_progress_bps(&500, &0), 0);
        assert_eq!(client.compute_progress_bps(&500, &-1_000), 0);
        assert_eq!(client.compute_progress_bps(&-100, &1_000), 0);
        assert_eq!(client.compute_progress_bps(&1, &10_000), 1);
    }

    #[test]
    fn test_compute_progress_bps_overflow_safety() {
        let (_env, client) = setup();
        let result = client.compute_progress_bps(&(i128::MAX / 2), &1_000);
        assert_eq!(result, PROGRESS_BPS_CAP);
    }

    // ── compute_fee_amount ────────────────────────────────────────────────────

    #[test]
    fn test_compute_fee_amount_basic() {
        let (_env, client) = setup();
        assert_eq!(client.compute_fee_amount(&1_000, &1_000), 100);
        assert_eq!(client.compute_fee_amount(&1_000, &5_000), 500);
        assert_eq!(client.compute_fee_amount(&1_000, &10_000), 1_000);
    }

    #[test]
    fn test_compute_fee_amount_edge_cases() {
        let (_env, client) = setup();
        assert_eq!(client.compute_fee_amount(&0, &5_000), 0);
        assert_eq!(client.compute_fee_amount(&-1_000, &5_000), 0);
        assert_eq!(client.compute_fee_amount(&1_000, &0), 0);
        assert_eq!(client.compute_fee_amount(&0, &0), 0);
    }

    #[test]
    fn test_compute_fee_amount_floor_division() {
        let (_env, client) = setup();
        assert_eq!(client.compute_fee_amount(&1_000, &3_333), 333);
        assert_eq!(client.compute_fee_amount(&1_000, &6_666), 666);
    }

    // ── log_tag ───────────────────────────────────────────────────────────────

    #[test]
    fn test_log_tag() {
        let (env, client) = setup();
        assert_eq!(client.log_tag(), Symbol::new(&env, "boundary"));
    }

    // ── New Edge Cases: is_ui_displayable_progress (Issue #423) ──────────────

    #[test]
    fn test_is_ui_displayable_progress_valid_range() {
        let (_env, client) = setup();
        assert!(client.is_ui_displayable_progress(&0));
        assert!(client.is_ui_displayable_progress(&5_000));
        assert!(client.is_ui_displayable_progress(&PROGRESS_BPS_CAP));
    }

    #[test]
    fn test_is_ui_displayable_progress_above_cap_rejected() {
        let (_env, client) = setup();
        assert!(!client.is_ui_displayable_progress(&(PROGRESS_BPS_CAP + 1)));
        assert!(!client.is_ui_displayable_progress(&u32::MAX));
    }

    // ── New Edge Cases: compute_display_percent (Issue #423) ─────────────────

    #[test]
    fn test_compute_display_percent_basic() {
        let (_env, client) = setup();
        assert_eq!(client.compute_display_percent(&0), 0);
        assert_eq!(client.compute_display_percent(&5_000), 5_000);
        assert_eq!(client.compute_display_percent(&10_000), 10_000);
    }

    #[test]
    fn test_compute_display_percent_clamps_above_cap() {
        let (_env, client) = setup();
        assert_eq!(client.compute_display_percent(&10_001), PROGRESS_BPS_CAP);
        assert_eq!(client.compute_display_percent(&u32::MAX), PROGRESS_BPS_CAP);
    }

    // ── New Edge Cases: is_contribution_ui_safe (Issue #423) ─────────────────

    #[test]
    fn test_is_contribution_ui_safe_valid() {
        let (_env, client) = setup();
        // XLM decimals = 7
        assert!(client.is_contribution_ui_safe(&1_000, &1_000, &7));
        assert!(client.is_contribution_ui_safe(&100_000_000, &1_000, &7));
        // USDC decimals = 6
        assert!(client.is_contribution_ui_safe(&1_000, &1_000, &6));
    }

    #[test]
    fn test_is_contribution_ui_safe_below_minimum_rejected() {
        let (_env, client) = setup();
        assert!(!client.is_contribution_ui_safe(&999, &1_000, &7));
        assert!(!client.is_contribution_ui_safe(&0, &1_000, &7));
        assert!(!client.is_contribution_ui_safe(&-1, &1_000, &7));
    }

    #[test]
    fn test_is_contribution_ui_safe_excessive_decimals_rejected() {
        let (_env, client) = setup();
        assert!(!client.is_contribution_ui_safe(&1_000, &1_000, &(MAX_TOKEN_DECIMALS + 1)));
        assert!(!client.is_contribution_ui_safe(&1_000, &1_000, &255));
    }

    #[test]
    fn test_is_contribution_ui_safe_overflow_rejected() {
        let (_env, client) = setup();
        // i128::MAX * 10^18 overflows
        assert!(!client.is_contribution_ui_safe(&i128::MAX, &1_000, &18));
    }

    #[test]
    fn test_is_contribution_ui_safe_zero_decimals() {
        let (_env, client) = setup();
        // 0 decimals: scale = 1, no overflow possible for valid amounts
        assert!(client.is_contribution_ui_safe(&1_000, &1_000, &0));
    }

    // ── New Edge Cases: deadline_ui_state (Issue #423) ────────────────────────

    #[test]
    fn test_deadline_ui_state_expired() {
        assert_eq!(deadline_ui_state(0), DeadlineUiState::Expired);
    }

    #[test]
    fn test_deadline_ui_state_ending_soon_boundary() {
        assert_eq!(
            deadline_ui_state(DEADLINE_ENDING_SOON_THRESHOLD),
            DeadlineUiState::EndingSoon
        );
        assert_eq!(deadline_ui_state(1), DeadlineUiState::EndingSoon);
        assert_eq!(
            deadline_ui_state(DEADLINE_ENDING_SOON_THRESHOLD - 1),
            DeadlineUiState::EndingSoon
        );
    }

    #[test]
    fn test_deadline_ui_state_active() {
        assert_eq!(
            deadline_ui_state(DEADLINE_ENDING_SOON_THRESHOLD + 1),
            DeadlineUiState::Active
        );
        assert_eq!(deadline_ui_state(DEADLINE_OFFSET_MIN), DeadlineUiState::Active);
        assert_eq!(deadline_ui_state(u64::MAX), DeadlineUiState::Active);
    }

    // ── New Edge Cases: compute_net_payout (Issue #423) ───────────────────────

    #[test]
    fn test_compute_net_payout_basic() {
        let (_env, client) = setup();
        // 10 % fee on 1 000 → net = 900
        assert_eq!(client.compute_net_payout(&1_000, &1_000), 900);
        // 0 % fee → net = total
        assert_eq!(client.compute_net_payout(&1_000, &0), 1_000);
        // 100 % fee → net = 0
        assert_eq!(client.compute_net_payout(&1_000, &10_000), 0);
    }

    #[test]
    fn test_compute_net_payout_zero_total() {
        let (_env, client) = setup();
        assert_eq!(client.compute_net_payout(&0, &5_000), 0);
    }

    #[test]
    fn test_compute_net_payout_invalid_fee_returns_zero() {
        let (_env, client) = setup();
        // fee_bps > FEE_BPS_CAP → None → contract returns 0
        assert_eq!(client.compute_net_payout(&1_000, &(FEE_BPS_CAP + 1)), 0);
        assert_eq!(client.compute_net_payout(&1_000, &u32::MAX), 0);
    }

    #[test]
    fn test_compute_net_payout_negative_total_returns_zero() {
        let (_env, client) = setup();
        assert_eq!(client.compute_net_payout(&-1_000, &1_000), 0);
    }

    // ── Pure function: compute_net_payout returns None on invalid fee ─────────

    #[test]
    fn test_pure_compute_net_payout_none_on_invalid_fee() {
        assert_eq!(compute_net_payout(1_000, FEE_BPS_CAP + 1), None);
    }

    #[test]
    fn test_pure_compute_net_payout_some_on_valid_fee() {
        assert_eq!(compute_net_payout(1_000, 1_000), Some(900));
        assert_eq!(compute_net_payout(1_000, 0), Some(1_000));
        assert_eq!(compute_net_payout(0, 5_000), Some(0));
    }

    // ── Property-Based Tests ──────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_valid_deadline_offset_always_accepted(
            offset in DEADLINE_OFFSET_MIN..=DEADLINE_OFFSET_MAX
        ) {
            prop_assert!(is_valid_deadline_offset(offset));
        }

        #[test]
        fn prop_deadline_offset_below_min_rejected(offset in 0u64..DEADLINE_OFFSET_MIN) {
            prop_assert!(!is_valid_deadline_offset(offset));
        }

        #[test]
        fn prop_deadline_offset_above_max_rejected(
            offset in (DEADLINE_OFFSET_MAX + 1)..=(DEADLINE_OFFSET_MAX + 100_000)
        ) {
            prop_assert!(!is_valid_deadline_offset(offset));
        }

        #[test]
        fn prop_valid_goal_always_accepted(goal in GOAL_MIN..=GOAL_MAX) {
            prop_assert!(is_valid_goal(goal));
        }

        #[test]
        fn prop_goal_below_min_rejected(goal in i128::MIN..GOAL_MIN) {
            prop_assert!(!is_valid_goal(goal));
        }

        #[test]
        fn prop_goal_above_max_rejected(goal in (GOAL_MAX + 1)..i128::MAX) {
            prop_assert!(!is_valid_goal(goal));
        }

        #[test]
        fn prop_progress_bps_always_bounded(
            raised in -1_000_000_000i128..=1_000_000_000i128,
            goal in GOAL_MIN..=GOAL_MAX
        ) {
            let bps = compute_progress_bps(raised, goal);
            prop_assert!(bps <= PROGRESS_BPS_CAP);
        }

        #[test]
        fn prop_progress_bps_zero_when_goal_zero(raised in -1_000_000i128..=1_000_000i128) {
            prop_assert_eq!(compute_progress_bps(raised, 0), 0);
        }

        #[test]
        fn prop_clamp_progress_bps_within_bounds(raw in i128::MIN..=i128::MAX) {
            let clamped = clamp_progress_bps(raw);
            prop_assert!(clamped <= PROGRESS_BPS_CAP);
        }

        /// Property (Issue #423): is_ui_displayable_progress is true iff bps <= cap.
        #[test]
        fn prop_ui_displayable_progress_iff_within_cap(bps in 0u32..=u32::MAX) {
            prop_assert_eq!(is_ui_displayable_progress(bps), bps <= PROGRESS_BPS_CAP);
        }

        /// Property (Issue #423): compute_display_percent never exceeds cap.
        #[test]
        fn prop_display_percent_never_exceeds_cap(bps in 0u32..=u32::MAX) {
            prop_assert!(compute_display_percent(bps) <= PROGRESS_BPS_CAP);
        }

        /// Property (Issue #423): compute_net_payout returns None iff fee_bps > cap.
        #[test]
        fn prop_net_payout_none_iff_fee_above_cap(
            total in 0i128..=100_000_000i128,
            fee_bps in (FEE_BPS_CAP + 1)..=u32::MAX
        ) {
            prop_assert_eq!(compute_net_payout(total, fee_bps), None);
        }

        /// Property (Issue #423): compute_net_payout is Some for valid fee_bps.
        #[test]
        fn prop_net_payout_some_for_valid_fee(
            total in 0i128..=100_000_000i128,
            fee_bps in 0u32..=FEE_BPS_CAP
        ) {
            prop_assert!(compute_net_payout(total, fee_bps).is_some());
        }

        /// Property (Issue #423): net payout never exceeds total.
        #[test]
        fn prop_net_payout_never_exceeds_total(
            total in 0i128..=100_000_000i128,
            fee_bps in 0u32..=FEE_BPS_CAP
        ) {
            if let Some(net) = compute_net_payout(total, fee_bps) {
                prop_assert!(net <= total);
                prop_assert!(net >= 0);
            }
        }

        /// Property (Issue #423): deadline_ui_state(0) is always Expired.
        #[test]
        fn prop_deadline_expired_when_zero(_x in 0u32..1u32) {
            prop_assert_eq!(deadline_ui_state(0), DeadlineUiState::Expired);
        }

        /// Property (Issue #423): deadline_ui_state is never Expired for > 0.
        #[test]
        fn prop_deadline_not_expired_when_positive(secs in 1u64..=u64::MAX) {
            prop_assert_ne!(deadline_ui_state(secs), DeadlineUiState::Expired);
        }

        /// Property (Issue #423): is_contribution_ui_safe rejects excessive decimals.
        #[test]
        fn prop_contribution_ui_safe_rejects_excess_decimals(
            amount in MIN_CONTRIBUTION_FLOOR..=GOAL_MAX,
            decimals in (MAX_TOKEN_DECIMALS + 1)..=255u32
        ) {
            prop_assert!(!is_contribution_ui_safe(amount, MIN_CONTRIBUTION_FLOOR, decimals));
        }

        /// Property (Issue #423): is_contribution_ui_safe rejects below-minimum amounts.
        #[test]
        fn prop_contribution_ui_safe_rejects_below_minimum(
            amount in i128::MIN..MIN_CONTRIBUTION_FLOOR
        ) {
            prop_assert!(!is_contribution_ui_safe(amount, MIN_CONTRIBUTION_FLOOR, 7));
        }
    }

    // ── Regression Seeds ──────────────────────────────────────────────────────

    #[test]
    fn regression_deadline_offset_100_rejected() {
        let (_env, client) = setup();
        assert!(!client.is_valid_deadline_offset(&100));
    }

    #[test]
    fn regression_goal_zero_rejected() {
        let (_env, client) = setup();
        assert!(!client.is_valid_goal(&0));
    }

    #[test]
    fn regression_progress_bps_never_exceeds_cap() {
        let (_env, client) = setup();
        assert_eq!(client.compute_progress_bps(&i128::MAX, &1), PROGRESS_BPS_CAP);
    }

    #[test]
    fn regression_fee_amount_never_negative() {
        let (_env, client) = setup();
        assert!(client.compute_fee_amount(&-1_000_000, &5_000) >= 0);
    }

    /// @security Regression: net payout with fee > cap must not silently return
    ///           a wrong value — the contract must return 0 (None path).
    #[test]
    fn regression_net_payout_invalid_fee_returns_zero() {
        let (_env, client) = setup();
        assert_eq!(client.compute_net_payout(&1_000_000, &(FEE_BPS_CAP + 1)), 0);
    }

    /// @security Regression: progress bar must never show > 100 % for over-funded
    ///           campaigns — critical for frontend UX trust.
    #[test]
    fn regression_overfunded_campaign_capped_at_100_percent() {
        let (_env, client) = setup();
        assert_eq!(
            client.compute_progress_bps(&200_000_000, &100_000_000),
            PROGRESS_BPS_CAP
        );
        assert!(client.is_ui_displayable_progress(&PROGRESS_BPS_CAP));
    }

    /// @security Regression: deadline_ui_state(0) must be Expired, not EndingSoon.
    #[test]
    fn regression_zero_seconds_is_expired_not_ending_soon() {
        assert_eq!(deadline_ui_state(0), DeadlineUiState::Expired);
        assert_ne!(deadline_ui_state(0), DeadlineUiState::EndingSoon);
    }
}
