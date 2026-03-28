//! Tests for the `algorithm_optimization` module.
//!
//! Coverage targets:
//! - `batch_contribution_lookup`: empty, partial, full batch, missing entries, cap enforcement
//! - `progress_bps`: zero/negative guards, exact 100 %, saturation, rounding
//! - `is_refund_eligible`: all four eligibility conditions
//! - `find_first_above_threshold`: no match, first match, early exit
//! - `sum_contributions`: empty, mixed, saturation guard

#[cfg(test)]
mod algorithm_optimization_tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env, Vec,
    };

    use crate::{
        algorithm_optimization::{
            batch_contribution_lookup, find_first_above_threshold, is_refund_eligible, progress_bps,
            sum_contributions, BPS_SCALE, MAX_BATCH_SIZE,
        },
        DataKey,
    };

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Seeds a contribution directly into persistent storage, bypassing the
    /// full `contribute()` flow so tests stay focused on the helpers under test.
    fn seed_contribution(env: &Env, contributor: &Address, amount: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::Contribution(contributor.clone()), &amount);
    }

    fn make_env() -> Env {
        Env::default()
    }

    // ── batch_contribution_lookup ─────────────────────────────────────────────

    #[test]
    fn batch_lookup_empty_vec_returns_empty() {
        let env = make_env();
        let addresses: Vec<Address> = Vec::new(&env);
        let results = batch_contribution_lookup(&env, &addresses);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn batch_lookup_missing_entries_return_zero() {
        let env = make_env();
        let addr = Address::generate(&env);
        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(addr);

        let results = batch_contribution_lookup(&env, &addresses);
        assert_eq!(results.len(), 1);
        assert_eq!(results.get(0).unwrap(), 0);
    }

    #[test]
    fn batch_lookup_returns_seeded_amounts() {
        let env = make_env();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        seed_contribution(&env, &a, 500);
        seed_contribution(&env, &b, 1_000);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);
        addresses.push_back(b);

        let results = batch_contribution_lookup(&env, &addresses);
        assert_eq!(results.get(0).unwrap(), 500);
        assert_eq!(results.get(1).unwrap(), 1_000);
    }

    #[test]
    fn batch_lookup_mixed_present_and_missing() {
        let env = make_env();
        let present = Address::generate(&env);
        let absent = Address::generate(&env);
        seed_contribution(&env, &present, 250);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(present);
        addresses.push_back(absent);

        let results = batch_contribution_lookup(&env, &addresses);
        assert_eq!(results.get(0).unwrap(), 250);
        assert_eq!(results.get(1).unwrap(), 0);
    }

    #[test]
    #[should_panic(expected = "MAX_BATCH_SIZE")]
    fn batch_lookup_panics_over_cap() {
        let env = make_env();
        let mut addresses: Vec<Address> = Vec::new(&env);
        for _ in 0..=MAX_BATCH_SIZE {
            addresses.push_back(Address::generate(&env));
        }
        batch_contribution_lookup(&env, &addresses);
    }

    // ── progress_bps ─────────────────────────────────────────────────────────

    #[test]
    fn progress_bps_zero_raised_returns_zero() {
        assert_eq!(progress_bps(0, 1_000), 0);
    }

    #[test]
    fn progress_bps_negative_raised_returns_zero() {
        assert_eq!(progress_bps(-1, 1_000), 0);
    }

    #[test]
    fn progress_bps_zero_goal_returns_zero() {
        assert_eq!(progress_bps(500, 0), 0);
    }

    #[test]
    fn progress_bps_negative_goal_returns_zero() {
        assert_eq!(progress_bps(500, -1), 0);
    }

    #[test]
    fn progress_bps_half_goal_returns_5000() {
        assert_eq!(progress_bps(500, 1_000), 5_000);
    }

    #[test]
    fn progress_bps_exact_goal_returns_10000() {
        assert_eq!(progress_bps(1_000, 1_000), 10_000);
    }

    #[test]
    fn progress_bps_over_goal_saturates_at_10000() {
        assert_eq!(progress_bps(2_000, 1_000), 10_000);
    }

    #[test]
    fn progress_bps_one_unit_raised() {
        // 1 / 10_000 * 10_000 = 1 bps
        assert_eq!(progress_bps(1, 10_000), 1);
    }

    #[test]
    fn progress_bps_large_values_no_overflow() {
        // i128::MAX / 2 raised against i128::MAX goal → ~5000 bps
        let half = i128::MAX / 2;
        let result = progress_bps(half, i128::MAX);
        assert!(result <= BPS_SCALE as u32);
    }

    // ── is_refund_eligible ────────────────────────────────────────────────────

    #[test]
    fn refund_eligible_before_deadline_returns_false() {
        let env = make_env();
        env.ledger().with_mut(|l| l.timestamp = 100);
        let contributor = Address::generate(&env);
        seed_contribution(&env, &contributor, 100);

        // deadline = 200, now = 100 → not yet expired
        assert!(!is_refund_eligible(&env, &contributor, 200, 50, 1_000));
    }

    #[test]
    fn refund_eligible_goal_met_returns_false() {
        let env = make_env();
        env.ledger().with_mut(|l| l.timestamp = 300);
        let contributor = Address::generate(&env);
        seed_contribution(&env, &contributor, 100);

        // deadline = 200, now = 300, total_raised >= goal
        assert!(!is_refund_eligible(&env, &contributor, 200, 1_000, 1_000));
    }

    #[test]
    fn refund_eligible_no_contribution_returns_false() {
        let env = make_env();
        env.ledger().with_mut(|l| l.timestamp = 300);
        let contributor = Address::generate(&env);
        // no seed → contribution = 0

        assert!(!is_refund_eligible(&env, &contributor, 200, 50, 1_000));
    }

    #[test]
    fn refund_eligible_all_conditions_met_returns_true() {
        let env = make_env();
        env.ledger().with_mut(|l| l.timestamp = 300);
        let contributor = Address::generate(&env);
        seed_contribution(&env, &contributor, 100);

        // deadline passed, goal not met, contribution > 0
        assert!(is_refund_eligible(&env, &contributor, 200, 50, 1_000));
    }

    #[test]
    fn refund_eligible_at_exact_deadline_returns_false() {
        let env = make_env();
        env.ledger().with_mut(|l| l.timestamp = 200);
        let contributor = Address::generate(&env);
        seed_contribution(&env, &contributor, 100);

        // timestamp == deadline → not yet expired (strict >)
        assert!(!is_refund_eligible(&env, &contributor, 200, 50, 1_000));
    }

    // ── find_first_above_threshold ────────────────────────────────────────────

    #[test]
    fn find_first_empty_vec_returns_none() {
        let env = make_env();
        let addresses: Vec<Address> = Vec::new(&env);
        assert!(find_first_above_threshold(&env, &addresses, 0).is_none());
    }

    #[test]
    fn find_first_no_match_returns_none() {
        let env = make_env();
        let a = Address::generate(&env);
        seed_contribution(&env, &a, 50);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);

        assert!(find_first_above_threshold(&env, &addresses, 100).is_none());
    }

    #[test]
    fn find_first_returns_first_match() {
        let env = make_env();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        seed_contribution(&env, &a, 50);
        seed_contribution(&env, &b, 200);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a.clone());
        addresses.push_back(b.clone());

        let result = find_first_above_threshold(&env, &addresses, 100);
        assert!(result.is_some());
        let (addr, amount) = result.unwrap();
        assert_eq!(addr, b);
        assert_eq!(amount, 200);
    }

    #[test]
    fn find_first_exact_threshold_not_matched() {
        // threshold is exclusive lower bound: amount must be *strictly* greater
        let env = make_env();
        let a = Address::generate(&env);
        seed_contribution(&env, &a, 100);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);

        assert!(find_first_above_threshold(&env, &addresses, 100).is_none());
    }

    #[test]
    #[should_panic(expected = "MAX_BATCH_SIZE")]
    fn find_first_panics_over_cap() {
        let env = make_env();
        let mut addresses: Vec<Address> = Vec::new(&env);
        for _ in 0..=MAX_BATCH_SIZE {
            addresses.push_back(Address::generate(&env));
        }
        find_first_above_threshold(&env, &addresses, 0);
    }

    // ── sum_contributions ─────────────────────────────────────────────────────

    #[test]
    fn sum_empty_vec_returns_zero() {
        let env = make_env();
        let addresses: Vec<Address> = Vec::new(&env);
        assert_eq!(sum_contributions(&env, &addresses), 0);
    }

    #[test]
    fn sum_single_contributor() {
        let env = make_env();
        let a = Address::generate(&env);
        seed_contribution(&env, &a, 300);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);

        assert_eq!(sum_contributions(&env, &addresses), 300);
    }

    #[test]
    fn sum_multiple_contributors() {
        let env = make_env();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let c = Address::generate(&env);
        seed_contribution(&env, &a, 100);
        seed_contribution(&env, &b, 200);
        seed_contribution(&env, &c, 300);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);
        addresses.push_back(b);
        addresses.push_back(c);

        assert_eq!(sum_contributions(&env, &addresses), 600);
    }

    #[test]
    fn sum_missing_entries_treated_as_zero() {
        let env = make_env();
        let present = Address::generate(&env);
        let absent = Address::generate(&env);
        seed_contribution(&env, &present, 400);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(present);
        addresses.push_back(absent);

        assert_eq!(sum_contributions(&env, &addresses), 400);
    }

    #[test]
    fn sum_saturates_instead_of_overflowing() {
        let env = make_env();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        seed_contribution(&env, &a, i128::MAX);
        seed_contribution(&env, &b, 1);

        let mut addresses: Vec<Address> = Vec::new(&env);
        addresses.push_back(a);
        addresses.push_back(b);

        // saturating_add should return i128::MAX, not panic
        assert_eq!(sum_contributions(&env, &addresses), i128::MAX);
    }

    #[test]
    #[should_panic(expected = "MAX_BATCH_SIZE")]
    fn sum_panics_over_cap() {
        let env = make_env();
        let mut addresses: Vec<Address> = Vec::new(&env);
        for _ in 0..=MAX_BATCH_SIZE {
            addresses.push_back(Address::generate(&env));
        }
        sum_contributions(&env, &addresses);
    }
}
