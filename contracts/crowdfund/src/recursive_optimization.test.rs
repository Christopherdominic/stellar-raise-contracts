//! Tests for the `recursive_optimization` module.

use soroban_sdk::{testutils::Address as _, vec, Address, Env};

use crate::{
    recursive_optimization::{
        is_power_of_two, iterative_first_unmet_milestone, iterative_max_contribution,
        iterative_progress_bps, iterative_sum, MAX_ITER_DEPTH,
    },
    DataKey,
};

// ── iterative_sum ─────────────────────────────────────────────────────────────

#[test]
fn test_iterative_sum_empty_list() {
    let env = Env::default();
    let keys = vec![&env];
    assert_eq!(iterative_sum(&env, &keys), Some(0));
}

#[test]
fn test_iterative_sum_single_contributor() {
    let env = Env::default();
    let addr = Address::generate(&env);

    env.storage()
        .persistent()
        .set(&DataKey::Contribution(addr.clone()), &500i128);

    let keys = vec![&env, addr];
    assert_eq!(iterative_sum(&env, &keys), Some(500));
}

#[test]
fn test_iterative_sum_multiple_contributors() {
    let env = Env::default();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);

    env.storage().persistent().set(&DataKey::Contribution(a.clone()), &100i128);
    env.storage().persistent().set(&DataKey::Contribution(b.clone()), &200i128);
    env.storage().persistent().set(&DataKey::Contribution(c.clone()), &300i128);

    let keys = vec![&env, a, b, c];
    assert_eq!(iterative_sum(&env, &keys), Some(600));
}

#[test]
fn test_iterative_sum_missing_entry_treated_as_zero() {
    let env = Env::default();
    let addr = Address::generate(&env);
    // No storage entry set — should default to 0
    let keys = vec![&env, addr];
    assert_eq!(iterative_sum(&env, &keys), Some(0));
}

// ── iterative_first_unmet_milestone ──────────────────────────────────────────

#[test]
fn test_first_unmet_milestone_empty() {
    let env = Env::default();
    let milestones = vec![&env];
    assert_eq!(iterative_first_unmet_milestone(&milestones, 1000), None);
}

#[test]
fn test_first_unmet_milestone_all_met() {
    let env = Env::default();
    let milestones = vec![&env, 100i128, 200i128, 300i128];
    assert_eq!(iterative_first_unmet_milestone(&milestones, 300), None);
}

#[test]
fn test_first_unmet_milestone_first_unmet() {
    let env = Env::default();
    let milestones = vec![&env, 100i128, 200i128, 300i128];
    assert_eq!(iterative_first_unmet_milestone(&milestones, 50), Some(0));
}

#[test]
fn test_first_unmet_milestone_middle_unmet() {
    let env = Env::default();
    let milestones = vec![&env, 100i128, 200i128, 300i128];
    assert_eq!(iterative_first_unmet_milestone(&milestones, 150), Some(1));
}

#[test]
fn test_first_unmet_milestone_last_unmet() {
    let env = Env::default();
    let milestones = vec![&env, 100i128, 200i128, 300i128];
    assert_eq!(iterative_first_unmet_milestone(&milestones, 250), Some(2));
}

// ── iterative_progress_bps ────────────────────────────────────────────────────

#[test]
fn test_progress_bps_zero_raised() {
    assert_eq!(iterative_progress_bps(0, 1000), 0);
}

#[test]
fn test_progress_bps_zero_goal() {
    assert_eq!(iterative_progress_bps(500, 0), 0);
}

#[test]
fn test_progress_bps_half() {
    assert_eq!(iterative_progress_bps(500, 1000), 5_000);
}

#[test]
fn test_progress_bps_full() {
    assert_eq!(iterative_progress_bps(1000, 1000), 10_000);
}

#[test]
fn test_progress_bps_clamped_at_10000() {
    // raised > goal should clamp to 10_000
    assert_eq!(iterative_progress_bps(2000, 1000), 10_000);
}

#[test]
fn test_progress_bps_quarter() {
    assert_eq!(iterative_progress_bps(250, 1000), 2_500);
}

// ── is_power_of_two ───────────────────────────────────────────────────────────

#[test]
fn test_is_power_of_two_zero_is_false() {
    assert!(!is_power_of_two(0));
}

#[test]
fn test_is_power_of_two_one() {
    assert!(is_power_of_two(1));
}

#[test]
fn test_is_power_of_two_powers() {
    for exp in 1..=20u32 {
        assert!(is_power_of_two(1u64 << exp), "2^{exp} should be power of two");
    }
}

#[test]
fn test_is_power_of_two_non_powers() {
    for n in [3u64, 5, 6, 7, 9, 10, 12, 100, 1000] {
        assert!(!is_power_of_two(n), "{n} should not be power of two");
    }
}

// ── iterative_max_contribution ────────────────────────────────────────────────

#[test]
fn test_max_contribution_empty_list() {
    let env = Env::default();
    let keys = vec![&env];
    assert_eq!(iterative_max_contribution(&env, &keys), 0);
}

#[test]
fn test_max_contribution_single() {
    let env = Env::default();
    let addr = Address::generate(&env);
    env.storage().persistent().set(&DataKey::Contribution(addr.clone()), &750i128);
    let keys = vec![&env, addr];
    assert_eq!(iterative_max_contribution(&env, &keys), 750);
}

#[test]
fn test_max_contribution_multiple() {
    let env = Env::default();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);

    env.storage().persistent().set(&DataKey::Contribution(a.clone()), &100i128);
    env.storage().persistent().set(&DataKey::Contribution(b.clone()), &999i128);
    env.storage().persistent().set(&DataKey::Contribution(c.clone()), &500i128);

    let keys = vec![&env, a, b, c];
    assert_eq!(iterative_max_contribution(&env, &keys), 999);
}

// ── MAX_ITER_DEPTH boundary ───────────────────────────────────────────────────

#[test]
fn test_max_iter_depth_is_positive() {
    assert!(MAX_ITER_DEPTH > 0);
}
