//! Comprehensive tests for `data_structure_optimization`.
//!
//! Coverage targets:
//! - `PackedCampaignMeta` round-trip (store + load).
//! - `load_packed_meta` returns `None` when absent.
//! - `load_contribution` returns `0` when absent, stored value when present.
//! - `store_contribution` writes when amount > 0, removes key when amount == 0.
//! - `contributor_exists` reflects storage state correctly.
//! - `checked_add_i128` / `checked_sub_i128` — normal, boundary, overflow cases.
//! - `safe_fraction_bps` — normal, zero denominator, zero scale, overflow guard.
//! - `count_unique_contributors` — empty, single, multiple, absent key.

#![cfg(test)]

use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};

use crate::{
    data_structure_optimization::{
        checked_add_i128, checked_sub_i128, contributor_exists, count_unique_contributors,
        load_contribution, load_packed_meta, safe_fraction_bps, store_contribution,
        store_packed_meta, PackedCampaignMeta,
    },
    DataKey,
};

// ── Minimal contract for storage access ──────────────────────────────────────

#[contract]
struct TestContract;

#[contractimpl]
impl TestContract {}

fn make_env() -> (Env, Address) {
    let env = Env::default();
    let id = env.register(TestContract, ());
    (env, id)
}

// ── PackedCampaignMeta round-trip ─────────────────────────────────────────────

#[test]
fn packed_meta_round_trip() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        let meta = PackedCampaignMeta {
            goal: 1_000,
            deadline: 9_999,
            min_contribution: 10,
            total_raised: 500,
        };
        store_packed_meta(&env, &meta);
        let loaded = load_packed_meta(&env).expect("should be present");
        assert_eq!(loaded, meta);
    });
}

#[test]
fn load_packed_meta_returns_none_when_absent() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        assert!(load_packed_meta(&env).is_none());
    });
}

#[test]
fn store_packed_meta_overwrites_previous_value() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        let first = PackedCampaignMeta { goal: 100, deadline: 1, min_contribution: 1, total_raised: 0 };
        let second = PackedCampaignMeta { goal: 200, deadline: 2, min_contribution: 5, total_raised: 50 };
        store_packed_meta(&env, &first);
        store_packed_meta(&env, &second);
        assert_eq!(load_packed_meta(&env).unwrap(), second);
    });
}

// ── load_contribution ─────────────────────────────────────────────────────────

#[test]
fn load_contribution_returns_zero_when_absent() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        assert_eq!(load_contribution(&env, &contributor), 0);
    });
}

#[test]
fn load_contribution_returns_stored_value() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        env.storage()
            .persistent()
            .set(&DataKey::Contribution(contributor.clone()), &250i128);
        assert_eq!(load_contribution(&env, &contributor), 250);
    });
}

// ── store_contribution ────────────────────────────────────────────────────────

#[test]
fn store_contribution_writes_positive_amount() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        store_contribution(&env, &contributor, 100);
        assert_eq!(load_contribution(&env, &contributor), 100);
    });
}

#[test]
fn store_contribution_removes_key_when_zero() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        store_contribution(&env, &contributor, 100);
        store_contribution(&env, &contributor, 0);
        assert!(!contributor_exists(&env, &contributor));
        assert_eq!(load_contribution(&env, &contributor), 0);
    });
}

#[test]
fn store_contribution_no_op_when_zero_and_absent() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        // Should not panic when removing a key that doesn't exist
        store_contribution(&env, &contributor, 0);
        assert!(!contributor_exists(&env, &contributor));
    });
}

#[test]
fn store_contribution_overwrites_previous_value() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        store_contribution(&env, &contributor, 50);
        store_contribution(&env, &contributor, 150);
        assert_eq!(load_contribution(&env, &contributor), 150);
    });
}

// ── contributor_exists ────────────────────────────────────────────────────────

#[test]
fn contributor_exists_false_when_absent() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        assert!(!contributor_exists(&env, &contributor));
    });
}

#[test]
fn contributor_exists_true_after_store() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        store_contribution(&env, &contributor, 1);
        assert!(contributor_exists(&env, &contributor));
    });
}

#[test]
fn contributor_exists_false_after_zero_store() {
    let (env, id) = make_env();
    let contributor = Address::generate(&env);
    env.as_contract(&id, || {
        store_contribution(&env, &contributor, 1);
        store_contribution(&env, &contributor, 0);
        assert!(!contributor_exists(&env, &contributor));
    });
}

// ── checked_add_i128 ──────────────────────────────────────────────────────────

#[test]
fn checked_add_normal() {
    assert_eq!(checked_add_i128(100, 50), Some(150));
}

#[test]
fn checked_add_zero() {
    assert_eq!(checked_add_i128(0, 0), Some(0));
}

#[test]
fn checked_add_overflow_returns_none() {
    assert_eq!(checked_add_i128(i128::MAX, 1), None);
}

#[test]
fn checked_add_negative_delta() {
    assert_eq!(checked_add_i128(100, -30), Some(70));
}

// ── checked_sub_i128 ──────────────────────────────────────────────────────────

#[test]
fn checked_sub_normal() {
    assert_eq!(checked_sub_i128(100, 40), Some(60));
}

#[test]
fn checked_sub_to_zero() {
    assert_eq!(checked_sub_i128(50, 50), Some(0));
}

#[test]
fn checked_sub_underflow_returns_none() {
    assert_eq!(checked_sub_i128(i128::MIN, 1), None);
}

// ── safe_fraction_bps ─────────────────────────────────────────────────────────

#[test]
fn safe_fraction_bps_normal() {
    // 500 / 1000 * 10_000 = 5_000 bps (50 %)
    assert_eq!(safe_fraction_bps(500, 1_000, 10_000), Some(5_000));
}

#[test]
fn safe_fraction_bps_full() {
    assert_eq!(safe_fraction_bps(1_000, 1_000, 10_000), Some(10_000));
}

#[test]
fn safe_fraction_bps_zero_numerator() {
    assert_eq!(safe_fraction_bps(0, 1_000, 10_000), Some(0));
}

#[test]
fn safe_fraction_bps_zero_denominator_returns_none() {
    assert_eq!(safe_fraction_bps(500, 0, 10_000), None);
}

#[test]
fn safe_fraction_bps_negative_denominator_returns_none() {
    assert_eq!(safe_fraction_bps(500, -1, 10_000), None);
}

#[test]
fn safe_fraction_bps_zero_scale_returns_none() {
    assert_eq!(safe_fraction_bps(500, 1_000, 0), None);
}

#[test]
fn safe_fraction_bps_overflow_returns_none() {
    // numerator * scale overflows i128
    assert_eq!(safe_fraction_bps(i128::MAX, 1, i128::MAX), None);
}

// ── count_unique_contributors ─────────────────────────────────────────────────

#[test]
fn count_unique_contributors_zero_when_absent() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        assert_eq!(count_unique_contributors(&env), 0);
    });
}

#[test]
fn count_unique_contributors_reflects_stored_list() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        let mut list = soroban_sdk::Vec::new(&env);
        list.push_back(Address::generate(&env));
        list.push_back(Address::generate(&env));
        env.storage().persistent().set(&DataKey::Contributors, &list);
        assert_eq!(count_unique_contributors(&env), 2);
    });
}

#[test]
fn count_unique_contributors_single_entry() {
    let (env, id) = make_env();
    env.as_contract(&id, || {
        let mut list = soroban_sdk::Vec::new(&env);
        list.push_back(Address::generate(&env));
        env.storage().persistent().set(&DataKey::Contributors, &list);
        assert_eq!(count_unique_contributors(&env), 1);
    });
}
