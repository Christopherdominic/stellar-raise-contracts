//! Algorithm optimization helpers for gas-efficient contract operations.
//!
//! @title   AlgorithmOptimization
//! @notice  Provides gas-efficient alternatives to common on-chain patterns:
//!          batch contribution lookups, cached progress computation, and
//!          bounded refund eligibility checks.
//!
//! # Design principles
//!
//! 1. **Single-pass reads** — aggregate multiple storage reads into one loop
//!    instead of calling storage once per query.
//! 2. **Early exit** — short-circuit loops as soon as the answer is known.
//! 3. **Integer-only arithmetic** — no floating-point; all ratios use basis
//!    points (1 bps = 0.01 %) to stay within Soroban's deterministic integer
//!    model.
//! 4. **Bounded iteration** — every loop is capped at `MAX_BATCH_SIZE` to
//!    prevent unbounded gas consumption.
//!
//! # Security assumptions
//!
//! - All public functions are **read-only** (no state mutation).
//! - Arithmetic uses `checked_add` / `saturating_mul` to prevent overflow.
//! - Batch size is capped at compile time; callers cannot exceed the cap.

use soroban_sdk::{Address, Env, Vec};

use crate::DataKey;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of addresses processed in a single batch call.
///
/// Keeping this at 50 aligns with `MAX_NFT_MINT_BATCH` and stays well within
/// Soroban's per-transaction instruction budget.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Basis-point scale factor (10 000 bps = 100 %).
pub const BPS_SCALE: i128 = 10_000;

// ── Public helpers ───────────────────────────────────────────────────────────

/// Returns the total contribution for each address in `addresses` using a
/// single bounded storage scan.
///
/// @param env       The Soroban environment.
/// @param addresses Slice of contributor addresses to look up (max `MAX_BATCH_SIZE`).
/// @return          A `Vec<i128>` parallel to `addresses`; missing entries are `0`.
///
/// @custom:security Panics if `addresses.len() > MAX_BATCH_SIZE` to prevent
///                  unbounded gas consumption.
pub fn batch_contribution_lookup(env: &Env, addresses: &Vec<Address>) -> Vec<i128> {
    assert!(
        addresses.len() <= MAX_BATCH_SIZE,
        "algorithm_optimization: batch size exceeds MAX_BATCH_SIZE"
    );

    let mut results: Vec<i128> = Vec::new(env);
    for addr in addresses.iter() {
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Contribution(addr))
            .unwrap_or(0);
        results.push_back(amount);
    }
    results
}

/// Computes campaign progress in basis points without re-reading storage.
///
/// Equivalent to `(total_raised * 10_000) / goal`, clamped to `[0, 10_000]`.
///
/// @param total_raised Current total raised (must be >= 0).
/// @param goal         Campaign goal (must be > 0).
/// @return             Progress in bps, saturated at `10_000` (100 %).
///
/// @custom:security Uses `saturating_mul` to prevent overflow on large balances.
pub fn progress_bps(total_raised: i128, goal: i128) -> u32 {
    if total_raised <= 0 || goal <= 0 {
        return 0;
    }
    let raw = total_raised.saturating_mul(BPS_SCALE) / goal;
    raw.clamp(0, BPS_SCALE) as u32
}

/// Checks whether a contributor is eligible for a refund in O(1) time.
///
/// A refund is eligible when:
/// - The campaign deadline has passed (`now > deadline`).
/// - The goal was **not** met (`total_raised < goal`).
/// - The contributor has a non-zero contribution on record.
///
/// @param env         The Soroban environment.
/// @param contributor The address to check.
/// @param deadline    Campaign deadline (Unix timestamp).
/// @param total_raised Total tokens raised.
/// @param goal        Campaign funding goal.
/// @return            `true` if the contributor may call `refund_single`.
pub fn is_refund_eligible(
    env: &Env,
    contributor: &Address,
    deadline: u64,
    total_raised: i128,
    goal: i128,
) -> bool {
    if env.ledger().timestamp() <= deadline {
        return false;
    }
    if total_raised >= goal {
        return false;
    }
    let contribution: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::Contribution(contributor.clone()))
        .unwrap_or(0);
    contribution > 0
}

/// Finds the first contributor in `addresses` whose contribution exceeds
/// `threshold`, returning their address and amount.
///
/// Exits early on the first match, avoiding a full scan when only one result
/// is needed.
///
/// @param env       The Soroban environment.
/// @param addresses Contributor address stream (max `MAX_BATCH_SIZE`).
/// @param threshold Minimum contribution amount (exclusive lower bound).
/// @return          `Some((address, amount))` for the first match, or `None`.
///
/// @custom:security Panics if `addresses.len() > MAX_BATCH_SIZE`.
pub fn find_first_above_threshold(
    env: &Env,
    addresses: &Vec<Address>,
    threshold: i128,
) -> Option<(Address, i128)> {
    assert!(
        addresses.len() <= MAX_BATCH_SIZE,
        "algorithm_optimization: batch size exceeds MAX_BATCH_SIZE"
    );

    for addr in addresses.iter() {
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Contribution(addr.clone()))
            .unwrap_or(0);
        if amount > threshold {
            return Some((addr, amount));
        }
    }
    None
}

/// Sums contributions for a batch of addresses in one pass.
///
/// More gas-efficient than calling `contribution()` N times from off-chain
/// because it avoids N separate host-function round-trips.
///
/// @param env       The Soroban environment.
/// @param addresses Contributor addresses (max `MAX_BATCH_SIZE`).
/// @return          Sum of all contributions; saturates at `i128::MAX`.
///
/// @custom:security Uses `saturating_add` to prevent overflow.
/// @custom:security Panics if `addresses.len() > MAX_BATCH_SIZE`.
pub fn sum_contributions(env: &Env, addresses: &Vec<Address>) -> i128 {
    assert!(
        addresses.len() <= MAX_BATCH_SIZE,
        "algorithm_optimization: batch size exceeds MAX_BATCH_SIZE"
    );

    let mut total: i128 = 0;
    for addr in addresses.iter() {
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Contribution(addr))
            .unwrap_or(0);
        total = total.saturating_add(amount);
    }
    total
}
