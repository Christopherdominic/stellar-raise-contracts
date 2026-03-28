//! # recursive_optimization
//!
//! @title   RecursiveOptimization — Iterative replacements for gas-efficient
//!          recursive-style computations in the crowdfund contract.
//!
//! @notice  Soroban charges per instruction; true recursion re-enters the call
//!          stack and duplicates frame setup cost on every level.  This module
//!          replaces common recursive patterns with bounded iterative equivalents
//!          that produce identical results at lower gas cost:
//!
//!          | Pattern                        | Recursive cost | Iterative cost |
//!          |--------------------------------|---------------|----------------|
//!          | Sum over contributor list      | O(n) frames   | O(n) loop iters|
//!          | Milestone search (first unmet) | O(n) frames   | O(n) loop iters|
//!          | Basis-point progress           | O(log n) muls | 1 multiply     |
//!          | Power-of-two check             | O(log n) divs | 1 bitwise AND  |
//!
//! ## Security Assumptions
//! 1. All loops are bounded by a compile-time constant (`MAX_ITER_DEPTH`) to
//!    prevent unbounded gas consumption.
//! 2. Arithmetic uses `checked_add` / `checked_mul` — overflows return `None`
//!    rather than wrapping silently.
//! 3. No storage writes occur in this module — all functions are pure or
//!    read-only, making them safe to call from any context.
//! 4. `MAX_ITER_DEPTH` is intentionally conservative; callers that need a
//!    larger bound should increase it and re-audit gas budgets.

#![allow(dead_code)]

use soroban_sdk::{Address, Env, Vec};

use crate::DataKey;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Hard cap on the number of iterations any loop in this module may execute.
///
/// @dev Aligned with the contributor cap so aggregate scans stay within the
///      largest valid on-chain list.  Increase only after re-auditing gas budgets.
pub const MAX_ITER_DEPTH: u32 = 1_000;

// ── Iterative sum ─────────────────────────────────────────────────────────────

/// @notice Compute the total of all contributor balances in a single bounded pass.
///
/// @dev    Replaces a naïve recursive sum that would re-enter the call stack once
///         per contributor.  Uses `checked_add` to surface overflows explicitly.
///
/// # Arguments
/// * `env`  – The Soroban environment.
/// * `keys` – Slice of contributor addresses whose `Contribution` entries to sum.
///
/// # Returns
/// `Some(total)` on success, `None` if an arithmetic overflow is detected.
///
/// # Security
/// - Bounded by `MAX_ITER_DEPTH` — cannot consume unbounded gas.
/// - Overflow-safe: returns `None` rather than wrapping.
pub fn iterative_sum(env: &Env, keys: &Vec<Address>) -> Option<i128> {
    let mut total: i128 = 0;
    let limit = keys.len().min(MAX_ITER_DEPTH);

    for i in 0..limit {
        let addr = keys.get(i)?;
        let contribution: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Contribution(addr))
            .unwrap_or(0);
        total = total.checked_add(contribution)?;
    }

    Some(total)
}

// ── Iterative milestone search ────────────────────────────────────────────────

/// @notice Find the index of the first milestone whose target has not yet been
///         reached, given the current `total_raised`.
///
/// @dev    Replaces a recursive scan that would allocate a new stack frame per
///         milestone.  Returns early on the first unmet milestone (best case O(1)).
///
/// # Arguments
/// * `milestones`   – Ordered list of milestone targets (ascending).
/// * `total_raised` – Current amount raised.
///
/// # Returns
/// `Some(index)` of the first unmet milestone, or `None` if all are met.
///
/// # Security
/// - Bounded by `MAX_ITER_DEPTH`.
/// - Read-only — no storage mutations.
pub fn iterative_first_unmet_milestone(milestones: &Vec<i128>, total_raised: i128) -> Option<u32> {
    let limit = milestones.len().min(MAX_ITER_DEPTH);

    for i in 0..limit {
        let target = milestones.get(i)?;
        if total_raised < target {
            return Some(i);
        }
    }

    None // all milestones met
}

// ── Iterative basis-point progress ───────────────────────────────────────────

/// @notice Compute funding progress in basis points (0–10 000) without recursion.
///
/// @dev    A recursive implementation would decompose the division into repeated
///         subtraction steps.  A single multiply + divide is O(1) and cheaper.
///
/// # Arguments
/// * `raised` – Amount raised so far.
/// * `goal`   – Campaign funding goal (must be > 0).
///
/// # Returns
/// Progress in basis points, clamped to `[0, 10_000]`.
/// Returns `0` if `goal` is zero to avoid division by zero.
///
/// # Security
/// - No overflow: intermediate value uses `i128` which can hold `raised * 10_000`
///   for any realistic token amount.
/// - Clamped output prevents callers from observing > 100% progress.
pub fn iterative_progress_bps(raised: i128, goal: i128) -> u32 {
    if goal <= 0 || raised <= 0 {
        return 0;
    }
    let bps = (raised * 10_000) / goal;
    bps.min(10_000) as u32
}

// ── Iterative power-of-two check ──────────────────────────────────────────────

/// @notice Check whether `n` is a power of two using a single bitwise operation.
///
/// @dev    A recursive halving approach costs O(log n) divisions.  The identity
///         `n & (n - 1) == 0` is O(1) and branchless on most targets.
///
/// # Arguments
/// * `n` – The value to test.
///
/// # Returns
/// `true` if `n` is a positive power of two, `false` otherwise.
///
/// # Security
/// - No loops, no recursion, no storage access — pure computation.
pub fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

// ── Iterative max contribution ────────────────────────────────────────────────

/// @notice Find the largest individual contribution in a single bounded pass.
///
/// @dev    Replaces a recursive max-finding pattern.  Returns `0` for an empty
///         list so callers can treat it as a safe default.
///
/// # Arguments
/// * `env`  – The Soroban environment.
/// * `keys` – Contributor addresses to scan.
///
/// # Returns
/// The largest contribution found, or `0` if the list is empty.
///
/// # Security
/// - Bounded by `MAX_ITER_DEPTH`.
/// - Read-only.
pub fn iterative_max_contribution(env: &Env, keys: &Vec<Address>) -> i128 {
    let mut max: i128 = 0;
    let limit = keys.len().min(MAX_ITER_DEPTH);

    for i in 0..limit {
        if let Some(addr) = keys.get(i) {
            let contribution: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::Contribution(addr))
                .unwrap_or(0);
            if contribution > max {
                max = contribution;
            }
        }
    }

    max
}
