//! # data_structure_optimization
//!
//! @title   DataStructureOptimization — Gas-efficient storage layout helpers
//!          for the crowdfund contract.
//!
//! @notice  Provides helpers that minimise ledger read/write costs by:
//!
//!          1. **Packing** four campaign scalars into one `PackedCampaignMeta`
//!             struct — one storage read instead of four.
//!          2. **Lazy writes** — contribution records are only written when
//!             non-zero; zero-amount keys are removed to reclaim ledger rent.
//!          3. **O(1) existence checks** — `contributor_exists` uses a single
//!             `has()` call instead of scanning the contributors vector.
//!          4. **Checked arithmetic** — all arithmetic uses `checked_*` to
//!             prevent silent overflow.
//!
//! @dev     All public functions are pure or storage-thin.  Mutating helpers
//!          are clearly marked; callers in `lib.rs` are responsible for auth
//!          and campaign-status checks before invoking them.
//!
//! ## Security Assumptions
//!
//! 1. **No auth required** — helpers are internal utilities; auth is enforced
//!    by callers.
//! 2. **Overflow-safe** — `checked_add` / `checked_sub` / `checked_mul` /
//!    `checked_div` are used throughout; callers receive `None` on overflow.
//! 3. **Bounded iteration** — `count_unique_contributors` iterates at most
//!    `MAX_CONTRIBUTORS` (128) entries.
//! 4. **Lazy writes** — `store_contribution(0)` removes the key, preventing
//!    stale zero-value entries from inflating storage costs.

#![allow(dead_code)]

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::{contract_state_size::MAX_CONTRIBUTORS, DataKey};

// ── Packed metadata struct ────────────────────────────────────────────────────

/// @notice Packs the four most-read campaign scalars into one storage slot.
///
/// @dev    One ledger-entry read fetches all four values instead of four
///         separate reads.  Write back with `store_packed_meta` after mutation.
///
/// @param goal              Campaign funding goal in token units.
/// @param deadline          Campaign deadline as a Unix timestamp (seconds).
/// @param min_contribution  Minimum single-contribution amount.
/// @param total_raised      Running total of tokens raised.
#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub struct PackedCampaignMeta {
    pub goal: i128,
    pub deadline: u64,
    pub min_contribution: i128,
    pub total_raised: i128,
}

// ── Packed-meta storage helpers ───────────────────────────────────────────────

/// Loads `PackedCampaignMeta` from instance storage, or returns `None`.
pub fn load_packed_meta(env: &Env) -> Option<PackedCampaignMeta> {
    env.storage().instance().get(&DataKey::PackedMeta)
}

/// Persists `PackedCampaignMeta` to instance storage.
///
/// @dev Callers must ensure all four fields are consistent before calling.
pub fn store_packed_meta(env: &Env, meta: &PackedCampaignMeta) {
    env.storage().instance().set(&DataKey::PackedMeta, meta);
}

// ── Contribution helpers ──────────────────────────────────────────────────────

/// @notice Returns the stored contribution for `contributor`, or `0` if absent.
pub fn load_contribution(env: &Env, contributor: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Contribution(contributor.clone()))
        .unwrap_or(0i128)
}

/// @notice Writes a contribution when `amount > 0`; removes the key when
///         `amount == 0` to reclaim ledger rent.
///
/// @custom:security `amount` must be validated by the caller.  This helper
///                  does not enforce `min_contribution` or campaign-status.
pub fn store_contribution(env: &Env, contributor: &Address, amount: i128) {
    let key = DataKey::Contribution(contributor.clone());
    if amount > 0 {
        env.storage().persistent().set(&key, &amount);
    } else {
        env.storage().persistent().remove(&key);
    }
}

/// @notice Returns `true` when a contribution record exists for `contributor`.
///
/// @dev    O(1) `has()` — avoids scanning the contributors vector.
pub fn contributor_exists(env: &Env, contributor: &Address) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Contribution(contributor.clone()))
}

// ── Arithmetic helpers ────────────────────────────────────────────────────────

/// @notice Adds `delta` to `base` with overflow protection.
/// @return `Some(result)` or `None` on overflow.
#[inline]
pub fn checked_add_i128(base: i128, delta: i128) -> Option<i128> {
    base.checked_add(delta)
}

/// @notice Subtracts `delta` from `base` with underflow protection.
/// @return `Some(result)` or `None` on underflow.
#[inline]
pub fn checked_sub_i128(base: i128, delta: i128) -> Option<i128> {
    base.checked_sub(delta)
}

/// @notice Computes `numerator * scale / denominator` safely.
///
/// @dev    Uses `i128` intermediate to avoid overflow.  Returns `None` when
///         `denominator <= 0`, `scale <= 0`, or the product overflows.
///
/// @param numerator   Value to express as a fraction of `denominator`.
/// @param denominator Reference total (must be > 0).
/// @param scale       Multiplier (e.g. 10_000 for basis points).
#[inline]
pub fn safe_fraction_bps(numerator: i128, denominator: i128, scale: i128) -> Option<i128> {
    if denominator <= 0 || scale <= 0 {
        return None;
    }
    numerator.checked_mul(scale)?.checked_div(denominator)
}

// ── Contributor count ─────────────────────────────────────────────────────────

/// @notice Returns the number of unique contributors, capped at `MAX_CONTRIBUTORS`.
///
/// @dev    Iterates the persistent contributors vector (≤ 128 entries).
///         Returns `0` when the key is absent.
pub fn count_unique_contributors(env: &Env) -> u32 {
    let list: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Contributors)
        .unwrap_or_else(|| Vec::new(env));
    list.len().min(MAX_CONTRIBUTORS)
}
