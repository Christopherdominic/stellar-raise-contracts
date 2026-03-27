//! # Proptest Generator Boundary Conditions
//!
//! Single source of truth for all boundary constants and validation helpers
//! used by the crowdfunding platform's property-based tests and frontend UI.
//!
//! ## New Edge Cases (Issue #423)
//!
//! - `is_ui_displayable_progress`: rejects bps values that would render as
//!   broken progress bars (NaN-equivalent: goal == 0, or bps > cap).
//! - `compute_display_percent`: converts bps → clamped 0–100 f32-equivalent
//!   integer (×100) for frontend percentage labels.
//! - `is_contribution_ui_safe`: validates that an amount is both above the
//!   minimum AND representable without overflow in the UI token-decimal layer.
//! - `deadline_ui_state`: classifies a deadline offset into the three UI
//!   states the frontend renders (Upcoming / Active / Expired).
//! - `compute_net_payout`: derives creator net payout after fee deduction,
//!   guarded against underflow and fee > total edge cases.
//!
//! ## Security Model
//!
//! - Overflow: `saturating_mul` / `checked_sub` throughout.
//! - Division by zero: explicit `goal <= 0` guard before every division.
//! - Basis-point cap: progress and fee capped at 10 000 (100 %).
//! - Timestamp: deadline offsets bounded to `[DEADLINE_OFFSET_MIN, DEADLINE_OFFSET_MAX]`.
//! - Resource bounds: batch sizes and case counts clamped to prevent CI spikes.

use soroban_sdk::{contract, contractimpl, Env, Symbol};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum deadline offset in seconds (~17 minutes).
/// @dev Prevents flaky tests due to timing races.
pub const DEADLINE_OFFSET_MIN: u64 = 1_000;

/// Maximum deadline offset in seconds (~11.5 days).
/// @dev Avoids u64 overflow when added to ledger timestamps.
pub const DEADLINE_OFFSET_MAX: u64 = 1_000_000;

/// Minimum valid goal amount (stroops).
/// @dev Prevents division-by-zero in progress calculations.
pub const GOAL_MIN: i128 = 1_000;

/// Maximum goal amount for test generation.
/// @dev Keeps tests fast while covering large campaign scenarios.
pub const GOAL_MAX: i128 = 100_000_000;

/// Absolute floor for contribution amounts.
/// @dev Prevents zero-value contributions from polluting ledger state.
pub const MIN_CONTRIBUTION_FLOOR: i128 = 1;

/// Maximum progress in basis points (100 %).
/// @dev Frontend never displays >100 % funded.
pub const PROGRESS_BPS_CAP: u32 = 10_000;

/// Maximum fee in basis points (100 %).
/// @dev Fee above this would exceed 100 % of the contribution.
pub const FEE_BPS_CAP: u32 = 10_000;

/// Minimum proptest case count.
pub const PROPTEST_CASES_MIN: u32 = 32;

/// Maximum proptest case count.
pub const PROPTEST_CASES_MAX: u32 = 256;

/// Maximum batch size for generator operations.
pub const GENERATOR_BATCH_MAX: u32 = 512;

/// Maximum token decimals supported by the frontend display layer.
/// @dev XLM = 7, USDC = 6. Values above this overflow JS Number precision.
pub const MAX_TOKEN_DECIMALS: u32 = 18;

/// Deadline offset threshold (seconds) below which the UI shows "Ending Soon".
/// @dev ~1 hour — triggers the amber countdown banner in the frontend.
pub const DEADLINE_ENDING_SOON_THRESHOLD: u64 = 3_600;

// ── UI State Enum ─────────────────────────────────────────────────────────────

/// Frontend deadline display state.
///
/// @notice Maps a remaining-seconds value to the three visual states
///         rendered by the campaign card component.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DeadlineUiState {
    /// Deadline is more than `DEADLINE_ENDING_SOON_THRESHOLD` seconds away.
    Active,
    /// Deadline is within `DEADLINE_ENDING_SOON_THRESHOLD` seconds (amber banner).
    EndingSoon,
    /// Deadline has passed (seconds_remaining == 0).
    Expired,
}

// ── Pure Validation Helpers ───────────────────────────────────────────────────

/// Returns `true` if `offset ∈ [DEADLINE_OFFSET_MIN, DEADLINE_OFFSET_MAX]`.
///
/// @security Rejects values < 1 000 that cause timing races and values that
///           could overflow a `u64` timestamp when added to `now`.
#[inline]
pub fn is_valid_deadline_offset(offset: u64) -> bool {
    (DEADLINE_OFFSET_MIN..=DEADLINE_OFFSET_MAX).contains(&offset)
}

/// Returns `true` if `goal ∈ [GOAL_MIN, GOAL_MAX]`.
///
/// @security Rejects `goal <= 0` which causes division-by-zero in
///           `compute_progress_bps` and breaks the frontend progress bar.
#[inline]
pub fn is_valid_goal(goal: i128) -> bool {
    (GOAL_MIN..=GOAL_MAX).contains(&goal)
}

/// Returns `true` if `MIN_CONTRIBUTION_FLOOR <= min_contribution <= goal`.
///
/// @security Ensures `min_contribution` never exceeds `goal`, which would
///           make the campaign permanently un-fundable.
#[inline]
pub fn is_valid_min_contribution(min_contribution: i128, goal: i128) -> bool {
    min_contribution >= MIN_CONTRIBUTION_FLOOR && min_contribution <= goal
}

/// Returns `true` if `amount >= min_contribution`.
#[inline]
pub fn is_valid_contribution_amount(amount: i128, min_contribution: i128) -> bool {
    amount >= min_contribution
}

/// Clamps a raw basis-point value into `[0, PROGRESS_BPS_CAP]`.
///
/// @notice Negative inputs floor to 0; over-funded campaigns cap at 100 %.
#[inline]
pub fn clamp_progress_bps(raw: i128) -> u32 {
    if raw <= 0 {
        0
    } else if raw >= PROGRESS_BPS_CAP as i128 {
        PROGRESS_BPS_CAP
    } else {
        raw as u32
    }
}

/// Computes campaign progress in basis points from `raised` and `goal`.
///
/// @security Uses `saturating_mul` to prevent overflow on large `raised`
///           values before dividing by `goal`. Returns 0 when `goal <= 0`.
#[inline]
pub fn compute_progress_bps(raised: i128, goal: i128) -> u32 {
    if goal <= 0 {
        return 0;
    }
    let raw = raised.saturating_mul(10_000) / goal;
    clamp_progress_bps(raw)
}

/// Clamps a requested proptest case count into `[PROPTEST_CASES_MIN, PROPTEST_CASES_MAX]`.
#[inline]
pub fn clamp_proptest_cases(requested: u32) -> u32 {
    requested.clamp(PROPTEST_CASES_MIN, PROPTEST_CASES_MAX)
}

// ── New Edge-Case Helpers (Issue #423) ────────────────────────────────────────

/// Returns `true` if `bps` is safe to render in the frontend progress bar.
///
/// @notice A value is UI-displayable when it is in `[0, PROGRESS_BPS_CAP]`.
///         Values outside this range would produce broken or misleading bars.
///
/// @param bps  Raw basis-point value coming from `compute_progress_bps`.
/// @return `true` when the value can be safely rendered.
///
/// @security Rejects negative-equivalent (impossible after clamping, but
///           guards against direct calls with unclamped values) and values
///           above the cap that would overflow a CSS `width` percentage.
#[inline]
pub fn is_ui_displayable_progress(bps: u32) -> bool {
    bps <= PROGRESS_BPS_CAP
}

/// Converts basis points to a display percentage scaled by 100 (i.e. 0–10 000).
///
/// @notice Returns an integer representing `bps / 100` × 100 so callers can
///         format "50.00 %" without floating-point arithmetic on-chain.
///         The value is clamped to `[0, 10_000]` before conversion.
///
/// @param bps  Basis-point progress value (will be clamped internally).
/// @return     Integer in `[0, 10_000]` — divide by 100 for the percentage.
///
/// @dev  Example: `bps = 5_000` → returns `5_000` → frontend renders "50.00 %".
///       `bps = 10_001` → clamped to `10_000` → "100.00 %".
#[inline]
pub fn compute_display_percent(bps: u32) -> u32 {
    bps.min(PROGRESS_BPS_CAP)
}

/// Returns `true` if `amount` is safe for both contract validation and the
/// frontend token-decimal display layer.
///
/// @notice Combines the minimum-contribution check with an overflow guard:
///         `amount * 10^decimals` must not exceed `i128::MAX` to be safely
///         formatted by the frontend without precision loss.
///
/// @param amount           Contribution amount in the token's smallest unit.
/// @param min_contribution Campaign minimum contribution floor.
/// @param token_decimals   Decimal precision of the token (e.g. 7 for XLM).
/// @return `true` when the amount is valid and UI-safe.
///
/// @security Rejects `token_decimals > MAX_TOKEN_DECIMALS` to prevent
///           JavaScript Number precision loss in the frontend display layer.
#[inline]
pub fn is_contribution_ui_safe(amount: i128, min_contribution: i128, token_decimals: u32) -> bool {
    if token_decimals > MAX_TOKEN_DECIMALS {
        return false;
    }
    if amount < min_contribution {
        return false;
    }
    // Guard: amount * 10^decimals must not overflow i128
    let scale: i128 = 10i128.pow(token_decimals);
    amount.checked_mul(scale).is_some()
}

/// Classifies a `seconds_remaining` value into the frontend deadline UI state.
///
/// @notice Maps remaining seconds to one of three visual states:
///         - `Expired`    — deadline has passed (`seconds_remaining == 0`).
///         - `EndingSoon` — within `DEADLINE_ENDING_SOON_THRESHOLD` seconds.
///         - `Active`     — more than the threshold away.
///
/// @param seconds_remaining  Seconds until the campaign deadline (0 = expired).
/// @return The `DeadlineUiState` variant for the frontend to render.
///
/// @security Treats `seconds_remaining == 0` as expired regardless of clock
///           skew, preventing the UI from showing an active campaign after
///           the on-chain deadline has passed.
#[inline]
pub fn deadline_ui_state(seconds_remaining: u64) -> DeadlineUiState {
    if seconds_remaining == 0 {
        DeadlineUiState::Expired
    } else if seconds_remaining <= DEADLINE_ENDING_SOON_THRESHOLD {
        DeadlineUiState::EndingSoon
    } else {
        DeadlineUiState::Active
    }
}

/// Computes the creator's net payout after platform fee deduction.
///
/// @notice Returns `None` when `fee_bps > FEE_BPS_CAP` (invalid fee) or
///         when arithmetic would underflow (fee > total).
///
/// @param total    Total tokens raised.
/// @param fee_bps  Platform fee in basis points.
/// @return `Some(net)` on success, `None` on invalid inputs.
///
/// @security Uses `checked_mul` and `checked_sub` to prevent overflow and
///           underflow. Rejects `fee_bps > FEE_BPS_CAP` before any arithmetic.
#[inline]
pub fn compute_net_payout(total: i128, fee_bps: u32) -> Option<i128> {
    if fee_bps > FEE_BPS_CAP {
        return None;
    }
    if total <= 0 {
        return Some(0);
    }
    let fee = total.checked_mul(fee_bps as i128)? / 10_000;
    total.checked_sub(fee)
}

// ── On-Chain Contract ─────────────────────────────────────────────────────────

/// On-chain contract that exposes boundary constants and validation logic so
/// off-chain scripts and other contracts can query current platform limits.
///
/// @notice All methods are pure (read-only) and do not modify contract state.
#[contract]
pub struct ProptestGeneratorBoundary;

#[contractimpl]
impl ProptestGeneratorBoundary {
    // ── Getters ───────────────────────────────────────────────────────────────

    pub fn deadline_offset_min(_env: Env) -> u64 { DEADLINE_OFFSET_MIN }
    pub fn deadline_offset_max(_env: Env) -> u64 { DEADLINE_OFFSET_MAX }
    pub fn goal_min(_env: Env) -> i128 { GOAL_MIN }
    pub fn goal_max(_env: Env) -> i128 { GOAL_MAX }
    pub fn min_contribution_floor(_env: Env) -> i128 { MIN_CONTRIBUTION_FLOOR }
    pub fn progress_bps_cap(_env: Env) -> u32 { PROGRESS_BPS_CAP }
    pub fn fee_bps_cap(_env: Env) -> u32 { FEE_BPS_CAP }
    pub fn proptest_cases_min(_env: Env) -> u32 { PROPTEST_CASES_MIN }
    pub fn proptest_cases_max(_env: Env) -> u32 { PROPTEST_CASES_MAX }
    pub fn generator_batch_max(_env: Env) -> u32 { GENERATOR_BATCH_MAX }
    pub fn max_token_decimals(_env: Env) -> u32 { MAX_TOKEN_DECIMALS }
    pub fn deadline_ending_soon_threshold(_env: Env) -> u64 { DEADLINE_ENDING_SOON_THRESHOLD }

    // ── Validation ────────────────────────────────────────────────────────────

    /// @notice Validates deadline offset is within [min, max].
    pub fn is_valid_deadline_offset(_env: Env, offset: u64) -> bool {
        is_valid_deadline_offset(offset)
    }

    /// @notice Validates goal is within [GOAL_MIN, GOAL_MAX].
    pub fn is_valid_goal(_env: Env, goal: i128) -> bool {
        is_valid_goal(goal)
    }

    /// @notice Validates min_contribution is in [MIN_CONTRIBUTION_FLOOR, goal].
    pub fn is_valid_min_contribution(_env: Env, min_contribution: i128, goal: i128) -> bool {
        is_valid_min_contribution(min_contribution, goal)
    }

    /// @notice Validates contribution amount meets the minimum.
    pub fn is_valid_contribution_amount(_env: Env, amount: i128, min_contribution: i128) -> bool {
        is_valid_contribution_amount(amount, min_contribution)
    }

    /// @notice Validates fee_bps <= FEE_BPS_CAP.
    pub fn is_valid_fee_bps(_env: Env, fee_bps: u32) -> bool {
        fee_bps <= FEE_BPS_CAP
    }

    /// @notice Validates batch_size is in (0, GENERATOR_BATCH_MAX].
    pub fn is_valid_generator_batch_size(_env: Env, batch_size: u32) -> bool {
        batch_size > 0 && batch_size <= GENERATOR_BATCH_MAX
    }

    // ── New Edge-Case Validators (Issue #423) ─────────────────────────────────

    /// @notice Returns true if bps is safe to render in the frontend progress bar.
    pub fn is_ui_displayable_progress(_env: Env, bps: u32) -> bool {
        is_ui_displayable_progress(bps)
    }

    /// @notice Returns true if amount is safe for contract validation and UI display.
    pub fn is_contribution_ui_safe(
        _env: Env,
        amount: i128,
        min_contribution: i128,
        token_decimals: u32,
    ) -> bool {
        is_contribution_ui_safe(amount, min_contribution, token_decimals)
    }

    // ── Clamping ──────────────────────────────────────────────────────────────

    /// @notice Clamps requested case count to [PROPTEST_CASES_MIN, PROPTEST_CASES_MAX].
    pub fn clamp_proptest_cases(_env: Env, requested: u32) -> u32 {
        clamp_proptest_cases(requested)
    }

    /// @notice Clamps raw progress bps to [0, PROGRESS_BPS_CAP].
    pub fn clamp_progress_bps(_env: Env, raw: i128) -> u32 {
        clamp_progress_bps(raw)
    }

    // ── Derived Calculations ──────────────────────────────────────────────────

    /// @notice Computes progress in basis points, capped at 10 000.
    /// @dev Uses saturating_mul; returns 0 when goal <= 0.
    pub fn compute_progress_bps(_env: Env, raised: i128, goal: i128) -> u32 {
        compute_progress_bps(raised, goal)
    }

    /// @notice Computes fee amount from contribution and fee_bps.
    /// @dev Returns 0 when amount <= 0 or fee_bps == 0.
    pub fn compute_fee_amount(_env: Env, amount: i128, fee_bps: u32) -> i128 {
        if amount <= 0 || fee_bps == 0 {
            return 0;
        }
        amount.saturating_mul(fee_bps as i128) / 10_000
    }

    /// @notice Converts basis points to a display percentage scaled by 100.
    pub fn compute_display_percent(_env: Env, bps: u32) -> u32 {
        compute_display_percent(bps)
    }

    /// @notice Computes creator net payout after fee; returns 0 on invalid inputs.
    pub fn compute_net_payout(_env: Env, total: i128, fee_bps: u32) -> i128 {
        compute_net_payout(total, fee_bps).unwrap_or(0)
    }

    /// @notice Returns a diagnostic tag for boundary log events.
    pub fn log_tag(_env: Env) -> Symbol {
        Symbol::new(&_env, "boundary")
    }
}
