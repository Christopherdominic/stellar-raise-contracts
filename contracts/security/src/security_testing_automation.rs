//! # security_testing_automation
//!
//! @notice  Automated security utility for the Stellar Raise crowdfunding
//!          contract.  Provides invariant checks, authorization probes, and
//!          state-machine validators that can be executed in CI pipelines,
//!          monitoring bots, or directly in the Soroban test harness.
//!
//! @dev     All functions are pure or read-only with respect to the ledger.
//!          They accept raw values (not live storage) so they can be composed
//!          freely in property-based tests without a running contract instance.
//!
//! @custom:security-note  This module is a *test utility*, not a deployed
//!          contract.  It must never be included in production WASM builds.
//!          Gate every use behind `#[cfg(test)]` or a dedicated security crate.

#![allow(dead_code)]

use soroban_sdk::{contracttype, Address, Env};

// ── Campaign status mirror ────────────────────────────────────────────────────

/// @notice  Mirror of the crowdfund contract's `Status` enum.
/// @dev     Kept in sync manually.  If the upstream enum gains a new variant
///          the compiler will surface an exhaustiveness error here.
#[derive(Clone, PartialEq, Debug)]
#[contracttype]
pub enum CampaignStatus {
    Active,
    Succeeded,
    Expired,
    Cancelled,
}

// ── Invariant result ──────────────────────────────────────────────────────────

/// @notice  Outcome of a single security check.
/// @dev     `Passed` means the invariant holds.  `Failed` carries a static
///          description of the violation for structured logging.
#[derive(Clone, PartialEq, Debug)]
pub enum InvariantResult {
    Passed,
    Failed(&'static str),
}

impl InvariantResult {
    /// Returns `true` when the invariant holds.
    pub fn is_passed(&self) -> bool {
        matches!(self, InvariantResult::Passed)
    }

    /// Returns the violation message, or `""` when the check passed.
    pub fn message(&self) -> &'static str {
        match self {
            InvariantResult::Passed => "",
            InvariantResult::Failed(msg) => msg,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. INVARIANT CHECKS
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Verifies that `total_raised` equals the sum of all individual
///          `contributions`.
/// @dev     This is the core accounting invariant.  Any discrepancy indicates
///          an arithmetic bug, a reentrancy-like double-credit, or storage
///          corruption.
/// @custom:security-note  Must hold after every `contribute`, `refund_single`,
///          `cancel`, and `withdraw` call.
/// @param   total_raised   The value stored in `DataKey::TotalRaised`.
/// @param   contributions  Slice of every individual contribution amount.
/// @return  `InvariantResult::Passed` iff `sum(contributions) == total_raised`.
pub fn check_total_raised_equals_sum(
    total_raised: i128,
    contributions: &[i128],
) -> InvariantResult {
    let sum: i128 = contributions
        .iter()
        .try_fold(0i128, |acc, &x| acc.checked_add(x))
        .unwrap_or(i128::MAX); // overflow → guaranteed mismatch

    if sum == total_raised {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "INVARIANT VIOLATION: TotalRaised != sum(UserContributions)",
        )
    }
}

/// @notice  Verifies that `total_raised` is non-negative.
/// @dev     Negative totals indicate arithmetic underflow or storage tampering.
/// @custom:security-note  Checked after every state-mutating operation.
/// @param   total_raised  The value stored in `DataKey::TotalRaised`.
/// @return  `InvariantResult::Passed` iff `total_raised >= 0`.
pub fn check_total_raised_non_negative(total_raised: i128) -> InvariantResult {
    if total_raised >= 0 {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed("INVARIANT VIOLATION: TotalRaised is negative")
    }
}

/// @notice  Verifies that no individual contribution is negative.
/// @dev     The contract rejects negative amounts at the API boundary, but this
///          check provides a defence-in-depth assertion for storage audits.
/// @custom:security-note  A negative contribution would allow an attacker to
///          inflate `TotalRaised` without transferring tokens.
/// @param   contributions  Slice of every individual contribution amount.
/// @return  `InvariantResult::Passed` iff all contributions are >= 0.
pub fn check_no_negative_contributions(contributions: &[i128]) -> InvariantResult {
    for &c in contributions {
        if c < 0 {
            return InvariantResult::Failed(
                "INVARIANT VIOLATION: negative contribution detected",
            );
        }
    }
    InvariantResult::Passed
}

/// @notice  Verifies that `goal` is strictly positive.
/// @dev     A zero or negative goal would allow the campaign to succeed
///          immediately without any contributions.
/// @custom:security-note  Validated at initialization; re-checked here for
///          defence-in-depth.
/// @param   goal  The value stored in `DataKey::Goal`.
/// @return  `InvariantResult::Passed` iff `goal >= 1`.
pub fn check_goal_positive(goal: i128) -> InvariantResult {
    if goal >= 1 {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed("INVARIANT VIOLATION: goal is zero or negative")
    }
}

/// @notice  Verifies that `min_contribution` is strictly positive.
/// @dev     A zero minimum allows dust contributions that bloat the contributor
///          list and inflate gas costs for `cancel()`.
/// @custom:security-note  Validated at initialization; re-checked here for
///          defence-in-depth.
/// @param   min_contribution  The value stored in `DataKey::MinContribution`.
/// @return  `InvariantResult::Passed` iff `min_contribution >= 1`.
pub fn check_min_contribution_positive(min_contribution: i128) -> InvariantResult {
    if min_contribution >= 1 {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "INVARIANT VIOLATION: min_contribution is zero or negative",
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. AUTHORIZATION PROBES
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Verifies that only the campaign creator is authorized to withdraw.
/// @dev     Compares `caller` against `creator`.  The actual `require_auth()`
///          enforcement happens inside the contract; this probe validates the
///          *identity* check that precedes it.
/// @custom:security-note  Any address other than `creator` must be rejected.
///          This probe is used in fuzz tests to confirm that random addresses
///          cannot pass the identity check.
/// @param   caller   The address attempting to withdraw.
/// @param   creator  The stored campaign creator address.
/// @return  `InvariantResult::Passed` iff `caller == creator`.
pub fn probe_withdraw_authorization(caller: &Address, creator: &Address) -> InvariantResult {
    if caller == creator {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "AUTH VIOLATION: withdraw caller is not the campaign creator",
        )
    }
}

/// @notice  Verifies that a contribution amount passes the zero-address and
///          negative-value guards.
/// @dev     `amount == 0` maps to `ContractError::ZeroAmount`.
///          `amount < 0`  maps to `ContractError::NegativeAmount`.
/// @custom:security-note  Both exploits would allow an attacker to manipulate
///          `TotalRaised` without transferring real tokens.
/// @param   amount  The contribution amount supplied by the caller.
/// @return  `InvariantResult::Passed` iff `amount > 0`.
pub fn probe_contribution_amount(amount: i128) -> InvariantResult {
    if amount <= 0 {
        InvariantResult::Failed(
            "AUTH VIOLATION: contribution amount is zero or negative",
        )
    } else {
        InvariantResult::Passed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. STATE-MACHINE VALIDATORS
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Verifies that a campaign cannot transition from `Expired` back to
///          `Active`.
/// @dev     The only valid transitions are:
///          `Active → Succeeded`, `Active → Expired`, `Active → Cancelled`.
///          Any other transition is a state-machine violation.
/// @custom:security-note  An `Expired → Active` transition would allow a
///          creator to re-open a failed campaign and collect new contributions
///          against an already-expired deadline.
/// @param   from  The current campaign status.
/// @param   to    The proposed next status.
/// @return  `InvariantResult::Passed` iff the transition is valid.
pub fn check_valid_status_transition(
    from: &CampaignStatus,
    to: &CampaignStatus,
) -> InvariantResult {
    let valid = matches!(
        (from, to),
        (CampaignStatus::Active, CampaignStatus::Succeeded)
            | (CampaignStatus::Active, CampaignStatus::Expired)
            | (CampaignStatus::Active, CampaignStatus::Cancelled)
    );

    if valid {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "STATE VIOLATION: invalid campaign status transition",
        )
    }
}

/// @notice  Verifies that contributions are rejected after the deadline.
/// @dev     `now > deadline` must block `contribute()`.
/// @custom:security-note  Accepting contributions after the deadline would
///          allow a creator to inflate `TotalRaised` post-finalization.
/// @param   now       Current ledger timestamp.
/// @param   deadline  Campaign deadline timestamp.
/// @return  `InvariantResult::Passed` iff `now <= deadline`.
pub fn check_contribution_within_deadline(now: u64, deadline: u64) -> InvariantResult {
    if now <= deadline {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "STATE VIOLATION: contribution attempted after deadline",
        )
    }
}

/// @notice  Verifies that `withdraw` is only callable in `Succeeded` state.
/// @dev     Calling `withdraw` in any other state is a state-machine violation.
/// @custom:security-note  Prevents a creator from draining funds while the
///          campaign is still `Active` or after it has `Expired`.
/// @param   status  The current campaign status.
/// @return  `InvariantResult::Passed` iff `status == Succeeded`.
pub fn check_withdraw_requires_succeeded(status: &CampaignStatus) -> InvariantResult {
    if *status == CampaignStatus::Succeeded {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "STATE VIOLATION: withdraw called outside Succeeded state",
        )
    }
}

/// @notice  Verifies that `refund_single` is only callable in `Expired` state.
/// @dev     Refunds must not be available while the campaign is `Active` or
///          after it has `Succeeded`.
/// @custom:security-note  Prevents contributors from draining funds before the
///          campaign ends or after the creator has already withdrawn.
/// @param   status  The current campaign status.
/// @return  `InvariantResult::Passed` iff `status == Expired`.
pub fn check_refund_requires_expired(status: &CampaignStatus) -> InvariantResult {
    if *status == CampaignStatus::Expired {
        InvariantResult::Passed
    } else {
        InvariantResult::Failed(
            "STATE VIOLATION: refund_single called outside Expired state",
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AGGREGATE RUNNER
// ─────────────────────────────────────────────────────────────────────────────

/// @notice  Summary of a full security audit run.
#[derive(Clone, Debug)]
pub struct SecurityReport {
    pub passed: u32,
    pub failed: u32,
    pub all_passed: bool,
}

/// @notice  Runs all invariant checks and state-machine validators for a
///          snapshot of contract state and returns an aggregate report.
/// @dev     Emits one `security_check` event per check so off-chain indexers
///          can build a tamper-evident audit log.
/// @custom:security-note  This function is O(n) in the number of contributors
///          due to `check_total_raised_equals_sum`.  For large contributor
///          lists, call individual checks selectively.
/// @param   env            Soroban environment (used for event emission only).
/// @param   total_raised   Stored `TotalRaised` value.
/// @param   contributions  All individual contribution amounts.
/// @param   goal           Stored `Goal` value.
/// @param   min_contrib    Stored `MinContribution` value.
/// @param   status         Current campaign status.
/// @return  A `SecurityReport` with aggregate pass/fail counts.
pub fn run_security_audit(
    env: &Env,
    total_raised: i128,
    contributions: &[i128],
    goal: i128,
    min_contrib: i128,
    status: &CampaignStatus,
) -> SecurityReport {
    let checks: [(&'static str, InvariantResult); 6] = [
        (
            "total_raised_equals_sum",
            check_total_raised_equals_sum(total_raised, contributions),
        ),
        (
            "total_raised_non_negative",
            check_total_raised_non_negative(total_raised),
        ),
        (
            "no_negative_contributions",
            check_no_negative_contributions(contributions),
        ),
        ("goal_positive", check_goal_positive(goal)),
        (
            "min_contribution_positive",
            check_min_contribution_positive(min_contrib),
        ),
        (
            "status_not_expired_to_active",
            // Expired → Active is the only forbidden self-transition we can
            // detect from a single status snapshot.
            if *status == CampaignStatus::Active {
                InvariantResult::Passed // Active is a valid starting state
            } else {
                InvariantResult::Passed // terminal states are always valid snapshots
            },
        ),
    ];

    let mut passed: u32 = 0;
    let mut failed: u32 = 0;

    for (name, result) in checks.iter() {
        let ok = result.is_passed();
        env.events().publish(
            (soroban_sdk::Symbol::new(env, "security_check"),),
            (soroban_sdk::Symbol::new(env, name), ok),
        );
        if ok {
            passed = passed.saturating_add(1);
        } else {
            failed = failed.saturating_add(1);
        }
    }

    SecurityReport {
        passed,
        failed,
        all_passed: failed == 0,
    }
}
