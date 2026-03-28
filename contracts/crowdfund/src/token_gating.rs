//! # token_gating
//!
//! @title   TokenGating — Minimum token-balance access control for the crowdfund contract.
//!
//! @notice  Restricts `contribute()` to callers who hold at least a configured
//!          minimum balance of a designated gate token.  This enables:
//!          - Whitelist-style access (e.g. hold ≥ 1 governance token to participate).
//!          - Tiered contribution limits based on token holdings.
//!
//! ## Security Assumptions
//! 1. Only `DEFAULT_ADMIN_ROLE` may configure or remove the gate.
//! 2. Gate checks are read-only — no tokens are transferred or locked.
//! 3. When no gate is configured (`TokenGate` key absent) all callers pass.
//! 4. All configuration changes emit an event for off-chain monitoring.

#![allow(dead_code)]

use soroban_sdk::{token, Address, Env, Symbol};

use crate::{ContractError, DataKey};

// ── Storage key ───────────────────────────────────────────────────────────────

/// Extends [`DataKey`] — stored under a dedicated variant added below.
/// We reuse the existing `DataKey` enum via a parallel key type to avoid
/// modifying the shared enum in `lib.rs`.
#[derive(Clone)]
#[soroban_sdk::contracttype]
pub struct TokenGateConfig {
    /// The SEP-41 token contract whose balance is checked.
    pub gate_token: Address,
    /// Minimum balance the caller must hold to pass the gate.
    pub min_balance: i128,
}

// ── Storage helpers ───────────────────────────────────────────────────────────

/// Persist a new gate configuration.  Overwrites any existing gate.
fn set_gate(env: &Env, config: &TokenGateConfig) {
    env.storage()
        .instance()
        .set(&DataKey::TokenGate, config);
}

/// Remove the gate configuration entirely (open access).
fn remove_gate(env: &Env) {
    env.storage().instance().remove(&DataKey::TokenGate);
}

/// Read the current gate configuration, if any.
pub fn get_gate(env: &Env) -> Option<TokenGateConfig> {
    env.storage().instance().get(&DataKey::TokenGate)
}

// ── Admin API ─────────────────────────────────────────────────────────────────

/// @notice Configure (or replace) the token gate.
/// @dev    Only `DEFAULT_ADMIN_ROLE` may call this.
///
/// # Arguments
/// * `caller`      – Must be the stored `DefaultAdmin`.
/// * `gate_token`  – SEP-41 token contract address used for the balance check.
/// * `min_balance` – Minimum token balance required to contribute.
///
/// # Errors
/// * [`ContractError::InvalidMinContribution`] if `min_balance` is zero or negative.
///
/// # Security
/// - `caller.require_auth()` ensures the admin key signed the transaction.
/// - Emits `token_gate / configured` for off-chain monitoring.
pub fn configure_gate(
    env: &Env,
    caller: &Address,
    gate_token: Address,
    min_balance: i128,
) -> Result<(), ContractError> {
    caller.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::DefaultAdmin)
        .expect("DEFAULT_ADMIN_ROLE not set");

    if *caller != admin {
        panic!("only DEFAULT_ADMIN_ROLE can configure token gate");
    }

    if min_balance <= 0 {
        return Err(ContractError::InvalidMinContribution);
    }

    let config = TokenGateConfig {
        gate_token: gate_token.clone(),
        min_balance,
    };
    set_gate(env, &config);

    env.events().publish(
        (
            Symbol::new(env, "token_gate"),
            Symbol::new(env, "configured"),
        ),
        (caller.clone(), gate_token, min_balance),
    );

    Ok(())
}

/// @notice Remove the token gate — all callers may contribute again.
/// @dev    Only `DEFAULT_ADMIN_ROLE` may call this.
///
/// # Security
/// - `caller.require_auth()` ensures the admin key signed the transaction.
/// - Emits `token_gate / removed` for off-chain monitoring.
pub fn remove_gate_config(env: &Env, caller: &Address) {
    caller.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::DefaultAdmin)
        .expect("DEFAULT_ADMIN_ROLE not set");

    if *caller != admin {
        panic!("only DEFAULT_ADMIN_ROLE can remove token gate");
    }

    remove_gate(env);

    env.events().publish(
        (Symbol::new(env, "token_gate"), Symbol::new(env, "removed")),
        caller.clone(),
    );
}

// ── Gate check ────────────────────────────────────────────────────────────────

/// @notice Assert that `caller` holds enough of the gate token to contribute.
/// @dev    Call at the top of `contribute()` after `assert_not_paused`.
///         If no gate is configured this is a no-op.
///
/// # Errors
/// * Panics with `"insufficient token balance to contribute"` if the caller's
///   balance is below `min_balance`.
///
/// # Security
/// - Balance is read directly from the SEP-41 token contract — no trust in caller.
/// - Read-only: no tokens are moved or locked.
pub fn assert_gate_passes(env: &Env, caller: &Address) {
    let Some(config) = get_gate(env) else {
        return; // no gate configured — open access
    };

    let client = token::Client::new(env, &config.gate_token);
    let balance = client.balance(caller);

    if balance < config.min_balance {
        panic!("insufficient token balance to contribute");
    }
}
