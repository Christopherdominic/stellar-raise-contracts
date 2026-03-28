//! # nft_gating
//!
//! @title   NftGating — NFT ownership access control for the crowdfund contract.
//!
//! @notice  Restricts `contribute()` to callers who own at least one NFT from
//!          a configured NFT collection contract.  This enables:
//!          - Exclusive campaign access for NFT holders (e.g. DAO membership NFTs).
//!          - Collection-gated crowdfunding rounds.
//!
//! ## Security Assumptions
//! 1. Only `DEFAULT_ADMIN_ROLE` may configure or remove the gate.
//! 2. Gate checks are read-only — no NFTs are transferred or locked.
//! 3. When no gate is configured (`NftGate` key absent) all callers pass.
//! 4. All configuration changes emit an event for off-chain monitoring.
//! 5. Balance is read directly from the NFT contract — the caller cannot spoof it.

#![allow(dead_code)]

use soroban_sdk::{contractclient, Address, Env, Symbol};

use crate::{ContractError, DataKey};

// ── NFT contract client ───────────────────────────────────────────────────────

/// Minimal interface for an external NFT contract.
/// Only `balance` is required for the gate check.
#[contractclient(name = "NftGateContractClient")]
pub trait NftGateContract {
    /// Returns the number of NFTs owned by `owner` in this collection.
    fn balance(env: Env, owner: Address) -> i128;
}

// ── Gate config ───────────────────────────────────────────────────────────────

/// Configuration stored under `DataKey::NftGate`.
#[derive(Clone)]
#[soroban_sdk::contracttype]
pub struct NftGateConfig {
    /// The NFT collection contract address.
    pub nft_contract: Address,
    /// Minimum number of NFTs the caller must own to pass the gate.
    pub min_balance: i128,
}

// ── Storage helpers ───────────────────────────────────────────────────────────

fn set_gate(env: &Env, config: &NftGateConfig) {
    env.storage().instance().set(&DataKey::NftGate, config);
}

fn remove_gate(env: &Env) {
    env.storage().instance().remove(&DataKey::NftGate);
}

/// Read the current NFT gate configuration, if any.
pub fn get_gate(env: &Env) -> Option<NftGateConfig> {
    env.storage().instance().get(&DataKey::NftGate)
}

// ── Admin API ─────────────────────────────────────────────────────────────────

/// @notice Configure (or replace) the NFT gate.
/// @dev    Only `DEFAULT_ADMIN_ROLE` may call this.
///
/// # Arguments
/// * `caller`       – Must be the stored `DefaultAdmin`.
/// * `nft_contract` – NFT collection contract address used for the balance check.
/// * `min_balance`  – Minimum NFT balance required to contribute (>= 1).
///
/// # Errors
/// * [`ContractError::InvalidMinContribution`] if `min_balance` is zero or negative.
///
/// # Security
/// - `caller.require_auth()` ensures the admin key signed the transaction.
/// - Emits `nft_gate / configured` for off-chain monitoring.
pub fn configure_gate(
    env: &Env,
    caller: &Address,
    nft_contract: Address,
    min_balance: i128,
) -> Result<(), ContractError> {
    caller.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::DefaultAdmin)
        .expect("DEFAULT_ADMIN_ROLE not set");

    if *caller != admin {
        panic!("only DEFAULT_ADMIN_ROLE can configure NFT gate");
    }

    if min_balance <= 0 {
        return Err(ContractError::InvalidMinContribution);
    }

    let config = NftGateConfig {
        nft_contract: nft_contract.clone(),
        min_balance,
    };
    set_gate(env, &config);

    env.events().publish(
        (Symbol::new(env, "nft_gate"), Symbol::new(env, "configured")),
        (caller.clone(), nft_contract, min_balance),
    );

    Ok(())
}

/// @notice Remove the NFT gate — all callers may contribute again.
/// @dev    Only `DEFAULT_ADMIN_ROLE` may call this.
///
/// # Security
/// - `caller.require_auth()` ensures the admin key signed the transaction.
/// - Emits `nft_gate / removed` for off-chain monitoring.
pub fn remove_gate_config(env: &Env, caller: &Address) {
    caller.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::DefaultAdmin)
        .expect("DEFAULT_ADMIN_ROLE not set");

    if *caller != admin {
        panic!("only DEFAULT_ADMIN_ROLE can remove NFT gate");
    }

    remove_gate(env);

    env.events().publish(
        (Symbol::new(env, "nft_gate"), Symbol::new(env, "removed")),
        caller.clone(),
    );
}

// ── Gate check ────────────────────────────────────────────────────────────────

/// @notice Assert that `caller` owns enough NFTs to contribute.
/// @dev    Call at the top of `contribute()` after `assert_not_paused`.
///         If no gate is configured this is a no-op.
///
/// # Panics
/// Panics with `"insufficient NFT balance to contribute"` if the caller's
/// NFT balance is below `min_balance`.
///
/// # Security
/// - Balance is read directly from the NFT contract — no trust in caller.
/// - Read-only: no NFTs are moved or locked.
pub fn assert_gate_passes(env: &Env, caller: &Address) {
    let Some(config) = get_gate(env) else {
        return; // no gate configured — open access
    };

    let client = NftGateContractClient::new(env, &config.nft_contract);
    let balance = client.balance(caller);

    if balance < config.min_balance {
        panic!("insufficient NFT balance to contribute");
    }
}
