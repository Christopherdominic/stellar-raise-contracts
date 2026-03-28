//! Tests for the `token_gating` module.

use soroban_sdk::{
    testutils::Address as _,
    token::StellarAssetClient,
    Address, Env,
};

use crate::{
    token_gating::{assert_gate_passes, configure_gate, get_gate, remove_gate_config},
    ContractError, DataKey,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal env with a token, an admin, and a contributor.
/// Returns (env, gate_token_addr, admin, contributor).
fn setup() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contributor = Address::generate(&env);

    // Register a Stellar asset contract as the gate token
    let token_id = env.register_stellar_asset_contract_v2(admin.clone());
    let gate_token = token_id.address();

    // Seed the contract's DefaultAdmin so configure_gate can read it
    env.as_contract(
        &env.register(crate::CrowdfundContract, ()),
        || {},
    );

    (env, gate_token, admin, contributor)
}

/// Registers a bare CrowdfundContract and seeds `DefaultAdmin` + a gate token balance.
/// Returns (env, contract_id, gate_token, admin, contributor).
fn setup_with_contract() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contributor = Address::generate(&env);

    let token_id = env.register_stellar_asset_contract_v2(admin.clone());
    let gate_token = token_id.address();

    let contract_id = env.register(crate::CrowdfundContract, ());

    // Seed DefaultAdmin directly into contract storage
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::DefaultAdmin, &admin);
    });

    (env, contract_id, gate_token, admin, contributor)
}

// ── configure_gate ────────────────────────────────────────────────────────────

#[test]
fn test_configure_gate_stores_config() {
    let (env, contract_id, gate_token, admin, _contributor) = setup_with_contract();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        let cfg = get_gate(&env).expect("gate should be set");
        assert_eq!(cfg.gate_token, gate_token);
        assert_eq!(cfg.min_balance, 100);
    });
}

#[test]
fn test_configure_gate_rejects_zero_min_balance() {
    let (env, contract_id, gate_token, admin, _) = setup_with_contract();

    env.as_contract(&contract_id, || {
        let result = configure_gate(&env, &admin, gate_token.clone(), 0);
        assert_eq!(result, Err(ContractError::InvalidMinContribution));
    });
}

#[test]
fn test_configure_gate_rejects_negative_min_balance() {
    let (env, contract_id, gate_token, admin, _) = setup_with_contract();

    env.as_contract(&contract_id, || {
        let result = configure_gate(&env, &admin, gate_token.clone(), -1);
        assert_eq!(result, Err(ContractError::InvalidMinContribution));
    });
}

#[test]
#[should_panic(expected = "only DEFAULT_ADMIN_ROLE can configure token gate")]
fn test_configure_gate_rejects_non_admin() {
    let (env, contract_id, gate_token, _admin, contributor) = setup_with_contract();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &contributor, gate_token.clone(), 100).unwrap();
    });
}

#[test]
fn test_configure_gate_overwrites_existing() {
    let (env, contract_id, gate_token, admin, _) = setup_with_contract();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        configure_gate(&env, &admin, gate_token.clone(), 500).unwrap();
        let cfg = get_gate(&env).unwrap();
        assert_eq!(cfg.min_balance, 500);
    });
}

// ── remove_gate_config ────────────────────────────────────────────────────────

#[test]
fn test_remove_gate_clears_config() {
    let (env, contract_id, gate_token, admin, _) = setup_with_contract();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        remove_gate_config(&env, &admin);
        assert!(get_gate(&env).is_none());
    });
}

#[test]
#[should_panic(expected = "only DEFAULT_ADMIN_ROLE can remove token gate")]
fn test_remove_gate_rejects_non_admin() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        remove_gate_config(&env, &contributor);
    });
}

// ── assert_gate_passes ────────────────────────────────────────────────────────

#[test]
fn test_no_gate_always_passes() {
    let (env, contract_id, _gate_token, _admin, contributor) = setup_with_contract();

    env.as_contract(&contract_id, || {
        // No gate configured — should not panic
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_when_balance_meets_minimum() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    // Mint exactly min_balance to contributor
    let asset_client = StellarAssetClient::new(&env, &gate_token);
    asset_client.mint(&contributor, &100);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        // Should not panic
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_when_balance_exceeds_minimum() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    let asset_client = StellarAssetClient::new(&env, &gate_token);
    asset_client.mint(&contributor, &999);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
#[should_panic(expected = "insufficient token balance to contribute")]
fn test_gate_fails_when_balance_below_minimum() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    // Mint less than min_balance
    let asset_client = StellarAssetClient::new(&env, &gate_token);
    asset_client.mint(&contributor, &50);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
#[should_panic(expected = "insufficient token balance to contribute")]
fn test_gate_fails_when_balance_is_zero() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    // contributor has no balance
    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 1).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_after_removal() {
    let (env, contract_id, gate_token, admin, contributor) = setup_with_contract();

    // contributor has no balance — would fail if gate were active
    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, gate_token.clone(), 100).unwrap();
        remove_gate_config(&env, &admin);
        // Gate removed — should pass regardless of balance
        assert_gate_passes(&env, &contributor);
    });
}
