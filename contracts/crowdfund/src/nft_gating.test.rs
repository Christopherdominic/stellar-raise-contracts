//! Tests for the `nft_gating` module.

use soroban_sdk::{
    contract, contractimpl,
    testutils::Address as _,
    Address, Env,
};

use crate::{
    nft_gating::{assert_gate_passes, configure_gate, get_gate, remove_gate_config},
    ContractError, DataKey,
};

// ── Stub NFT contract ─────────────────────────────────────────────────────────

/// Minimal NFT stub that stores balances set via `set_balance`.
#[contract]
struct StubNft;

#[contractimpl]
impl StubNft {
    pub fn set_balance(env: Env, owner: Address, amount: i128) {
        env.storage().instance().set(&owner, &amount);
    }
    pub fn balance(env: Env, owner: Address) -> i128 {
        env.storage().instance().get(&owner).unwrap_or(0)
    }
}

// ── Setup helper ──────────────────────────────────────────────────────────────

/// Returns (env, contract_id, nft_contract_addr, admin, contributor).
fn setup() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contributor = Address::generate(&env);

    let nft_id = env.register(StubNft, ());

    let contract_id = env.register(crate::CrowdfundContract, ());
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::DefaultAdmin, &admin);
    });

    (env, contract_id, nft_id, admin, contributor)
}

// ── configure_gate ────────────────────────────────────────────────────────────

#[test]
fn test_configure_gate_stores_config() {
    let (env, contract_id, nft_id, admin, _) = setup();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        let cfg = get_gate(&env).expect("gate should be set");
        assert_eq!(cfg.nft_contract, nft_id);
        assert_eq!(cfg.min_balance, 1);
    });
}

#[test]
fn test_configure_gate_rejects_zero_min_balance() {
    let (env, contract_id, nft_id, admin, _) = setup();

    env.as_contract(&contract_id, || {
        let result = configure_gate(&env, &admin, nft_id.clone(), 0);
        assert_eq!(result, Err(ContractError::InvalidMinContribution));
    });
}

#[test]
fn test_configure_gate_rejects_negative_min_balance() {
    let (env, contract_id, nft_id, admin, _) = setup();

    env.as_contract(&contract_id, || {
        let result = configure_gate(&env, &admin, nft_id.clone(), -1);
        assert_eq!(result, Err(ContractError::InvalidMinContribution));
    });
}

#[test]
#[should_panic(expected = "only DEFAULT_ADMIN_ROLE can configure NFT gate")]
fn test_configure_gate_rejects_non_admin() {
    let (env, contract_id, nft_id, _, contributor) = setup();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &contributor, nft_id.clone(), 1).unwrap();
    });
}

#[test]
fn test_configure_gate_overwrites_existing() {
    let (env, contract_id, nft_id, admin, _) = setup();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        configure_gate(&env, &admin, nft_id.clone(), 5).unwrap();
        assert_eq!(get_gate(&env).unwrap().min_balance, 5);
    });
}

// ── remove_gate_config ────────────────────────────────────────────────────────

#[test]
fn test_remove_gate_clears_config() {
    let (env, contract_id, nft_id, admin, _) = setup();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        remove_gate_config(&env, &admin);
        assert!(get_gate(&env).is_none());
    });
}

#[test]
#[should_panic(expected = "only DEFAULT_ADMIN_ROLE can remove NFT gate")]
fn test_remove_gate_rejects_non_admin() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        remove_gate_config(&env, &contributor);
    });
}

// ── assert_gate_passes ────────────────────────────────────────────────────────

#[test]
fn test_no_gate_always_passes() {
    let (env, contract_id, _, _, contributor) = setup();

    env.as_contract(&contract_id, || {
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_when_nft_balance_meets_minimum() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    let nft_client = StubNftClient::new(&env, &nft_id);
    nft_client.set_balance(&contributor, &1);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_when_nft_balance_exceeds_minimum() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    let nft_client = StubNftClient::new(&env, &nft_id);
    nft_client.set_balance(&contributor, &10);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 3).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
#[should_panic(expected = "insufficient NFT balance to contribute")]
fn test_gate_fails_when_nft_balance_below_minimum() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    // contributor owns 0 NFTs
    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
#[should_panic(expected = "insufficient NFT balance to contribute")]
fn test_gate_fails_when_nft_balance_is_zero() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    let nft_client = StubNftClient::new(&env, &nft_id);
    nft_client.set_balance(&contributor, &0);

    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        assert_gate_passes(&env, &contributor);
    });
}

#[test]
fn test_gate_passes_after_removal() {
    let (env, contract_id, nft_id, admin, contributor) = setup();

    // contributor owns no NFTs — would fail if gate were active
    env.as_contract(&contract_id, || {
        configure_gate(&env, &admin, nft_id.clone(), 1).unwrap();
        remove_gate_config(&env, &admin);
        assert_gate_passes(&env, &contributor);
    });
}
