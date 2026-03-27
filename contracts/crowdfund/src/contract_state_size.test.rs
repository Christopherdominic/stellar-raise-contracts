//! Integration tests for the `ContractStateSize` on-chain contract.
//!
//! @title   ContractStateSize Contract Interface Tests
//! @notice  Validates that the on-chain contract correctly exposes constants
//!          and the `validate_string` view function.
//! @dev     Uses soroban-sdk's test utilities to mock the environment.

#[cfg(test)]
mod tests {
    use crate::contract_state_size::{
        ContractStateSize, ContractStateSizeClient, MAX_CONTRIBUTORS, MAX_ROADMAP_ITEMS,
        MAX_STRETCH_GOALS, MAX_STRING_LEN,
    };
    use soroban_sdk::{Env, String};

    fn setup() -> (Env, ContractStateSizeClient<'static>) {
        let env = Env::default();
        let contract_id = env.register(ContractStateSize, ());
        let client = ContractStateSizeClient::new(&env, &contract_id);
        (env, client)
    }

    #[test]
    fn constants_are_exposed_correctly() {
        let (_env, client) = setup();
        assert_eq!(client.max_string_len(), MAX_STRING_LEN);
        assert_eq!(client.max_contributors(), MAX_CONTRIBUTORS);
        assert_eq!(client.max_roadmap_items(), MAX_ROADMAP_ITEMS);
        assert_eq!(client.max_stretch_goals(), MAX_STRETCH_GOALS);
    }

    #[test]
    fn validate_string_accepts_empty() {
        let (env, client) = setup();
        assert!(client.validate_string(&String::from_str(&env, "")));
    }

    #[test]
    fn validate_string_accepts_at_limit() {
        let (env, client) = setup();
        let s = String::from_str(&env, &"a".repeat(MAX_STRING_LEN as usize));
        assert!(client.validate_string(&s));
    }

    #[test]
    fn validate_string_rejects_one_over_limit() {
        let (env, client) = setup();
        let s = String::from_str(&env, &"a".repeat((MAX_STRING_LEN + 1) as usize));
        assert!(!client.validate_string(&s));
    }

    #[test]
    fn constants_have_documented_values() {
        assert_eq!(MAX_CONTRIBUTORS, 128);
        assert_eq!(MAX_ROADMAP_ITEMS, 32);
        assert_eq!(MAX_STRETCH_GOALS, 32);
        assert_eq!(MAX_STRING_LEN, 256);
    }
}
