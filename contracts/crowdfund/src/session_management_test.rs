//! Tests for the `session_management` module.
//!
//! Coverage targets:
//! - `validate_ttl`: boundary values, out-of-range inputs
//! - `is_session_expired`: exact boundary, before/after expiry
//! - `create_session`: happy path, duplicate session, expired session reuse, invalid TTL
//! - `validate_session`: happy path, single-use enforcement, expiry, missing session
//! - `revoke_session`: idempotent revoke, revoke then validate
//! - `get_session`: live session, expired session, missing session

#[cfg(test)]
mod session_management_tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env,
    };

    use crate::session_management::{
        create_session, get_session, is_session_expired, revoke_session, validate_session,
        validate_ttl, SessionError, MAX_SESSION_TTL_SECONDS, MIN_SESSION_TTL_SECONDS,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env
    }

    fn set_time(env: &Env, ts: u64) {
        env.ledger().with_mut(|l| l.timestamp = ts);
    }

    // ── validate_ttl ──────────────────────────────────────────────────────────

    #[test]
    fn validate_ttl_accepts_minimum() {
        assert!(validate_ttl(MIN_SESSION_TTL_SECONDS).is_ok());
    }

    #[test]
    fn validate_ttl_accepts_maximum() {
        assert!(validate_ttl(MAX_SESSION_TTL_SECONDS).is_ok());
    }

    #[test]
    fn validate_ttl_accepts_midrange() {
        assert!(validate_ttl(1_800).is_ok());
    }

    #[test]
    fn validate_ttl_rejects_zero() {
        assert_eq!(validate_ttl(0), Err(SessionError::InvalidTtl));
    }

    #[test]
    fn validate_ttl_rejects_below_minimum() {
        assert_eq!(validate_ttl(MIN_SESSION_TTL_SECONDS - 1), Err(SessionError::InvalidTtl));
    }

    #[test]
    fn validate_ttl_rejects_above_maximum() {
        assert_eq!(validate_ttl(MAX_SESSION_TTL_SECONDS + 1), Err(SessionError::InvalidTtl));
    }

    // ── is_session_expired ────────────────────────────────────────────────────

    #[test]
    fn not_expired_when_now_equals_expires_at() {
        assert!(!is_session_expired(1_000, 1_000));
    }

    #[test]
    fn not_expired_when_now_before_expires_at() {
        assert!(!is_session_expired(1_000, 999));
    }

    #[test]
    fn expired_when_now_after_expires_at() {
        assert!(is_session_expired(1_000, 1_001));
    }

    // ── create_session ────────────────────────────────────────────────────────

    #[test]
    fn create_session_happy_path() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        let record = create_session(&env, &caller, 300).unwrap();
        assert_eq!(record.expires_at, 1_300);
        assert!(!record.used);
    }

    #[test]
    fn create_session_rejects_invalid_ttl() {
        let env = make_env();
        let caller = Address::generate(&env);
        assert_eq!(
            create_session(&env, &caller, 0),
            Err(SessionError::InvalidTtl)
        );
        assert_eq!(
            create_session(&env, &caller, MAX_SESSION_TTL_SECONDS + 1),
            Err(SessionError::InvalidTtl)
        );
    }

    #[test]
    fn create_session_rejects_duplicate_live_session() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        assert_eq!(
            create_session(&env, &caller, 300),
            Err(SessionError::SessionAlreadyExists)
        );
    }

    #[test]
    fn create_session_allows_new_session_after_expiry() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, MIN_SESSION_TTL_SECONDS).unwrap();

        // Advance past expiry
        set_time(&env, 1_000 + MIN_SESSION_TTL_SECONDS + 1);
        let record = create_session(&env, &caller, 300).unwrap();
        assert!(!record.used);
    }

    #[test]
    fn create_session_allows_new_session_after_used() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        validate_session(&env, &caller).unwrap();

        // Session is used — should be able to create a new one
        let record = create_session(&env, &caller, 300).unwrap();
        assert!(!record.used);
    }

    // ── validate_session ──────────────────────────────────────────────────────

    #[test]
    fn validate_session_happy_path() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        assert!(validate_session(&env, &caller).is_ok());
    }

    #[test]
    fn validate_session_single_use_enforcement() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        validate_session(&env, &caller).unwrap();

        // Second call within TTL must fail
        assert_eq!(
            validate_session(&env, &caller),
            Err(SessionError::SessionAlreadyUsed)
        );
    }

    #[test]
    fn validate_session_returns_not_found_when_no_session() {
        let env = make_env();
        let caller = Address::generate(&env);
        assert_eq!(
            validate_session(&env, &caller),
            Err(SessionError::SessionNotFound)
        );
    }

    #[test]
    fn validate_session_returns_expired_after_ttl() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, MIN_SESSION_TTL_SECONDS).unwrap();

        // Advance past expiry
        set_time(&env, 1_000 + MIN_SESSION_TTL_SECONDS + 1);
        assert_eq!(
            validate_session(&env, &caller),
            Err(SessionError::SessionExpired)
        );
    }

    #[test]
    fn validate_session_at_exact_expiry_is_valid() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();

        // At exactly expires_at — not yet expired (strict >)
        set_time(&env, 1_300);
        assert!(validate_session(&env, &caller).is_ok());
    }

    // ── revoke_session ────────────────────────────────────────────────────────

    #[test]
    fn revoke_session_removes_record() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        revoke_session(&env, &caller);

        assert_eq!(
            validate_session(&env, &caller),
            Err(SessionError::SessionNotFound)
        );
    }

    #[test]
    fn revoke_session_is_idempotent() {
        let env = make_env();
        let caller = Address::generate(&env);
        // Revoking a non-existent session must not panic
        revoke_session(&env, &caller);
        revoke_session(&env, &caller);
    }

    // ── get_session ───────────────────────────────────────────────────────────

    #[test]
    fn get_session_returns_live_record() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        let record = get_session(&env, &caller).unwrap();
        assert_eq!(record.expires_at, 1_300);
        assert!(!record.used);
    }

    #[test]
    fn get_session_returns_none_when_expired() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, MIN_SESSION_TTL_SECONDS).unwrap();
        set_time(&env, 1_000 + MIN_SESSION_TTL_SECONDS + 1);

        assert!(get_session(&env, &caller).is_none());
    }

    #[test]
    fn get_session_returns_none_when_missing() {
        let env = make_env();
        let caller = Address::generate(&env);
        assert!(get_session(&env, &caller).is_none());
    }

    #[test]
    fn get_session_does_not_consume_session() {
        let env = make_env();
        set_time(&env, 1_000);
        let caller = Address::generate(&env);

        create_session(&env, &caller, 300).unwrap();
        get_session(&env, &caller).unwrap();

        // Session must still be valid after get_session
        assert!(validate_session(&env, &caller).is_ok());
    }

    // ── Session isolation ─────────────────────────────────────────────────────

    #[test]
    fn sessions_are_isolated_per_address() {
        let env = make_env();
        set_time(&env, 1_000);
        let a = Address::generate(&env);
        let b = Address::generate(&env);

        create_session(&env, &a, 300).unwrap();
        // b has no session
        assert_eq!(
            validate_session(&env, &b),
            Err(SessionError::SessionNotFound)
        );
        // a's session is unaffected
        assert!(validate_session(&env, &a).is_ok());
    }
}
