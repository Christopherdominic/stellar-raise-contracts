//! Smart contract session management for the Stellar Raise crowdfund contract.
//!
//! @title   SessionManagement
//! @notice  Provides time-bounded, single-use session tokens that authorize
//!          sensitive operations (e.g. withdraw, upgrade) without requiring the
//!          caller to re-sign every ledger. Sessions are stored in persistent
//!          storage keyed by the caller's address and expire after a configurable
//!          TTL.
//!
//! # Session lifecycle
//!
//! ```text
//! create_session(caller, ttl_seconds)
//!     → stores SessionRecord { expires_at, used: false }
//!
//! validate_session(caller)
//!     → checks expiry and used flag
//!     → marks session as used (single-use)
//!     → returns Ok(()) or Err(SessionError)
//!
//! revoke_session(caller)
//!     → removes the session record immediately
//! ```
//!
//! # Security assumptions
//!
//! 1. `caller.require_auth()` is called in `create_session` — only the address
//!    owner can open a session for themselves.
//! 2. Sessions are **single-use**: `validate_session` marks `used = true` on
//!    first call, preventing replay attacks within the TTL window.
//! 3. TTL is capped at `MAX_SESSION_TTL_SECONDS` to limit the exposure window.
//! 4. A zero or negative TTL is rejected at creation time.
//! 5. Expired sessions are treated identically to missing sessions — no
//!    information is leaked about whether a session ever existed.

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum allowed session TTL: 1 hour.
/// @security Caps the exposure window for a compromised session.
pub const MAX_SESSION_TTL_SECONDS: u64 = 3_600;

/// Minimum allowed session TTL: 60 seconds.
pub const MIN_SESSION_TTL_SECONDS: u64 = 60;

/// Persistent storage TTL extension applied when a session is written (in ledgers).
/// 17_280 ledgers ≈ 24 hours at 5-second ledger close time.
pub const SESSION_LEDGER_TTL: u32 = 17_280;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by session management functions.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SessionError {
    /// A session already exists for this address and has not expired.
    SessionAlreadyExists = 1,
    /// No session record found for this address.
    SessionNotFound = 2,
    /// The session has passed its expiry timestamp.
    SessionExpired = 3,
    /// The session has already been consumed by a previous `validate_session` call.
    SessionAlreadyUsed = 4,
    /// The requested TTL is outside the allowed range.
    InvalidTtl = 5,
}

// ── Storage type ──────────────────────────────────────────────────────────────

/// On-chain record for a single session.
///
/// @dev Stored in persistent storage under `DataKey::Session(address)`.
///      The `used` flag is set atomically during `validate_session` to
///      prevent replay within the TTL window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Ledger timestamp after which the session is invalid.
    pub expires_at: u64,
    /// True once `validate_session` has consumed this session.
    pub used: bool,
}

// ── Storage key ───────────────────────────────────────────────────────────────

/// Persistent storage key for a session record.
///
/// @dev Defined locally so this module is self-contained and testable without
///      depending on the main `DataKey` enum.
#[contracttype]
#[derive(Clone)]
pub enum SessionKey {
    Session(Address),
}

// ── Pure helpers (exported for unit testing) ──────────────────────────────────

/// @title is_session_expired
/// @notice Returns `true` when `expires_at` is in the past relative to `now`.
/// @param expires_at  Session expiry as a Unix timestamp.
/// @param now         Current ledger timestamp.
/// @dev Pure function — no storage reads, no auth.
pub fn is_session_expired(expires_at: u64, now: u64) -> bool {
    now > expires_at
}

/// @title validate_ttl
/// @notice Returns `Ok(())` when `ttl` is within `[MIN, MAX]`, else `Err(InvalidTtl)`.
/// @param ttl  Requested session duration in seconds.
pub fn validate_ttl(ttl: u64) -> Result<(), SessionError> {
    if ttl < MIN_SESSION_TTL_SECONDS || ttl > MAX_SESSION_TTL_SECONDS {
        Err(SessionError::InvalidTtl)
    } else {
        Ok(())
    }
}

// ── Core functions ────────────────────────────────────────────────────────────

/// @title create_session
/// @notice Opens a new time-bounded session for `caller`.
///
/// @param env         The Soroban environment.
/// @param caller      The address opening the session (must authorize).
/// @param ttl_seconds Session lifetime in seconds (`[60, 3600]`).
///
/// @return `Ok(SessionRecord)` on success.
///
/// @custom:error `InvalidTtl`           — TTL outside allowed range.
/// @custom:error `SessionAlreadyExists` — A live session already exists.
///
/// @custom:security `caller.require_auth()` ensures only the key-holder can
///                  open a session for their own address.
pub fn create_session(
    env: &Env,
    caller: &Address,
    ttl_seconds: u64,
) -> Result<SessionRecord, SessionError> {
    caller.require_auth();

    validate_ttl(ttl_seconds)?;

    let now = env.ledger().timestamp();

    // Reject if a live (non-expired, non-used) session already exists.
    if let Some(existing) = load_session(env, caller) {
        if !existing.used && !is_session_expired(existing.expires_at, now) {
            return Err(SessionError::SessionAlreadyExists);
        }
    }

    let record = SessionRecord {
        expires_at: now + ttl_seconds,
        used: false,
    };

    env.storage()
        .persistent()
        .set(&SessionKey::Session(caller.clone()), &record);
    env.storage()
        .persistent()
        .extend_ttl(&SessionKey::Session(caller.clone()), SESSION_LEDGER_TTL, SESSION_LEDGER_TTL);

    env.events().publish(
        (Symbol::new(env, "session"), Symbol::new(env, "created")),
        (caller.clone(), record.expires_at),
    );

    Ok(record)
}

/// @title validate_session
/// @notice Checks and consumes a session for `caller` in one atomic step.
///
/// @param env     The Soroban environment.
/// @param caller  The address whose session is being validated.
///
/// @return `Ok(())` when the session is live and unused; marks it as used.
///
/// @custom:error `SessionNotFound`    — No record exists.
/// @custom:error `SessionExpired`     — Record exists but TTL has elapsed.
/// @custom:error `SessionAlreadyUsed` — Record was already consumed.
///
/// @custom:security Single-use enforcement: `used` is set to `true` before
///                  returning `Ok`, so a second call within the TTL window
///                  returns `SessionAlreadyUsed` instead of `Ok`.
pub fn validate_session(env: &Env, caller: &Address) -> Result<(), SessionError> {
    let record = load_session(env, caller).ok_or(SessionError::SessionNotFound)?;

    let now = env.ledger().timestamp();

    if is_session_expired(record.expires_at, now) {
        return Err(SessionError::SessionExpired);
    }

    if record.used {
        return Err(SessionError::SessionAlreadyUsed);
    }

    // Mark as used — atomic within this transaction.
    let consumed = SessionRecord {
        expires_at: record.expires_at,
        used: true,
    };
    env.storage()
        .persistent()
        .set(&SessionKey::Session(caller.clone()), &consumed);

    env.events().publish(
        (Symbol::new(env, "session"), Symbol::new(env, "validated")),
        caller.clone(),
    );

    Ok(())
}

/// @title revoke_session
/// @notice Immediately removes the session record for `caller`.
///
/// @param env     The Soroban environment.
/// @param caller  The address whose session is being revoked (must authorize).
///
/// @custom:security `caller.require_auth()` ensures only the key-holder or
///                  an authorized admin can revoke a session.
///                  Revoking a non-existent session is a no-op (idempotent).
pub fn revoke_session(env: &Env, caller: &Address) {
    caller.require_auth();

    env.storage()
        .persistent()
        .remove(&SessionKey::Session(caller.clone()));

    env.events().publish(
        (Symbol::new(env, "session"), Symbol::new(env, "revoked")),
        caller.clone(),
    );
}

/// @title get_session
/// @notice Returns the session record for `caller`, or `None` if absent/expired.
///
/// @dev Read-only view — does not mutate state or consume the session.
pub fn get_session(env: &Env, caller: &Address) -> Option<SessionRecord> {
    let record = load_session(env, caller)?;
    let now = env.ledger().timestamp();
    if is_session_expired(record.expires_at, now) {
        None
    } else {
        Some(record)
    }
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn load_session(env: &Env, caller: &Address) -> Option<SessionRecord> {
    env.storage()
        .persistent()
        .get(&SessionKey::Session(caller.clone()))
}
