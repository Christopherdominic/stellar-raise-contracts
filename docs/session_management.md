# Session Management

Time-bounded, single-use session tokens for the Stellar Raise crowdfund contract.

## Overview

`session_management` provides on-chain session records that authorize sensitive
operations without requiring the caller to re-sign every ledger. Each session has
a configurable TTL, is single-use, and can be revoked at any time.

## Session Lifecycle

```
create_session(caller, ttl_seconds)
    → stores SessionRecord { expires_at, used: false }

validate_session(caller)
    → checks expiry and used flag
    → marks session as used (single-use, replay-safe)
    → returns Ok(()) or Err(SessionError)

revoke_session(caller)
    → removes the session record immediately (idempotent)
```

## Functions

### `create_session(env, caller, ttl_seconds) -> Result<SessionRecord, SessionError>`

Opens a new session for `caller`. Requires authorization from `caller`.

| Parameter    | Type      | Description                          |
|--------------|-----------|--------------------------------------|
| `caller`     | `Address` | Address opening the session          |
| `ttl_seconds`| `u64`     | Session lifetime in seconds (60–3600)|

**Errors:** `InvalidTtl`, `SessionAlreadyExists`

---

### `validate_session(env, caller) -> Result<(), SessionError>`

Checks and **consumes** the session in one atomic step. Safe to call from any
sensitive entry point (withdraw, upgrade, etc.).

**Errors:** `SessionNotFound`, `SessionExpired`, `SessionAlreadyUsed`

---

### `revoke_session(env, caller)`

Immediately removes the session record. Idempotent — revoking a non-existent
session is a no-op. Requires authorization from `caller`.

---

### `get_session(env, caller) -> Option<SessionRecord>`

Read-only view. Returns the live session record, or `None` if absent or expired.
Does **not** consume the session.

## Pure Helpers

| Function | Description |
|---|---|
| `validate_ttl(ttl)` | Returns `Err(InvalidTtl)` when TTL is outside `[60, 3600]` |
| `is_session_expired(expires_at, now)` | Returns `true` when `now > expires_at` |

## Constants

| Constant | Value | Description |
|---|---|---|
| `MIN_SESSION_TTL_SECONDS` | `60` | Minimum session lifetime |
| `MAX_SESSION_TTL_SECONDS` | `3600` | Maximum session lifetime (1 hour) |
| `SESSION_LEDGER_TTL` | `17280` | Persistent storage TTL in ledgers (~24 h) |

## Error Codes

| Variant | Code | Trigger |
|---|---|---|
| `SessionAlreadyExists` | 1 | Live session already open for this address |
| `SessionNotFound` | 2 | No session record found |
| `SessionExpired` | 3 | Session TTL has elapsed |
| `SessionAlreadyUsed` | 4 | Session was already consumed |
| `InvalidTtl` | 5 | TTL outside `[MIN, MAX]` range |

## Security Notes

- `caller.require_auth()` in `create_session` and `revoke_session` ensures only
  the key-holder can open or revoke their own session.
- **Single-use**: `validate_session` sets `used = true` atomically before returning
  `Ok`, preventing replay attacks within the TTL window.
- TTL is capped at 1 hour (`MAX_SESSION_TTL_SECONDS`) to limit exposure.
- Expired sessions return `SessionExpired` — identical to missing sessions from
  the caller's perspective, leaking no information about past sessions.
- Sessions are isolated per address; one address cannot affect another's session.

## Usage Example

```rust
use crate::session_management::{create_session, validate_session};

// Open a 5-minute session
create_session(&env, &caller, 300)?;

// Later, in a sensitive operation:
validate_session(&env, &caller)?;
// ... perform the operation
```
