# Token Gating

## Overview

`token_gating.rs` adds minimum token-balance access control to the crowdfund contract.
Only callers who hold at least a configured balance of a designated SEP-41 token may call `contribute()`.

When no gate is configured the contract behaves as before — all callers are allowed.

---

## Storage

| Key | Type | Description |
|-----|------|-------------|
| `DataKey::TokenGate` | `TokenGateConfig` | Gate token address + minimum balance. Absent when no gate is active. |

```rust
pub struct TokenGateConfig {
    pub gate_token: Address,  // SEP-41 token contract
    pub min_balance: i128,    // minimum balance required
}
```

---

## Functions

### `configure_gate(env, caller, gate_token, min_balance)`

Set or replace the token gate.

- **Auth**: `DEFAULT_ADMIN_ROLE` only.
- **Errors**: `ContractError::InvalidMinContribution` if `min_balance <= 0`.
- **Event**: `(token_gate, configured)` → `(admin, gate_token, min_balance)`.

### `remove_gate_config(env, caller)`

Remove the gate — restores open access.

- **Auth**: `DEFAULT_ADMIN_ROLE` only.
- **Event**: `(token_gate, removed)` → `admin`.

### `assert_gate_passes(env, caller)`

Called inside `contribute()`. Panics with `"insufficient token balance to contribute"` if the caller's balance is below `min_balance`. No-op when no gate is configured.

### `get_gate(env) -> Option<TokenGateConfig>`

Read-only. Returns the current gate config or `None`.

---

## Integration

Call `assert_gate_passes` at the top of `contribute()`, after `assert_not_paused`:

```rust
access_control::assert_not_paused(&env);
token_gating::assert_gate_passes(&env, &contributor);
```

---

## Security Assumptions

1. Only `DEFAULT_ADMIN_ROLE` may configure or remove the gate.
2. Balance is read directly from the SEP-41 token contract — the caller cannot spoof it.
3. The gate is read-only — no tokens are transferred or locked.
4. All configuration changes emit events for off-chain monitoring.
5. Removing the gate is an admin action — a compromised contributor key cannot bypass the gate.

---

## Test Coverage

| Test | Scenario |
|------|----------|
| `test_configure_gate_stores_config` | Config is persisted correctly |
| `test_configure_gate_rejects_zero_min_balance` | `min_balance = 0` returns error |
| `test_configure_gate_rejects_negative_min_balance` | `min_balance < 0` returns error |
| `test_configure_gate_rejects_non_admin` | Non-admin panics |
| `test_configure_gate_overwrites_existing` | Second configure replaces first |
| `test_remove_gate_clears_config` | Gate is absent after removal |
| `test_remove_gate_rejects_non_admin` | Non-admin panics |
| `test_no_gate_always_passes` | No gate → all callers pass |
| `test_gate_passes_when_balance_meets_minimum` | Exact minimum passes |
| `test_gate_passes_when_balance_exceeds_minimum` | Above minimum passes |
| `test_gate_fails_when_balance_below_minimum` | Below minimum panics |
| `test_gate_fails_when_balance_is_zero` | Zero balance panics |
| `test_gate_passes_after_removal` | Passes after gate removed |
