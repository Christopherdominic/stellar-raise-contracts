# NFT Gating

## Overview

`nft_gating.rs` adds NFT ownership access control to the crowdfund contract.
Only callers who own at least a configured number of NFTs from a designated collection may call `contribute()`.

When no gate is configured the contract behaves as before — all callers are allowed.

---

## Storage

| Key | Type | Description |
|-----|------|-------------|
| `DataKey::NftGate` | `NftGateConfig` | NFT collection address + minimum balance. Absent when no gate is active. |

```rust
pub struct NftGateConfig {
    pub nft_contract: Address,  // NFT collection contract
    pub min_balance: i128,      // minimum NFTs required (>= 1)
}
```

---

## Functions

### `configure_gate(env, caller, nft_contract, min_balance)`

Set or replace the NFT gate.

- **Auth**: `DEFAULT_ADMIN_ROLE` only.
- **Errors**: `ContractError::InvalidMinContribution` if `min_balance <= 0`.
- **Event**: `(nft_gate, configured)` → `(admin, nft_contract, min_balance)`.

### `remove_gate_config(env, caller)`

Remove the gate — restores open access.

- **Auth**: `DEFAULT_ADMIN_ROLE` only.
- **Event**: `(nft_gate, removed)` → `admin`.

### `assert_gate_passes(env, caller)`

Called inside `contribute()`. Panics with `"insufficient NFT balance to contribute"` if the caller's NFT balance is below `min_balance`. No-op when no gate is configured.

### `get_gate(env) -> Option<NftGateConfig>`

Read-only. Returns the current gate config or `None`.

---

## NFT Contract Interface

The gate expects the NFT collection contract to implement:

```rust
fn balance(env: Env, owner: Address) -> i128;
```

This is the standard balance query used by SEP-41 compatible and custom NFT contracts.

---

## Integration

Call `assert_gate_passes` at the top of `contribute()`, after `assert_not_paused`:

```rust
access_control::assert_not_paused(&env);
nft_gating::assert_gate_passes(&env, &contributor);
```

---

## Security Assumptions

1. Only `DEFAULT_ADMIN_ROLE` may configure or remove the gate.
2. NFT balance is read directly from the collection contract — the caller cannot spoof it.
3. The gate is read-only — no NFTs are transferred or locked.
4. All configuration changes emit events for off-chain monitoring.
5. Removing the gate is an admin action — a contributor cannot bypass the gate.
6. `min_balance >= 1` is enforced — a zero-balance gate is rejected at configuration time.

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
| `test_gate_passes_when_nft_balance_meets_minimum` | Exact minimum passes |
| `test_gate_passes_when_nft_balance_exceeds_minimum` | Above minimum passes |
| `test_gate_fails_when_nft_balance_below_minimum` | Zero balance panics |
| `test_gate_fails_when_nft_balance_is_zero` | Explicit zero balance panics |
| `test_gate_passes_after_removal` | Passes after gate removed |
