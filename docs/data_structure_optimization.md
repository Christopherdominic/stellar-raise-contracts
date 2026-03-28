# data_structure_optimization

Gas-efficient storage layout helpers for the Stellar Raise crowdfund contract.

## Overview

`data_structure_optimization` provides pure helpers and storage-access patterns that reduce ledger read/write costs through four techniques:

| Technique | Saving |
|---|---|
| **Packed metadata** — 4 scalars in one slot | 3 fewer ledger reads per campaign query |
| **Lazy writes** — zero-amount keys removed | Eliminates empty-slot rent on refund/reset |
| **O(1) existence check** — `has()` instead of vector scan | Avoids O(n) scan on every contribution |
| **Checked arithmetic** — `checked_*` throughout | No silent overflow; `None` returned instead |

## Files

| File | Purpose |
|---|---|
| `contracts/crowdfund/src/data_structure_optimization.rs` | Module implementation |
| `contracts/crowdfund/src/data_structure_optimization.test.rs` | Test suite |
| `docs/data_structure_optimization.md` | This document |

## Public API

### `PackedCampaignMeta`

```rust
#[contracttype]
pub struct PackedCampaignMeta {
    pub goal: i128,
    pub deadline: u64,
    pub min_contribution: i128,
    pub total_raised: i128,
}
```

Packs the four most-read campaign scalars into one `DataKey::PackedMeta` instance-storage slot.

### Storage helpers

| Function | Description |
|---|---|
| `load_packed_meta(env)` | Returns `Option<PackedCampaignMeta>` — one read for four values |
| `store_packed_meta(env, meta)` | Persists the packed struct |
| `load_contribution(env, addr)` | Returns stored amount or `0` |
| `store_contribution(env, addr, amount)` | Writes when `amount > 0`; removes key when `amount == 0` |
| `contributor_exists(env, addr)` | O(1) `has()` check |
| `count_unique_contributors(env)` | Length of contributors vector, capped at `MAX_CONTRIBUTORS` |

### Arithmetic helpers

| Function | Returns |
|---|---|
| `checked_add_i128(base, delta)` | `Some(result)` or `None` on overflow |
| `checked_sub_i128(base, delta)` | `Some(result)` or `None` on underflow |
| `safe_fraction_bps(numerator, denominator, scale)` | `Some(bps)` or `None` when denominator ≤ 0, scale ≤ 0, or overflow |

## DataKey addition

`DataKey::PackedMeta` was added to the `DataKey` enum in `lib.rs` to support the packed metadata slot.

## Security Assumptions

1. **No auth required** — helpers are internal utilities; callers enforce auth and campaign-status checks.
2. **Overflow-safe** — all arithmetic uses `checked_*`; callers receive `None` on overflow rather than a panic.
3. **Bounded iteration** — `count_unique_contributors` iterates at most `MAX_CONTRIBUTORS` (128) entries.
4. **Lazy writes** — `store_contribution(0)` removes the key, preventing stale zero-value entries from inflating storage costs.
5. **No duplicate writes** — callers are responsible for reading the current value before calling `store_contribution` to avoid unnecessary writes.

## Running Tests

```bash
cargo test -p crowdfund data_structure_optimization
```

Expected: all tests pass with ≥ 95 % coverage across all helpers.
