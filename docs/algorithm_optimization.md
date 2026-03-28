# Algorithm Optimization

Gas-efficient helpers for common on-chain patterns in the Stellar Raise crowdfund contract.

## Overview

The `algorithm_optimization` module provides four pure read-only helpers that replace
repeated single-item storage calls with bounded, single-pass alternatives. Each helper
is designed to minimize instruction consumption while remaining easy to audit.

## Functions

### `batch_contribution_lookup(env, addresses) -> Vec<i128>`

Returns the contribution amount for each address in one storage scan.

| Parameter   | Type           | Description                              |
|-------------|----------------|------------------------------------------|
| `env`       | `&Env`         | Soroban environment                      |
| `addresses` | `&Vec<Address>`| Addresses to look up (max 50)            |

**Returns:** `Vec<i128>` parallel to `addresses`; missing entries are `0`.

**Panics** if `addresses.len() > MAX_BATCH_SIZE`.

---

### `progress_bps(total_raised, goal) -> u32`

Computes campaign progress as basis points (0–10 000) without touching storage.

| Parameter     | Type   | Description              |
|---------------|--------|--------------------------|
| `total_raised`| `i128` | Current total raised     |
| `goal`        | `i128` | Campaign funding goal    |

**Returns:** `(total_raised * 10_000) / goal`, clamped to `[0, 10_000]`.

Returns `0` for non-positive inputs. Uses `saturating_mul` to prevent overflow.

---

### `is_refund_eligible(env, contributor, deadline, total_raised, goal) -> bool`

O(1) check for whether a contributor may call `refund_single`.

Returns `true` only when **all** of the following hold:
1. `ledger.timestamp > deadline` (campaign has expired)
2. `total_raised < goal` (goal was not met)
3. The contributor has a recorded contribution `> 0`

---

### `find_first_above_threshold(env, addresses, threshold) -> Option<(Address, i128)>`

Scans `addresses` and returns the first contributor whose amount strictly exceeds
`threshold`, exiting early on the first match.

**Panics** if `addresses.len() > MAX_BATCH_SIZE`.

---

### `sum_contributions(env, addresses) -> i128`

Sums contributions for a batch of addresses in one pass. Uses `saturating_add`
so the result never overflows — it saturates at `i128::MAX` instead.

**Panics** if `addresses.len() > MAX_BATCH_SIZE`.

---

## Constants

| Constant        | Value  | Description                                  |
|-----------------|--------|----------------------------------------------|
| `MAX_BATCH_SIZE`| `50`   | Maximum addresses per batch call             |
| `BPS_SCALE`     | `10000`| Basis-point scale factor                     |

## Security Notes

- All helpers are **read-only** — no state is mutated.
- Batch size is enforced at runtime with a `panic!` to fail closed.
- Arithmetic uses `saturating_mul` / `saturating_add` / `checked_add` throughout.
- `is_refund_eligible` uses a strict `>` comparison for the deadline, consistent
  with the main `contribute()` deadline check.

## Gas Efficiency Rationale

| Pattern                        | Before                        | After                              |
|--------------------------------|-------------------------------|------------------------------------|
| N contribution lookups         | N host-function calls         | 1 loop, N storage reads            |
| Progress calculation           | Division + float cast         | Integer bps, no float              |
| Refund eligibility             | 3 separate view calls         | 1 function, 1 storage read         |
| Finding top contributor        | Full scan always              | Early exit on first match          |

## Usage Example

```rust
use crate::algorithm_optimization::{batch_contribution_lookup, progress_bps};

// Look up contributions for a batch of addresses
let amounts = batch_contribution_lookup(&env, &contributor_addresses);

// Compute progress without re-reading storage
let bps = progress_bps(total_raised, goal); // e.g. 7500 = 75 %
```
