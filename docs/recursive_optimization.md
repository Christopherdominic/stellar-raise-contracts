# Recursive Optimization

## Overview

`recursive_optimization.rs` replaces recursive-style computation patterns with
bounded iterative equivalents to reduce gas consumption on Soroban.

Soroban charges per instruction — recursive functions re-enter the call stack
and duplicate frame setup cost on every level. The helpers in this module
produce identical results at lower and more predictable gas cost.

---

## Gas Comparison

| Pattern | Recursive cost | Iterative cost |
|---------|---------------|----------------|
| Sum over contributor list | O(n) stack frames | O(n) loop iterations |
| Milestone search (first unmet) | O(n) stack frames | O(n) loop iterations, early exit |
| Basis-point progress | O(log n) multiplications | 1 multiply + 1 divide |
| Power-of-two check | O(log n) divisions | 1 bitwise AND |

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ITER_DEPTH` | `1_000` | Hard cap on loop iterations — prevents unbounded gas consumption |

---

## Functions

### `iterative_sum(env, keys) -> Option<i128>`

Sum all contributor balances in a single bounded pass.

- Reads `DataKey::Contribution(addr)` for each address.
- Returns `None` on arithmetic overflow.
- Bounded by `MAX_ITER_DEPTH`.

### `iterative_first_unmet_milestone(milestones, total_raised) -> Option<u32>`

Find the index of the first milestone target not yet reached.

- Returns early on the first unmet milestone (best case O(1)).
- Returns `None` if all milestones are met.
- Bounded by `MAX_ITER_DEPTH`.

### `iterative_progress_bps(raised, goal) -> u32`

Compute funding progress in basis points (0–10 000).

- Returns `0` if `goal <= 0` or `raised <= 0`.
- Clamped to `10_000` — never reports > 100%.
- O(1), no loops.

### `is_power_of_two(n) -> bool`

Check whether `n` is a positive power of two using a single bitwise AND.

- O(1), branchless.
- Returns `false` for `n = 0`.

### `iterative_max_contribution(env, keys) -> i128`

Find the largest individual contribution in a single bounded pass.

- Returns `0` for an empty list.
- Bounded by `MAX_ITER_DEPTH`.

---

## Integration

```rust
let total = recursive_optimization::iterative_sum(&env, &contributors)?;
let next  = recursive_optimization::iterative_first_unmet_milestone(&milestones, total_raised);
let bps   = recursive_optimization::iterative_progress_bps(total_raised, goal);
```

---

## Security Assumptions

1. All loops are bounded by `MAX_ITER_DEPTH` — no unbounded gas consumption.
2. `iterative_sum` uses `checked_add` — overflows return `None` rather than wrapping.
3. No storage writes in this module — all functions are pure or read-only.
4. `iterative_progress_bps` clamps output to `10_000` — callers cannot observe > 100%.
5. `is_power_of_two` is branchless and allocation-free.

---

## Test Coverage

| Test | Scenario |
|------|----------|
| `test_iterative_sum_empty_list` | Empty list returns `Some(0)` |
| `test_iterative_sum_single_contributor` | Single entry summed correctly |
| `test_iterative_sum_multiple_contributors` | Multiple entries summed correctly |
| `test_iterative_sum_missing_entry_treated_as_zero` | Missing storage defaults to 0 |
| `test_first_unmet_milestone_empty` | Empty milestones returns `None` |
| `test_first_unmet_milestone_all_met` | All met returns `None` |
| `test_first_unmet_milestone_first_unmet` | First milestone unmet |
| `test_first_unmet_milestone_middle_unmet` | Middle milestone unmet |
| `test_first_unmet_milestone_last_unmet` | Last milestone unmet |
| `test_progress_bps_zero_raised` | Zero raised returns 0 |
| `test_progress_bps_zero_goal` | Zero goal returns 0 |
| `test_progress_bps_half` | 50% returns 5 000 |
| `test_progress_bps_full` | 100% returns 10 000 |
| `test_progress_bps_clamped_at_10000` | Over 100% clamped to 10 000 |
| `test_progress_bps_quarter` | 25% returns 2 500 |
| `test_is_power_of_two_zero_is_false` | 0 is not a power of two |
| `test_is_power_of_two_one` | 1 is a power of two |
| `test_is_power_of_two_powers` | 2^1 … 2^20 all pass |
| `test_is_power_of_two_non_powers` | Non-powers all fail |
| `test_max_contribution_empty_list` | Empty list returns 0 |
| `test_max_contribution_single` | Single entry returned |
| `test_max_contribution_multiple` | Largest of three returned |
| `test_max_iter_depth_is_positive` | Constant sanity check |
