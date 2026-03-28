# Batch Processing Optimization

## Overview

`batch_processing_optimization.rs` provides gas-efficient batch helpers for the
crowdfund contract. It reduces per-call overhead when processing multiple
contributions in a single transaction by validating, aggregating, and filtering
entries in bounded O(n) passes.

## Security Assumptions

| # | Assumption | Detail |
|---|-----------|--------|
| 1 | **Bounded** | All loops iterate at most `MAX_BATCH_SIZE` (10) times. |
| 2 | **Fail-fast** | Invalid input panics before any state mutation. |
| 3 | **Overflow-safe** | Totals use `checked_add`/`checked_mul`; panics on overflow. |
| 4 | **No auth bypass** | Auth is the caller's responsibility; this module validates structure only. |
| 5 | **Deterministic** | Same input always produces the same output. |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_BATCH_SIZE` | 10 | Maximum entries per batch call |

## Public API

### `validate_batch(env, entries) -> ValidationResult`

Single-pass O(n) validation. Checks (in order):
1. Batch is non-empty
2. Batch does not exceed `MAX_BATCH_SIZE`
3. No entry has a zero or negative amount
4. No duplicate contributor addresses

Returns `ValidationResult::Valid` or `ValidationResult::Invalid(reason)`.

### `summarize_batch(entries) -> BatchSummary`

Computes `count`, `total_amount`, `max_amount`, `min_amount` in one pass.
Assumes the batch has already been validated. Panics on overflow.

### `filter_above_threshold(env, entries, threshold) -> Vec<BatchEntry>`

Returns entries where `amount > threshold`. Useful for filtering dust
contributions before processing.

### `compute_batch_fee(entries, fee_bps) -> i128`

Computes total platform fee across all entries using integer basis-point
arithmetic (`amount * fee_bps / 10_000`). Uses `checked_mul` to prevent
overflow on large amounts.

## Types

### `BatchEntry`
```rust
pub struct BatchEntry {
    pub contributor: Address,
    pub amount: i128,      // must be > 0
}
```

### `BatchSummary`
```rust
pub struct BatchSummary {
    pub count: u32,
    pub total_amount: i128,
    pub max_amount: i128,
    pub min_amount: i128,
}
```

### `ValidationResult`
```rust
pub enum ValidationResult {
    Valid,
    Invalid(&'static str),  // static violation description
}
```

## Design Decisions

### Why fail-fast?
Partial state (some entries applied, others not) is harder to reason about and
recover from than a clean rollback. Fail-fast ensures the caller always gets a
consistent outcome.

### Why single-pass validation?
Callers pay validation cost once, not once per entry. The duplicate-address
check uses a `Vec<Address>` accumulator bounded by `MAX_BATCH_SIZE`, keeping
memory usage predictable.

### Why `MAX_BATCH_SIZE = 10`?
Aligned with the factory contract's `batch_contribute` module. Keeps worst-case
gas predictable and prevents oversized-array attacks.

## Test Coverage

Run with:
```bash
cargo test -p crowdfund batch_processing_optimization
```

The test suite (`batch_processing_optimization.test.rs`) covers:
- `ValidationResult` helpers (2 tests)
- `validate_batch`: empty, oversized, zero amount, negative amount, duplicate, single valid, max-size, multi-entry (8 tests)
- `summarize_batch`: single entry, multi-entry, equal amounts, first-entry tracking (4 tests)
- `filter_above_threshold`: all pass, all filtered, partial, zero threshold, exact boundary, empty input (6 tests)
- `compute_batch_fee`: zero fee, 1%, 10%, multi-entry sum, dust rounding, max fee, empty batch (7 tests)

Total: 27 tests, ≥ 95% coverage.
