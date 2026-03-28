# security_monitoring_dashboard

Automated security monitoring dashboard for the Stellar Raise crowdfund contract.

## Overview

`security_monitoring_dashboard` provides a read-only, permissionless set of checks that aggregate key security metrics into a single `DashboardReport` snapshot. Automated tooling (CI bots, monitoring scripts, governance dashboards) can call `generate_report` at any time to detect anomalies without mutating ledger state.

## Files

| File | Purpose |
|---|---|
| `contracts/crowdfund/src/security_monitoring_dashboard.rs` | Module implementation |
| `contracts/crowdfund/src/security_monitoring_dashboard.test.rs` | Test suite |
| `docs/security_monitoring_dashboard.md` | This document |

## Public API

### `generate_report(env: &Env) -> DashboardReport`

Runs all 7 security checks and returns a `DashboardReport`.

```rust
use crate::security_monitoring_dashboard::generate_report;

let report = generate_report(&env);
if !report.healthy {
    // report.critical_count > 0 — operator action required
}
```

Also emits a `("security", "dashboard_scanned")` event with `(critical_count, warning_count)` for off-chain indexers.

### `DashboardReport`

```rust
pub struct DashboardReport {
    pub alerts: [Alert; 7],   // one entry per check
    pub critical_count: u32,
    pub warning_count: u32,
    pub healthy: bool,        // true when critical_count == 0
}
```

### `Alert`

```rust
pub struct Alert {
    pub check:   &'static str,  // short identifier, e.g. "fee_bps"
    pub level:   AlertLevel,    // Ok | Warning | Critical
    pub message: &'static str,  // human-readable finding
}
```

### `AlertLevel`

| Variant | Meaning |
|---|---|
| `Ok` | No anomaly detected |
| `Warning` | Informational — investigate but not immediately dangerous |
| `Critical` | Requires immediate operator attention |

## Checks

| Check | Key | Critical condition | Warning condition |
|---|---|---|---|
| `check_fee_bps` | `fee_bps` | `fee_bps > 1000` (> 10 %) | `PlatformConfig` absent |
| `check_total_raised_non_negative` | `total_raised` | `TotalRaised < 0` | `TotalRaised` key absent |
| `check_goal_positive` | `goal` | `Goal ≤ 0` | `Goal` key absent |
| `check_deadline_not_stale` | `deadline` | — | Campaign `Active` but deadline passed |
| `check_overcontribution` | `overcontribution` | `TotalRaised > 200 % of Goal` on Active campaign | — |
| `check_admin_set` | `admin` | `Admin` key absent | — |
| `check_paused_flag_present` | `paused_flag` | — | `Paused` key absent |

## Security Assumptions

1. **Read-only** — No function writes to storage; safe to call from simulation contexts.
2. **No auth required** — Permissionless so automated tooling needs no privileged key.
3. **Overflow-safe** — `check_overcontribution` uses `checked_mul` / `checked_div`; falls back to `i128::MAX` on overflow (treated as critical).
4. **Deterministic** — Same ledger state always produces the same report.
5. **Event integrity** — The `dashboard_scanned` event is emitted *after* all checks complete, so a mid-scan panic never produces a misleading partial event.

## Running Tests

```bash
cargo test -p crowdfund security_monitoring_dashboard
```

Expected: all tests pass. The suite covers every check's happy path and failure path, the aggregate report, and edge cases (zero goal, negative raised, fee at boundary, missing keys, over-contribution on Active vs. non-Active status).
