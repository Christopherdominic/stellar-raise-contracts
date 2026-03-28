//! # security_monitoring_dashboard
//!
//! @title   SecurityMonitoringDashboard — Automated security monitoring and
//!          alerting for the crowdfund contract.
//!
//! @notice  Provides a lightweight, read-only dashboard that aggregates key
//!          security metrics into a single `DashboardReport` snapshot.
//!          Automated tooling (CI bots, monitoring scripts) can call
//!          `generate_report` at any time to detect anomalies without
//!          mutating ledger state.
//!
//! @dev     All public functions are **read-only** — they never write to
//!          storage.  This makes them safe to call from simulation contexts.
//!
//! ## Security Assumptions
//!
//! 1. **Read-only** — No function in this module writes to storage.
//! 2. **No auth required** — Monitoring is intentionally permissionless so
//!    automated tooling does not need a privileged key.
//! 3. **Overflow-safe** — All arithmetic uses `checked_*` operations and
//!    falls back to a sentinel value rather than panicking.
//! 4. **Deterministic** — Given the same ledger state, every function returns
//!    the same result.
//! 5. **Bounded** — `generate_report` runs in O(1) with respect to
//!    contributor count; it reads only instance-storage scalars.

#![allow(dead_code)]

use soroban_sdk::{Env, Symbol};

use crate::{DataKey, PlatformConfig, Status};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum allowed platform fee in basis points (10 %).
pub const MAX_ALLOWED_FEE_BPS: u32 = 1_000;

/// Alert threshold: total raised must not exceed goal by more than this
/// fraction in basis points (200 % = 20_000 bps) before the campaign is
/// finalised.  Exceeding this suggests a double-contribution bug.
pub const OVERCONTRIBUTION_THRESHOLD_BPS: u32 = 20_000;

// ── Alert level ───────────────────────────────────────────────────────────────

/// Severity level attached to each security alert.
///
/// @notice `Ok` means no anomaly; `Warning` is informational; `Critical`
///         requires immediate operator attention.
#[derive(Clone, PartialEq, Debug)]
pub enum AlertLevel {
    Ok,
    Warning,
    Critical,
}

// ── Individual alert ──────────────────────────────────────────────────────────

/// A single security observation produced by the dashboard.
///
/// @param check   Short identifier for the check (e.g. `"fee_bps"`).
/// @param level   Severity of the observation.
/// @param message Human-readable description of the finding.
#[derive(Clone, Debug)]
pub struct Alert {
    pub check: &'static str,
    pub level: AlertLevel,
    pub message: &'static str,
}

impl Alert {
    fn ok(check: &'static str) -> Self {
        Alert { check, level: AlertLevel::Ok, message: "ok" }
    }
    fn warning(check: &'static str, message: &'static str) -> Self {
        Alert { check, level: AlertLevel::Warning, message }
    }
    fn critical(check: &'static str, message: &'static str) -> Self {
        Alert { check, level: AlertLevel::Critical, message }
    }
}

// ── Dashboard report ──────────────────────────────────────────────────────────

/// Aggregated security snapshot returned by `generate_report`.
///
/// @param alerts          All observations produced during the scan (fixed array of 7).
/// @param critical_count  Number of `Critical`-level alerts.
/// @param warning_count   Number of `Warning`-level alerts.
/// @param healthy         `true` when `critical_count == 0`.
#[derive(Debug)]
pub struct DashboardReport {
    pub alerts: [Alert; 7],
    pub critical_count: u32,
    pub warning_count: u32,
    pub healthy: bool,
}

// ── Individual check functions (exported for unit testing) ────────────────────

/// @notice Checks that the platform fee does not exceed `MAX_ALLOWED_FEE_BPS`.
/// @dev    Returns `Critical` when the fee is above the limit; `Ok` otherwise.
///         Returns `Warning` when `PlatformConfig` is absent (unconfigured).
pub fn check_fee_bps(env: &Env) -> Alert {
    match env.storage().instance().get::<_, PlatformConfig>(&DataKey::PlatformConfig) {
        Some(cfg) => {
            if cfg.fee_bps > MAX_ALLOWED_FEE_BPS {
                Alert::critical("fee_bps", "platform fee exceeds maximum allowed (10 %)")
            } else {
                Alert::ok("fee_bps")
            }
        }
        None => Alert::warning("fee_bps", "PlatformConfig not set"),
    }
}

/// @notice Checks that `TotalRaised` is non-negative.
/// @dev    A negative value indicates a storage corruption or arithmetic bug.
pub fn check_total_raised_non_negative(env: &Env) -> Alert {
    match env.storage().instance().get::<_, i128>(&DataKey::TotalRaised) {
        Some(v) if v < 0 => Alert::critical("total_raised", "TotalRaised is negative"),
        Some(_) => Alert::ok("total_raised"),
        None => Alert::warning("total_raised", "TotalRaised not initialised"),
    }
}

/// @notice Checks that the campaign goal is positive.
pub fn check_goal_positive(env: &Env) -> Alert {
    match env.storage().instance().get::<_, i128>(&DataKey::Goal) {
        Some(g) if g <= 0 => Alert::critical("goal", "campaign goal is not positive"),
        Some(_) => Alert::ok("goal"),
        None => Alert::warning("goal", "Goal not set"),
    }
}

/// @notice Checks that the campaign deadline has not already passed while the
///         campaign is still `Active`.
/// @dev    A past deadline on an Active campaign means `finalize` was never
///         called — a potential liveness issue.
pub fn check_deadline_not_stale(env: &Env) -> Alert {
    let status: Option<Status> = env.storage().instance().get(&DataKey::Status);
    let deadline: Option<u64> = env.storage().instance().get(&DataKey::Deadline);

    match (status, deadline) {
        (Some(Status::Active), Some(dl)) => {
            if env.ledger().timestamp() > dl {
                Alert::warning("deadline", "campaign is Active but deadline has passed; finalize() not called")
            } else {
                Alert::ok("deadline")
            }
        }
        (None, _) => Alert::warning("deadline", "Status not set"),
        _ => Alert::ok("deadline"),
    }
}

/// @notice Checks that `TotalRaised` does not exceed the goal by more than
///         `OVERCONTRIBUTION_THRESHOLD_BPS` while the campaign is Active.
/// @dev    Significant over-contribution on an Active campaign may indicate a
///         double-contribution vulnerability.
pub fn check_overcontribution(env: &Env) -> Alert {
    let status: Option<Status> = env.storage().instance().get(&DataKey::Status);
    if !matches!(status, Some(Status::Active)) {
        return Alert::ok("overcontribution");
    }

    let raised: i128 = env.storage().instance().get(&DataKey::TotalRaised).unwrap_or(0);
    let goal: i128 = env.storage().instance().get(&DataKey::Goal).unwrap_or(0);

    if goal <= 0 {
        return Alert::ok("overcontribution");
    }

    // progress_bps = raised * 10_000 / goal  (checked arithmetic)
    let progress_bps = raised
        .checked_mul(10_000)
        .and_then(|v| v.checked_div(goal))
        .unwrap_or(i128::MAX);

    if progress_bps > OVERCONTRIBUTION_THRESHOLD_BPS as i128 {
        Alert::critical("overcontribution", "TotalRaised exceeds 200 % of goal on Active campaign")
    } else {
        Alert::ok("overcontribution")
    }
}

/// @notice Checks that the `Admin` key is present.
/// @dev    A missing admin means the contract cannot be upgraded or paused.
pub fn check_admin_set(env: &Env) -> Alert {
    if env.storage().instance().has(&DataKey::Admin) {
        Alert::ok("admin")
    } else {
        Alert::critical("admin", "Admin key not set")
    }
}

/// @notice Checks that the `Paused` flag is present (even if `false`).
/// @dev    Absence of the flag means the pause mechanism was never initialised.
pub fn check_paused_flag_present(env: &Env) -> Alert {
    if env.storage().instance().has(&DataKey::Paused) {
        Alert::ok("paused_flag")
    } else {
        Alert::warning("paused_flag", "Paused flag not initialised")
    }
}

// ── Aggregate report ──────────────────────────────────────────────────────────

/// @notice Runs all security checks and returns a `DashboardReport`.
///
/// @dev    Emits a single `("security", "dashboard_scanned")` event carrying
///         `(critical_count, warning_count)` so off-chain indexers can track
///         scan history without re-reading storage.
///
/// @custom:security The event is emitted *after* all checks complete so a
///                  mid-scan panic never produces a misleading partial event.
pub fn generate_report(env: &Env) -> DashboardReport {
    let alerts: [Alert; 7] = [
        check_fee_bps(env),
        check_total_raised_non_negative(env),
        check_goal_positive(env),
        check_deadline_not_stale(env),
        check_overcontribution(env),
        check_admin_set(env),
        check_paused_flag_present(env),
    ];

    let mut critical_count: u32 = 0;
    let mut warning_count: u32 = 0;
    for alert in &alerts {
        match alert.level {
            AlertLevel::Critical => critical_count += 1,
            AlertLevel::Warning => warning_count += 1,
            AlertLevel::Ok => {}
        }
    }

    let healthy = critical_count == 0;

    env.events().publish(
        (Symbol::new(env, "security"), Symbol::new(env, "dashboard_scanned")),
        (critical_count, warning_count),
    );

    DashboardReport { alerts, critical_count, warning_count, healthy }
}
