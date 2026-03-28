//! Comprehensive tests for `security_monitoring_dashboard`.
//!
//! Coverage targets:
//! - Every individual check function (happy path + failure path).
//! - `generate_report` aggregate: healthy, warning-only, and critical states.
//! - `AlertLevel` and `Alert` constructors.
//! - Edge cases: zero goal, negative total_raised, fee at boundary, fee above
//!   boundary, missing keys, over-contribution on Active vs. non-Active status.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env};

use crate::{
    security_monitoring_dashboard::{
        check_admin_set, check_deadline_not_stale, check_fee_bps, check_goal_positive,
        check_overcontribution, check_paused_flag_present, check_total_raised_non_negative,
        generate_report, Alert, AlertLevel, MAX_ALLOWED_FEE_BPS, OVERCONTRIBUTION_THRESHOLD_BPS,
    },
    DataKey, PlatformConfig, Status,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Seeds a fully-compliant contract state.
fn seed_compliant(env: &Env) {
    let admin = Address::generate(env);
    let platform = Address::generate(env);
    let token = Address::generate(env);

    env.storage().instance().set(&DataKey::Admin, &admin);
    env.storage().instance().set(&DataKey::Token, &token);
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    env.storage().instance().set(&DataKey::TotalRaised, &0i128);
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    let deadline = env.ledger().timestamp() + 3_600;
    env.storage().instance().set(&DataKey::Deadline, &deadline);
    env.storage().instance().set(&DataKey::Paused, &false);
    env.storage().instance().set(
        &DataKey::PlatformConfig,
        &PlatformConfig { address: platform, fee_bps: 500 },
    );
}

// ── AlertLevel ────────────────────────────────────────────────────────────────

#[test]
fn alert_level_variants_are_distinct() {
    assert_ne!(AlertLevel::Ok, AlertLevel::Warning);
    assert_ne!(AlertLevel::Ok, AlertLevel::Critical);
    assert_ne!(AlertLevel::Warning, AlertLevel::Critical);
}

// ── check_fee_bps ─────────────────────────────────────────────────────────────

#[test]
fn fee_bps_ok_when_within_limit() {
    let env = Env::default();
    let platform = Address::generate(&env);
    env.storage().instance().set(
        &DataKey::PlatformConfig,
        &PlatformConfig { address: platform, fee_bps: MAX_ALLOWED_FEE_BPS },
    );
    let alert = check_fee_bps(&env);
    assert_eq!(alert.level, AlertLevel::Ok);
}

#[test]
fn fee_bps_critical_when_above_limit() {
    let env = Env::default();
    let platform = Address::generate(&env);
    env.storage().instance().set(
        &DataKey::PlatformConfig,
        &PlatformConfig { address: platform, fee_bps: MAX_ALLOWED_FEE_BPS + 1 },
    );
    let alert = check_fee_bps(&env);
    assert_eq!(alert.level, AlertLevel::Critical);
}

#[test]
fn fee_bps_warning_when_config_absent() {
    let env = Env::default();
    let alert = check_fee_bps(&env);
    assert_eq!(alert.level, AlertLevel::Warning);
}

#[test]
fn fee_bps_ok_when_zero() {
    let env = Env::default();
    let platform = Address::generate(&env);
    env.storage().instance().set(
        &DataKey::PlatformConfig,
        &PlatformConfig { address: platform, fee_bps: 0 },
    );
    let alert = check_fee_bps(&env);
    assert_eq!(alert.level, AlertLevel::Ok);
}

// ── check_total_raised_non_negative ──────────────────────────────────────────

#[test]
fn total_raised_ok_when_zero() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::TotalRaised, &0i128);
    assert_eq!(check_total_raised_non_negative(&env).level, AlertLevel::Ok);
}

#[test]
fn total_raised_ok_when_positive() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::TotalRaised, &500i128);
    assert_eq!(check_total_raised_non_negative(&env).level, AlertLevel::Ok);
}

#[test]
fn total_raised_critical_when_negative() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::TotalRaised, &-1i128);
    assert_eq!(check_total_raised_non_negative(&env).level, AlertLevel::Critical);
}

#[test]
fn total_raised_warning_when_absent() {
    let env = Env::default();
    assert_eq!(check_total_raised_non_negative(&env).level, AlertLevel::Warning);
}

// ── check_goal_positive ───────────────────────────────────────────────────────

#[test]
fn goal_ok_when_positive() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    assert_eq!(check_goal_positive(&env).level, AlertLevel::Ok);
}

#[test]
fn goal_critical_when_zero() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Goal, &0i128);
    assert_eq!(check_goal_positive(&env).level, AlertLevel::Critical);
}

#[test]
fn goal_critical_when_negative() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Goal, &-100i128);
    assert_eq!(check_goal_positive(&env).level, AlertLevel::Critical);
}

#[test]
fn goal_warning_when_absent() {
    let env = Env::default();
    assert_eq!(check_goal_positive(&env).level, AlertLevel::Warning);
}

// ── check_deadline_not_stale ──────────────────────────────────────────────────

#[test]
fn deadline_ok_when_in_future_and_active() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    let future = env.ledger().timestamp() + 3_600;
    env.storage().instance().set(&DataKey::Deadline, &future);
    assert_eq!(check_deadline_not_stale(&env).level, AlertLevel::Ok);
}

#[test]
fn deadline_warning_when_past_and_active() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    // timestamp() returns 0 in default env; set deadline to 0 (already passed)
    env.storage().instance().set(&DataKey::Deadline, &0u64);
    assert_eq!(check_deadline_not_stale(&env).level, AlertLevel::Warning);
}

#[test]
fn deadline_ok_when_past_but_succeeded() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Succeeded);
    env.storage().instance().set(&DataKey::Deadline, &0u64);
    assert_eq!(check_deadline_not_stale(&env).level, AlertLevel::Ok);
}

#[test]
fn deadline_ok_when_past_but_expired() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Expired);
    env.storage().instance().set(&DataKey::Deadline, &0u64);
    assert_eq!(check_deadline_not_stale(&env).level, AlertLevel::Ok);
}

#[test]
fn deadline_warning_when_status_absent() {
    let env = Env::default();
    assert_eq!(check_deadline_not_stale(&env).level, AlertLevel::Warning);
}

// ── check_overcontribution ────────────────────────────────────────────────────

#[test]
fn overcontribution_ok_when_raised_equals_goal() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    env.storage().instance().set(&DataKey::TotalRaised, &1_000i128);
    assert_eq!(check_overcontribution(&env).level, AlertLevel::Ok);
}

#[test]
fn overcontribution_ok_when_raised_below_threshold() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    // 199 % — just below the 200 % threshold
    env.storage().instance().set(&DataKey::TotalRaised, &1_990i128);
    assert_eq!(check_overcontribution(&env).level, AlertLevel::Ok);
}

#[test]
fn overcontribution_critical_when_raised_exceeds_threshold() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    // 201 % — above the 200 % threshold
    env.storage().instance().set(&DataKey::TotalRaised, &2_010i128);
    assert_eq!(check_overcontribution(&env).level, AlertLevel::Critical);
}

#[test]
fn overcontribution_ok_when_status_not_active() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Succeeded);
    env.storage().instance().set(&DataKey::Goal, &1_000i128);
    env.storage().instance().set(&DataKey::TotalRaised, &9_999_999i128);
    assert_eq!(check_overcontribution(&env).level, AlertLevel::Ok);
}

#[test]
fn overcontribution_ok_when_goal_is_zero() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Status, &Status::Active);
    env.storage().instance().set(&DataKey::Goal, &0i128);
    env.storage().instance().set(&DataKey::TotalRaised, &1_000i128);
    assert_eq!(check_overcontribution(&env).level, AlertLevel::Ok);
}

// ── check_admin_set ───────────────────────────────────────────────────────────

#[test]
fn admin_ok_when_set() {
    let env = Env::default();
    let admin = Address::generate(&env);
    env.storage().instance().set(&DataKey::Admin, &admin);
    assert_eq!(check_admin_set(&env).level, AlertLevel::Ok);
}

#[test]
fn admin_critical_when_absent() {
    let env = Env::default();
    assert_eq!(check_admin_set(&env).level, AlertLevel::Critical);
}

// ── check_paused_flag_present ─────────────────────────────────────────────────

#[test]
fn paused_flag_ok_when_false() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Paused, &false);
    assert_eq!(check_paused_flag_present(&env).level, AlertLevel::Ok);
}

#[test]
fn paused_flag_ok_when_true() {
    let env = Env::default();
    env.storage().instance().set(&DataKey::Paused, &true);
    assert_eq!(check_paused_flag_present(&env).level, AlertLevel::Ok);
}

#[test]
fn paused_flag_warning_when_absent() {
    let env = Env::default();
    assert_eq!(check_paused_flag_present(&env).level, AlertLevel::Warning);
}

// ── generate_report ───────────────────────────────────────────────────────────

#[test]
fn report_healthy_on_compliant_state() {
    let env = Env::default();
    seed_compliant(&env);
    let report = generate_report(&env);
    assert!(report.healthy);
    assert_eq!(report.critical_count, 0);
}

#[test]
fn report_not_healthy_when_admin_missing() {
    let env = Env::default();
    seed_compliant(&env);
    env.storage().instance().remove(&DataKey::Admin);
    let report = generate_report(&env);
    assert!(!report.healthy);
    assert!(report.critical_count > 0);
}

#[test]
fn report_not_healthy_when_total_raised_negative() {
    let env = Env::default();
    seed_compliant(&env);
    env.storage().instance().set(&DataKey::TotalRaised, &-1i128);
    let report = generate_report(&env);
    assert!(!report.healthy);
}

#[test]
fn report_has_warning_when_paused_flag_absent() {
    let env = Env::default();
    seed_compliant(&env);
    env.storage().instance().remove(&DataKey::Paused);
    let report = generate_report(&env);
    assert!(report.warning_count > 0);
    // No critical from this alone
    assert_eq!(report.critical_count, 0);
    assert!(report.healthy);
}

#[test]
fn report_alerts_length_equals_check_count() {
    let env = Env::default();
    seed_compliant(&env);
    let report = generate_report(&env);
    // 7 checks defined in generate_report
    assert_eq!(report.alerts.len(), 7);
}

#[test]
fn report_critical_count_matches_critical_alerts() {
    let env = Env::default();
    // No state seeded → admin missing (critical) + goal missing (warning) + others
    let report = generate_report(&env);
    let counted = report
        .alerts
        .iter()
        .filter(|a| a.level == AlertLevel::Critical)
        .count() as u32;
    assert_eq!(report.critical_count, counted);
}

#[test]
fn report_warning_count_matches_warning_alerts() {
    let env = Env::default();
    let report = generate_report(&env);
    let counted = report
        .alerts
        .iter()
        .filter(|a| a.level == AlertLevel::Warning)
        .count() as u32;
    assert_eq!(report.warning_count, counted);
}
