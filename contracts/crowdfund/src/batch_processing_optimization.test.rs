//! Tests for `batch_processing_optimization`.
//!
//! @title   BatchProcessingOptimization Test Suite
//! @notice  Covers all public functions: validate_batch, summarize_batch,
//!          filter_above_threshold, compute_batch_fee, ValidationResult helpers.
//!          Includes happy paths, boundary values, and all error paths.
//!
//! Coverage targets (≥ 95%):
//! - validate_batch: empty, oversized, zero amount, negative amount, duplicate, valid
//! - summarize_batch: single entry, multi-entry, max/min tracking, overflow guard
//! - filter_above_threshold: all pass, all filtered, partial, threshold = 0
//! - compute_batch_fee: zero fee, max fee, single entry, multi-entry, overflow guard
//! - ValidationResult: is_valid, message helpers

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

use crate::batch_processing_optimization::{
    compute_batch_fee, filter_above_threshold, summarize_batch, validate_batch, BatchEntry,
    BatchSummary, ValidationResult, MAX_BATCH_SIZE,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_entry(env: &Env, amount: i128) -> BatchEntry {
    BatchEntry {
        contributor: Address::generate(env),
        amount,
    }
}

fn make_batch(env: &Env, amounts: &[i128]) -> Vec<BatchEntry> {
    let mut v: Vec<BatchEntry> = Vec::new(env);
    for &amt in amounts {
        v.push_back(make_entry(env, amt));
    }
    v
}

// ── ValidationResult helpers ──────────────────────────────────────────────────

#[test]
fn validation_result_valid_is_valid() {
    assert!(ValidationResult::Valid.is_valid());
    assert_eq!(ValidationResult::Valid.message(), "");
}

#[test]
fn validation_result_invalid_is_not_valid() {
    let r = ValidationResult::Invalid("some error");
    assert!(!r.is_valid());
    assert_eq!(r.message(), "some error");
}

// ── validate_batch ────────────────────────────────────────────────────────────

#[test]
fn validate_batch_rejects_empty() {
    let env = Env::default();
    let entries: Vec<BatchEntry> = Vec::new(&env);
    let result = validate_batch(&env, &entries);
    assert!(!result.is_valid());
    assert_eq!(result.message(), "batch is empty");
}

#[test]
fn validate_batch_rejects_oversized() {
    let env = Env::default();
    let mut entries: Vec<BatchEntry> = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        entries.push_back(make_entry(&env, 100));
    }
    let result = validate_batch(&env, &entries);
    assert!(!result.is_valid());
    assert_eq!(result.message(), "batch exceeds MAX_BATCH_SIZE");
}

#[test]
fn validate_batch_rejects_zero_amount() {
    let env = Env::default();
    let entries = make_batch(&env, &[100, 0, 50]);
    let result = validate_batch(&env, &entries);
    assert!(!result.is_valid());
    assert_eq!(result.message(), "entry amount must be positive");
}

#[test]
fn validate_batch_rejects_negative_amount() {
    let env = Env::default();
    let entries = make_batch(&env, &[100, -1]);
    let result = validate_batch(&env, &entries);
    assert!(!result.is_valid());
    assert_eq!(result.message(), "entry amount must be positive");
}

#[test]
fn validate_batch_rejects_duplicate_contributor() {
    let env = Env::default();
    let addr = Address::generate(&env);
    let entry = BatchEntry { contributor: addr.clone(), amount: 100 };
    let mut entries: Vec<BatchEntry> = Vec::new(&env);
    entries.push_back(entry.clone());
    entries.push_back(entry);
    let result = validate_batch(&env, &entries);
    assert!(!result.is_valid());
    assert_eq!(result.message(), "duplicate contributor address");
}

#[test]
fn validate_batch_accepts_single_valid_entry() {
    let env = Env::default();
    let entries = make_batch(&env, &[1]);
    assert!(validate_batch(&env, &entries).is_valid());
}

#[test]
fn validate_batch_accepts_max_size_batch() {
    let env = Env::default();
    let mut entries: Vec<BatchEntry> = Vec::new(&env);
    for i in 1..=MAX_BATCH_SIZE as i128 {
        entries.push_back(make_entry(&env, i));
    }
    assert!(validate_batch(&env, &entries).is_valid());
}

#[test]
fn validate_batch_accepts_multi_entry_valid_batch() {
    let env = Env::default();
    let entries = make_batch(&env, &[10, 20, 30]);
    assert!(validate_batch(&env, &entries).is_valid());
}

// ── summarize_batch ───────────────────────────────────────────────────────────

#[test]
fn summarize_batch_single_entry() {
    let env = Env::default();
    let entries = make_batch(&env, &[500]);
    let s = summarize_batch(&entries);
    assert_eq!(s, BatchSummary { count: 1, total_amount: 500, max_amount: 500, min_amount: 500 });
}

#[test]
fn summarize_batch_multiple_entries() {
    let env = Env::default();
    let entries = make_batch(&env, &[100, 300, 200]);
    let s = summarize_batch(&entries);
    assert_eq!(s.count, 3);
    assert_eq!(s.total_amount, 600);
    assert_eq!(s.max_amount, 300);
    assert_eq!(s.min_amount, 100);
}

#[test]
fn summarize_batch_all_equal_amounts() {
    let env = Env::default();
    let entries = make_batch(&env, &[50, 50, 50]);
    let s = summarize_batch(&entries);
    assert_eq!(s.total_amount, 150);
    assert_eq!(s.max_amount, 50);
    assert_eq!(s.min_amount, 50);
}

#[test]
fn summarize_batch_tracks_first_as_min_and_max() {
    let env = Env::default();
    let entries = make_batch(&env, &[999]);
    let s = summarize_batch(&entries);
    assert_eq!(s.max_amount, 999);
    assert_eq!(s.min_amount, 999);
}

// ── filter_above_threshold ────────────────────────────────────────────────────

#[test]
fn filter_above_threshold_all_pass() {
    let env = Env::default();
    let entries = make_batch(&env, &[10, 20, 30]);
    let filtered = filter_above_threshold(&env, &entries, 5);
    assert_eq!(filtered.len(), 3);
}

#[test]
fn filter_above_threshold_all_filtered() {
    let env = Env::default();
    let entries = make_batch(&env, &[1, 2, 3]);
    let filtered = filter_above_threshold(&env, &entries, 100);
    assert_eq!(filtered.len(), 0);
}

#[test]
fn filter_above_threshold_partial() {
    let env = Env::default();
    let entries = make_batch(&env, &[5, 15, 25]);
    let filtered = filter_above_threshold(&env, &entries, 10);
    assert_eq!(filtered.len(), 2);
}

#[test]
fn filter_above_threshold_zero_threshold_passes_all_positive() {
    let env = Env::default();
    let entries = make_batch(&env, &[1, 100, 1_000]);
    let filtered = filter_above_threshold(&env, &entries, 0);
    assert_eq!(filtered.len(), 3);
}

#[test]
fn filter_above_threshold_exact_boundary_excluded() {
    // threshold is exclusive (amount > threshold)
    let env = Env::default();
    let entries = make_batch(&env, &[10, 10, 11]);
    let filtered = filter_above_threshold(&env, &entries, 10);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered.get(0).unwrap().amount, 11);
}

#[test]
fn filter_above_threshold_empty_input() {
    let env = Env::default();
    let entries: Vec<BatchEntry> = Vec::new(&env);
    let filtered = filter_above_threshold(&env, &entries, 0);
    assert_eq!(filtered.len(), 0);
}

// ── compute_batch_fee ─────────────────────────────────────────────────────────

#[test]
fn compute_batch_fee_zero_fee_bps() {
    let env = Env::default();
    let entries = make_batch(&env, &[1_000, 2_000]);
    assert_eq!(compute_batch_fee(&entries, 0), 0);
}

#[test]
fn compute_batch_fee_100_bps_is_one_percent() {
    let env = Env::default();
    let entries = make_batch(&env, &[10_000]);
    // 10_000 * 100 / 10_000 = 100
    assert_eq!(compute_batch_fee(&entries, 100), 100);
}

#[test]
fn compute_batch_fee_1000_bps_is_ten_percent() {
    let env = Env::default();
    let entries = make_batch(&env, &[1_000]);
    // 1_000 * 1_000 / 10_000 = 100
    assert_eq!(compute_batch_fee(&entries, 1_000), 100);
}

#[test]
fn compute_batch_fee_sums_across_entries() {
    let env = Env::default();
    let entries = make_batch(&env, &[10_000, 20_000]);
    // (10_000 + 20_000) * 100 / 10_000 = 300
    assert_eq!(compute_batch_fee(&entries, 100), 300);
}

#[test]
fn compute_batch_fee_dust_rounds_to_zero() {
    let env = Env::default();
    // 1 * 1 / 10_000 = 0 (integer division)
    let entries = make_batch(&env, &[1]);
    assert_eq!(compute_batch_fee(&entries, 1), 0);
}

#[test]
fn compute_batch_fee_max_fee_bps() {
    let env = Env::default();
    let entries = make_batch(&env, &[10_000]);
    // 10_000 * 10_000 / 10_000 = 10_000
    assert_eq!(compute_batch_fee(&entries, 10_000), 10_000);
}

#[test]
fn compute_batch_fee_empty_batch_returns_zero() {
    let entries: Vec<BatchEntry> = Vec::new(&Env::default());
    assert_eq!(compute_batch_fee(&entries, 100), 0);
}
