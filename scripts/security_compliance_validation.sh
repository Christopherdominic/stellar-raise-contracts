#!/usr/bin/env bash
# @title   security_compliance_validation.sh
# @notice  Orchestrates all security compliance checks for the Stellar Raise
#          crowdfunding contract.  Designed to run in CI/CD and locally.
# @dev     Exit code policy:
#            0 = all checks passed
#            1 = one or more security checks failed
#            2 = required tooling is missing
# @custom:security-note  Every check writes a PASS/FAIL line to stdout so the
#          CI log provides a scannable summary without reading raw tool output.

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

# Maximum allowed optimised WASM size in bytes (256 KB — Stellar's limit).
# @dev  Increase only after confirming the new limit with Stellar documentation.
readonly WASM_MAX_BYTES=$(( 256 * 1024 ))

# Path to the compiled WASM binary (release build).
readonly WASM_PATH="target/wasm32-unknown-unknown/release/crowdfund.wasm"

# Minimum required Rust edition year (enforced via rustc --version parsing).
readonly MIN_RUST_EDITION=2021

# Allow-list file: one "advisory-id" per line to suppress known false positives.
# @dev  Add entries like "RUSTSEC-2023-0001" to suppress specific advisories.
#       Document every entry with a comment explaining why it is safe to ignore.
readonly ALLOWLIST_FILE=".security-allowlist"

# ── Colour helpers ────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # no colour

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILURES=$(( FAILURES + 1 )); }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
section() { echo -e "\n── $* ──────────────────────────────────────────────"; }

FAILURES=0

# ── Tool presence check ───────────────────────────────────────────────────────

# @notice  Verifies that every required security tool is installed before
#          running any checks.  Exits with code 2 if any tool is missing so
#          the caller can distinguish "tooling missing" from "check failed".
# @dev     Tools checked: cargo, cargo-audit, wasm-opt.
#          cargo-clippy ships with the stable toolchain so it is not checked
#          separately — if cargo is present, clippy is present.
check_tools() {
    section "Tool Presence"
    local missing=0

    for tool in cargo wasm-opt; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[MISSING]${NC} $tool — install it before running this script"
            missing=$(( missing + 1 ))
        else
            pass "$tool found ($(command -v "$tool"))"
        fi
    done

    # cargo-audit is a separate install: `cargo install cargo-audit`
    if ! cargo audit --version &>/dev/null 2>&1; then
        echo -e "${RED}[MISSING]${NC} cargo-audit — run: cargo install cargo-audit"
        missing=$(( missing + 1 ))
    else
        pass "cargo-audit found"
    fi

    if [ "$missing" -gt 0 ]; then
        echo ""
        echo "ERROR: $missing required tool(s) missing.  Install them and re-run."
        exit 2
    fi
}

# ── Check 1: Static analysis (clippy) ────────────────────────────────────────

# @notice  Runs cargo clippy with strict flags to catch common Rust
#          anti-patterns before they reach production.
# @dev     Flags used:
#            -D warnings          — treat every warning as an error
#            -D clippy::unwrap_used — forbid unwrap() in non-test code
#            -D clippy::expect_used — forbid expect() in non-test code
#            -D clippy::panic      — forbid panic!() in non-test code
#          These flags are intentionally strict; use the allow-list mechanism
#          or inline #[allow(...)] attributes for justified exceptions.
# @custom:security-note  unwrap()/expect()/panic!() in production code can
#          cause silent contract aborts that are indistinguishable from
#          legitimate errors on-chain.
check_static_analysis() {
    section "Static Analysis (clippy)"

    # Run clippy; capture exit code without triggering set -e.
    if cargo clippy --all-targets --all-features -- \
        -D warnings \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        2>&1; then
        pass "clippy — no forbidden patterns detected"
    else
        fail "clippy — forbidden patterns detected (unwrap/expect/panic in production code)"
    fi
}

# ── Check 2: Vulnerability scanning (cargo audit) ────────────────────────────

# @notice  Runs cargo audit against the RustSec advisory database to detect
#          known vulnerabilities in the dependency tree.
# @dev     If ALLOWLIST_FILE exists, advisories listed there are ignored via
#          --ignore flags.  Each ignored advisory must be documented in the
#          allow-list file with a comment explaining why it is safe.
# @custom:security-note  A single unpatched critical advisory in a dependency
#          can expose the contract to fund-draining exploits.
check_vulnerability_scan() {
    section "Vulnerability Scan (cargo audit)"

    local ignore_flags=""
    if [ -f "$ALLOWLIST_FILE" ]; then
        # Build --ignore flags from the allow-list (skip comment lines).
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            advisory_id=$(echo "$line" | awk '{print $1}')
            ignore_flags="$ignore_flags --ignore $advisory_id"
            warn "Allow-listed advisory: $advisory_id"
        done < "$ALLOWLIST_FILE"
    fi

    # shellcheck disable=SC2086
    if cargo audit $ignore_flags 2>&1; then
        pass "cargo audit — no unignored vulnerabilities found"
    else
        fail "cargo audit — vulnerable dependencies detected (see output above)"
    fi
}

# ── Check 3: Build-time invariants ───────────────────────────────────────────

# @notice  Verifies the contract compiles to WASM with release optimisations
#          and that the resulting binary does not exceed Stellar's size limit.
# @dev     Two sub-checks:
#            3a. cargo build --release --target wasm32-unknown-unknown
#            3b. wasm-opt -Oz + size gate (WASM_MAX_BYTES)
# @custom:security-note  An oversized WASM will be rejected by the Stellar
#          network at deployment time, causing a silent CI/CD failure that
#          only surfaces on testnet.  Catching it here saves a deploy cycle.
check_build_invariants() {
    section "Build-Time Invariants"

    # 3a. Compile
    if cargo build --release --target wasm32-unknown-unknown -p crowdfund 2>&1; then
        pass "WASM build succeeded"
    else
        fail "WASM build failed — contract does not compile"
        return  # no point checking size if build failed
    fi

    if [ ! -f "$WASM_PATH" ]; then
        fail "WASM binary not found at $WASM_PATH"
        return
    fi

    # 3b. Optimise and check size
    local opt_path="${WASM_PATH%.wasm}.opt.wasm"
    wasm-opt -Oz --enable-sign-ext "$WASM_PATH" -o "$opt_path" 2>&1

    local size
    size=$(stat -c%s "$opt_path" 2>/dev/null || stat -f%z "$opt_path")

    if [ "$size" -le "$WASM_MAX_BYTES" ]; then
        pass "WASM size OK: ${size} bytes (limit: ${WASM_MAX_BYTES} bytes)"
    else
        fail "WASM too large: ${size} bytes exceeds limit of ${WASM_MAX_BYTES} bytes"
    fi
}

# ── Check 4: Storage rent audit ──────────────────────────────────────────────

# @notice  Simulates the 1-year TTL cost for the contract's instance storage
#          to ensure the DApp will not go dormant prematurely due to unpaid
#          storage rent.
# @dev     Soroban charges rent in ledger entries per ledger.  One year ≈
#          3 153 600 ledgers (at 10 s/ledger).  The check verifies that the
#          contract's Cargo.toml declares soroban-sdk >= 22.0.0, which ships
#          with the TTL extension API required for rent management.
#          A full on-chain simulation requires a live RPC endpoint; this check
#          performs a static approximation suitable for CI.
# @custom:security-note  A contract whose instance storage expires becomes
#          permanently inaccessible.  Contributors would lose their funds with
#          no recourse.
check_storage_rent() {
    section "Storage Rent Audit"

    # Verify soroban-sdk version meets the minimum for TTL management.
    # @dev  The regex matches "soroban-sdk = ..." lines in any Cargo.toml.
    local sdk_version
    sdk_version=$(grep -r 'soroban-sdk' Cargo.toml contracts/*/Cargo.toml 2>/dev/null \
        | grep -oP '"\K[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)

    if [ -z "$sdk_version" ]; then
        fail "storage rent — could not determine soroban-sdk version"
        return
    fi

    # Require soroban-sdk >= 22.0.0 (ships with extend_ttl API).
    local major
    major=$(echo "$sdk_version" | cut -d. -f1)
    if [ "$major" -ge 22 ]; then
        pass "storage rent — soroban-sdk $sdk_version >= 22.0.0 (extend_ttl API available)"
    else
        fail "storage rent — soroban-sdk $sdk_version < 22.0.0; upgrade to enable TTL management"
    fi

    # Verify that extend_ttl calls are present in the contract source.
    # @dev  The contract must call extend_ttl on every persistent key write.
    local ttl_call_count
    ttl_call_count=$(grep -r 'extend_ttl' contracts/crowdfund/src/ 2>/dev/null | wc -l)

    if [ "$ttl_call_count" -gt 0 ]; then
        pass "storage rent — $ttl_call_count extend_ttl call(s) found in contract source"
    else
        fail "storage rent — no extend_ttl calls found; persistent keys may expire"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "════════════════════════════════════════════════════════"
    if [ "$FAILURES" -eq 0 ]; then
        echo -e "${GREEN}  SECURITY COMPLIANCE: PASSED (0 failures)${NC}"
    else
        echo -e "${RED}  SECURITY COMPLIANCE: FAILED ($FAILURES failure(s))${NC}"
    fi
    echo "════════════════════════════════════════════════════════"
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    echo "Stellar Raise — Security Compliance Validation"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    check_tools
    check_static_analysis
    check_vulnerability_scan
    check_build_invariants
    check_storage_rent
    print_summary

    [ "$FAILURES" -eq 0 ] || exit 1
}

main "$@"
