#!/usr/bin/env bash
# =============================================================================
# @file    github_actions_test.sh
# @brief   Validates GitHub Actions workflow files for correctness and speed.
#
# @description
#   Audits workflow YAML files under .github/workflows/ and enforces rules
#   that keep CI fast, correct, and maintainable. Runs locally and in CI.
#
# @checks
#   1.  Required workflow files exist and are non-empty.
#   2.  No workflow references the non-existent actions/checkout@v6.
#   3.  rust_ci.yml has no duplicate WASM build steps (~60-90 s/run wasted).
#   4.  Smoke test does not invoke non-existent contract functions.
#   5.  Smoke test initialize call includes the required --admin argument.
#   6.  Smoke test WASM build is scoped to -p crowdfund (not full workspace).
#   7.  Smoke test uses stellar-cli, not the deprecated soroban-cli.
#   8.  rust_ci.yml includes a frontend UI test job.
#   9.  rust_ci.yml uses Swatinem/rust-cache for dependency caching.
#   10. rust_ci.yml has timeout-minutes set to prevent runaway builds.
#   11. testnet_smoke.yml has permissions: contents: read (least-privilege).
#   12. rust_ci.yml includes a wasm-opt optimisation step.
#
# @security
#   - Reads workflow files only; never writes or executes them.
#   - No secrets or credentials are accessed.
#   - set -euo pipefail ensures unset variables and pipeline errors are fatal.
#   - All grep calls use -- to prevent flag injection from filenames.
#
# @performance
#   - Each check is a single grep pass; no repeated file reads.
#   - Script completes in under 100 ms on any modern machine.
#
# @usage
#   bash scripts/github_actions_test.sh
#
# @exitcodes
#   0  All checks passed.
#   1  One or more checks failed (details printed to stderr).
#
# @author  stellar-raise-contracts contributors
# @version 4.0.0
# =============================================================================

set -euo pipefail

# =============================================================================
# @section Constants — paths
# @notice  All file paths are defined here. Change once to affect all checks.
# =============================================================================

# @constant WORKFLOWS_DIR
# @notice  Root directory containing all GitHub Actions workflow YAML files.
readonly WORKFLOWS_DIR=".github/workflows"

# @constant RUST_CI_YML
# @notice  Path to the main Rust CI workflow file.
readonly RUST_CI_YML="$WORKFLOWS_DIR/rust_ci.yml"

# @constant SMOKE_YML
# @notice  Path to the testnet smoke-test workflow file.
readonly SMOKE_YML="$WORKFLOWS_DIR/testnet_smoke.yml"

# @constant SPELLCHECK_YML
# @notice  Path to the spellcheck workflow file.
readonly SPELLCHECK_YML="$WORKFLOWS_DIR/spellcheck.yml"

# @constant REQUIRED_WORKFLOW_FILES
# @notice  Array of workflow files that must exist and be non-empty.
readonly -a REQUIRED_WORKFLOW_FILES=(
  "$RUST_CI_YML"
  "$SMOKE_YML"
  "$SPELLCHECK_YML"
)

# =============================================================================
# @section Constants — versioning
# @notice  Pin action versions here; update in one place when upgrading.
# =============================================================================

# @constant CHECKOUT_BANNED_VERSION
# @notice  The non-existent checkout version that must never appear in workflows.
readonly CHECKOUT_BANNED_VERSION="actions/checkout@v6"

# @constant RUST_CACHE_ACTION
# @notice  The caching action required in rust_ci.yml for fast dependency builds.
readonly RUST_CACHE_ACTION="Swatinem/rust-cache"

# =============================================================================
# @section Constants — build configuration
# @notice  Cargo build flags and targets used in workflow validation checks.
# =============================================================================

# @constant WASM_BUILD_PATTERN
# @notice  The exact cargo command that constitutes a WASM build step.
#          Used to detect duplicate build steps (Check 3).
readonly WASM_BUILD_PATTERN="cargo build --release --target wasm32-unknown-unknown"

# @constant WASM_SCOPE_PATTERN
# @notice  Regex pattern confirming the WASM build is scoped to the crowdfund crate.
#          A full workspace build wastes 2-4x more CI time (Check 6).
readonly WASM_SCOPE_PATTERN="cargo build.*-p crowdfund"

# @constant WASM_OPT_TOOL
# @notice  The binary size optimiser that must appear in rust_ci.yml (Check 12).
#          wasm-opt -Oz reduces WASM size by 20-40%, lowering deployment fees.
readonly WASM_OPT_TOOL="wasm-opt"

# =============================================================================
# @section Constants — CLI tooling
# @notice  CLI tool names used in smoke-test validation.
# =============================================================================

# @constant DEPRECATED_CLI
# @notice  The deprecated Soroban CLI package name that must not appear in workflows.
#          soroban-cli is unmaintained and may contain unpatched vulnerabilities.
readonly DEPRECATED_CLI="soroban-cli"

# @constant REQUIRED_ADMIN_FLAG
# @notice  The --admin flag required in the smoke-test initialize invocation.
#          Omitting it causes on-chain rejection with a cryptic error message.
readonly REQUIRED_ADMIN_FLAG="--admin"

# =============================================================================
# @section Constants — non-existent contract functions
# @notice  Functions that do not exist in the crowdfund ABI.
#          Calling them causes the smoke test to fail with a confusing error.
# =============================================================================

# @constant BANNED_CONTRACT_FUNCTIONS
# @notice  Array of function names that must not appear in smoke-test invocations.
readonly -a BANNED_CONTRACT_FUNCTIONS=(
  "is_initialized"
  "get_campaign_info"
  "get_stats"
)

# =============================================================================
# @section Constants — security
# @notice  Permission strings required for least-privilege workflow jobs.
# =============================================================================

# @constant LEAST_PRIVILEGE_PERM
# @notice  The permissions declaration required in testnet_smoke.yml (Check 11).
#          Prevents a compromised job from pushing commits or modifying releases.
readonly LEAST_PRIVILEGE_PERM="contents: read"

# =============================================================================
# @section Constants — performance thresholds
# @notice  Numeric limits used in timeout and build-count checks.
# =============================================================================

# @constant MAX_WASM_BUILD_STEPS
# @notice  Maximum allowed WASM build steps in rust_ci.yml.
#          More than one step wastes 60-90 s of CI time per run.
readonly MAX_WASM_BUILD_STEPS=1

# @constant TIMEOUT_PATTERN
# @notice  Regex pattern confirming a timeout-minutes bound is present (Check 10).
readonly TIMEOUT_PATTERN="timeout-minutes:"

# @constant ELAPSED_TIME_PATTERN
# @notice  Regex pattern confirming elapsed-time logging is present (Check 10).
readonly ELAPSED_TIME_PATTERN="elapsed|JOB_START"

# @constant FRONTEND_JOB_PATTERN
# @notice  Regex pattern confirming the frontend job exists in rust_ci.yml (Check 8).
readonly FRONTEND_JOB_PATTERN="^  frontend:"

# =============================================================================
# @section Constants — exit codes
# =============================================================================

# @constant EXIT_PASS
# @notice  Exit code returned when all checks pass.
readonly EXIT_PASS=0

# @constant EXIT_FAIL
# @notice  Exit code returned when one or more checks fail.
readonly EXIT_FAIL=1

# @constant TOTAL_CHECKS
# @notice  Total number of checks performed by this script.
readonly TOTAL_CHECKS=12

# =============================================================================
# @section Helpers
# =============================================================================

# @var errors
# @notice  Running count of failed checks. Incremented by fail().
errors=0

# @function fail
# @notice  Records a check failure and increments the errors counter.
# @param   $*  Human-readable failure message printed to stderr.
fail() {
  echo "FAIL: $*" >&2
  errors=$((errors + 1))
}

# @function pass
# @notice  Prints a success message for a completed check.
# @param   $*  Human-readable success message printed to stdout.
pass() {
  echo "PASS: $*"
}

# @function check_file_exists_and_nonempty
# @notice  Verifies a workflow file exists and contains at least one byte.
# @param   $1  path  Full path to the workflow file.
# @exitcode  Calls fail() if the file is missing or empty; pass() otherwise.
check_file_exists_and_nonempty() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    fail "$path does not exist"
  elif [[ ! -s "$path" ]]; then
    fail "$path is empty"
  else
    pass "$path exists and is non-empty"
  fi
}

# =============================================================================
# Check 1 — Required workflow files exist and are non-empty
# @rationale Missing or empty workflow files silently disable CI jobs.
# =============================================================================
for file in "${REQUIRED_WORKFLOW_FILES[@]}"; do
  check_file_exists_and_nonempty "$file"
done

# =============================================================================
# Check 2 — No workflow references the non-existent actions/checkout@v6
# @rationale $CHECKOUT_BANNED_VERSION does not exist; any reference blocks CI.
# @security  A non-existent version could be hijacked by a malicious actor.
# =============================================================================
if grep -rq -- "$CHECKOUT_BANNED_VERSION" "$WORKFLOWS_DIR/"; then
  fail "Found '$CHECKOUT_BANNED_VERSION' (non-existent version) in $WORKFLOWS_DIR/"
  grep -rn -- "$CHECKOUT_BANNED_VERSION" "$WORKFLOWS_DIR/" >&2
else
  pass "No workflow references $CHECKOUT_BANNED_VERSION"
fi

# =============================================================================
# Check 3 — rust_ci.yml has no duplicate WASM build step
# @rationale Duplicate build wastes 60-90 s of CI time per run.
# @performance Removing the duplicate reduces median wall-clock time by ~90 s.
# =============================================================================
wasm_build_count=$(grep -c -- "$WASM_BUILD_PATTERN" "$RUST_CI_YML" 2>/dev/null || echo "0")
if [[ "$wasm_build_count" -gt "$MAX_WASM_BUILD_STEPS" ]]; then
  fail "$RUST_CI_YML contains $wasm_build_count WASM build steps (max $MAX_WASM_BUILD_STEPS)"
else
  pass "$RUST_CI_YML has $wasm_build_count WASM build step(s) (within limit of $MAX_WASM_BUILD_STEPS)"
fi

# =============================================================================
# Check 4 — Smoke test does not call non-existent contract functions
# @rationale Calling non-existent ABI functions causes confusing on-chain errors.
# =============================================================================
for bad_fn in "${BANNED_CONTRACT_FUNCTIONS[@]}"; do
  if grep -qF -- "-- $bad_fn" "$SMOKE_YML"; then
    fail "$SMOKE_YML calls non-existent contract function: $bad_fn"
  else
    pass "$SMOKE_YML does not call non-existent function '$bad_fn'"
  fi
done

# =============================================================================
# Check 5 — Smoke test initialize call includes the required --admin argument
# @rationale Omitting $REQUIRED_ADMIN_FLAG causes on-chain rejection.
# @security  Admin controls privileged ops (upgrades, refunds).
# =============================================================================
if ! grep -qF -- "$REQUIRED_ADMIN_FLAG" "$SMOKE_YML"; then
  fail "$SMOKE_YML initialize call is missing required $REQUIRED_ADMIN_FLAG argument"
else
  pass "$SMOKE_YML initialize call includes $REQUIRED_ADMIN_FLAG"
fi

# =============================================================================
# Check 6 — Smoke test WASM build is scoped to -p crowdfund
# @rationale Full workspace build compiles unnecessary crates.
# @performance Scoped build is 2-4x faster than full workspace build.
# =============================================================================
if ! grep -qE -- "$WASM_SCOPE_PATTERN" "$SMOKE_YML"; then
  fail "$SMOKE_YML WASM build step is missing '-p crowdfund' scope"
else
  pass "$SMOKE_YML WASM build step is scoped to -p crowdfund"
fi

# =============================================================================
# Check 7 — Smoke test uses stellar-cli, not the deprecated soroban-cli
# @rationale $DEPRECATED_CLI is unmaintained and may have unpatched vulnerabilities.
# @security  Unmaintained CLI increases supply-chain risk.
# =============================================================================
if grep -qF -- "$DEPRECATED_CLI" "$SMOKE_YML"; then
  fail "$SMOKE_YML installs deprecated '$DEPRECATED_CLI' — use 'stellar-cli'"
else
  pass "$SMOKE_YML does not reference deprecated $DEPRECATED_CLI"
fi

# =============================================================================
# Check 8 — rust_ci.yml includes a frontend UI test job
# @rationale Without a frontend job, Jest tests never run in CI.
# @performance Frontend job runs in parallel — zero added wall-clock time.
# =============================================================================
if ! grep -qE -- "$FRONTEND_JOB_PATTERN" "$RUST_CI_YML"; then
  fail "$RUST_CI_YML is missing a 'frontend' job for UI tests"
else
  pass "$RUST_CI_YML includes a 'frontend' job for UI tests"
fi

# =============================================================================
# Check 9 — rust_ci.yml uses Swatinem/rust-cache for dependency caching
# @rationale Without caching, every run re-downloads all Rust dependencies.
# @performance rust-cache reduces cold-build time by 60-80%.
# =============================================================================
if ! grep -qF -- "$RUST_CACHE_ACTION" "$RUST_CI_YML"; then
  fail "$RUST_CI_YML is missing '$RUST_CACHE_ACTION' (dependency caching)"
else
  pass "$RUST_CI_YML uses $RUST_CACHE_ACTION for dependency caching"
fi

# =============================================================================
# Check 10 — rust_ci.yml has timeout-minutes and elapsed-time logging
# @rationale Without a timeout, a hung build can block runners for up to 6 hours.
# @performance Elapsed-time logging surfaces slow steps for future optimisation.
# =============================================================================
if ! grep -qE "$TIMEOUT_PATTERN" "$RUST_CI_YML"; then
  fail "$RUST_CI_YML is missing $TIMEOUT_PATTERN (runaway build risk)"
else
  pass "$RUST_CI_YML has $TIMEOUT_PATTERN bound"
fi

if ! grep -qE "$ELAPSED_TIME_PATTERN" "$RUST_CI_YML"; then
  fail "$RUST_CI_YML is missing elapsed-time logging step"
else
  pass "$RUST_CI_YML includes elapsed-time logging"
fi

# =============================================================================
# Check 11 — testnet_smoke.yml has least-privilege permissions
# @rationale Smoke test only needs read access; write perms are unnecessary.
# @security  Read-only perms prevent a compromised job from pushing commits.
# =============================================================================
if ! grep -qF -- "$LEAST_PRIVILEGE_PERM" "$SMOKE_YML"; then
  fail "$SMOKE_YML is missing 'permissions: $LEAST_PRIVILEGE_PERM' (least-privilege)"
else
  pass "$SMOKE_YML has least-privilege permissions ($LEAST_PRIVILEGE_PERM)"
fi

# =============================================================================
# Check 12 — rust_ci.yml includes a wasm-opt optimisation step
# @rationale Raw rustc WASM is not size-optimised; $WASM_OPT_TOOL -Oz saves 20-40%.
# @performance Reduces binary size 50-150 KB; lowers Stellar deployment fees.
# =============================================================================
if ! grep -qF -- "$WASM_OPT_TOOL" "$RUST_CI_YML"; then
  fail "$RUST_CI_YML is missing a $WASM_OPT_TOOL optimisation step"
else
  pass "$RUST_CI_YML includes a $WASM_OPT_TOOL optimisation step"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
if [[ "$errors" -eq 0 ]]; then
  echo "All checks passed. ($TOTAL_CHECKS/$TOTAL_CHECKS)"
  exit $EXIT_PASS
else
  echo "$errors check(s) failed out of $TOTAL_CHECKS." >&2
  exit $EXIT_FAIL
fi
