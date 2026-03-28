#!/usr/bin/env bash
# =============================================================================
# @file    github_actions_test.test.sh
# @brief   Test suite for github_actions_test.sh (12 checks, 22 tests).
#
# @description
#   Exercises every check in github_actions_test.sh against both the real
#   repository (happy path) and synthetic fixture directories (failure paths).
#   Each test creates an isolated temporary directory so tests are hermetic.
#
# @coverage
#   - Check 1:  required files exist / missing / empty / whitespace-only
#   - Check 2:  actions/checkout@v6 typo detection (rust_ci + smoke)
#   - Check 3:  duplicate WASM build step detection
#   - Check 4:  non-existent contract function detection (3 functions)
#   - Check 5:  missing --admin argument detection
#   - Check 6:  missing -p crowdfund scope detection
#   - Check 7:  deprecated soroban-cli detection
#   - Check 8:  missing frontend job detection
#   - Check 9:  missing Swatinem/rust-cache detection
#   - Check 10: missing timeout-minutes / elapsed-time logging detection
#   - Check 11: missing least-privilege permissions detection
#   - Check 12: missing wasm-opt step detection
#   - Edge:     multiple simultaneous failures all reported (no short-circuit)
#
# @security
#   - All fixture directories are created under mktemp -d and removed on EXIT.
#   - The script under test is never executed with elevated privileges.
#   - No network calls are made; all checks are purely file-based.
#   - Fixture content is inlined via heredocs — no external file downloads.
#
# @usage
#   bash scripts/github_actions_test.test.sh
#   VERBOSE=1 bash scripts/github_actions_test.test.sh
#
# @exitcodes
#   0  All tests passed.
#   1  One or more tests failed.
#
# @author  stellar-raise-contracts contributors
# @version 4.0.0
# =============================================================================

set -euo pipefail

# =============================================================================
# @section Constants
# =============================================================================

# @constant SCRIPT
# @notice  Relative path to the validator script under test.
readonly SCRIPT="scripts/github_actions_test.sh"

# @constant REPO_ROOT
# @notice  Absolute path to the repository root, captured before any subshell.
readonly REPO_ROOT="$(pwd)"

# @constant TOTAL_EXPECTED
# @notice  Total number of tests in this suite.
readonly TOTAL_EXPECTED=22

# =============================================================================
# @section State
# =============================================================================

passed=0
failed=0

# Collect all temp dirs for cleanup on exit
TMPDIRS=()
cleanup() { rm -rf "${TMPDIRS[@]:-}"; }
trap cleanup EXIT

# =============================================================================
# @section Helpers
# =============================================================================

# @function make_tmp
# @notice  Creates a temp directory, registers it for cleanup, and echoes path.
make_tmp() {
  local d; d=$(mktemp -d)
  TMPDIRS+=("$d")
  echo "$d"
}

# @function assert_exit
# @notice  Runs a command and asserts its exit code matches the expectation.
# @param   $1  desc      Human-readable test description.
# @param   $2  expected  Expected exit code (0 = pass, 1 = fail).
# @param   $@  command   Command and arguments to execute.
assert_exit() {
  local desc="$1" expected="$2"
  shift 2
  local actual=0
  if [[ "${VERBOSE:-0}" == "1" ]]; then
    "$@" || actual=$?
  else
    "$@" > /dev/null 2>&1 || actual=$?
  fi
  if [[ "$actual" -eq "$expected" ]]; then
    echo "  PASS  $desc"
    passed=$((passed + 1))
  else
    echo "  FAIL  $desc (expected exit $expected, got $actual)"
    failed=$((failed + 1))
  fi
}

# @function make_valid_fixture
# @notice  Creates a minimal valid workflow fixture satisfying all 12 checks.
# @param   $1  dir  Path to an already-created temporary directory.
# @note    Use as a baseline; corrupt one field per failure test.
make_valid_fixture() {
  local dir="$1"
  mkdir -p "$dir/.github/workflows"

  # rust_ci.yml — satisfies checks 2,3,8,9,10,12
  cat > "$dir/.github/workflows/rust_ci.yml" <<'EOF'
name: Rust CI
jobs:
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Record job start time
        run: echo "JOB_START=$(date +%s)" >> "$GITHUB_ENV"
      - uses: actions/checkout@v4
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --target wasm32-unknown-unknown -p crowdfund
        timeout-minutes: 10
      - run: cargo test --workspace
        timeout-minutes: 15
      - run: wasm-opt -Oz target/wasm32-unknown-unknown/release/crowdfund.wasm -o out.wasm
      - name: Log elapsed time
        if: always()
        run: |
          END=$(date +%s)
          ELAPSED=$(( END - JOB_START ))
          echo "elapsed: ${ELAPSED}s"
EOF

  # testnet_smoke.yml — satisfies checks 2,4,5,6,7,11
  cat > "$dir/.github/workflows/testnet_smoke.yml" <<'EOF'
name: Testnet Smoke Test
permissions:
  contents: read
jobs:
  smoke-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install stellar-cli
      - run: cargo build --target wasm32-unknown-unknown --release -p crowdfund
      - run: |
          stellar contract invoke --id $ID -- initialize \
            --admin $ADDR --creator $ADDR --token T --goal 1000 --deadline 9999 --min_contribution 1
EOF

  # spellcheck.yml — satisfies check 1
  echo "name: Spellcheck" > "$dir/.github/workflows/spellcheck.yml"
}

# =============================================================================
# Tests
# =============================================================================

echo ""
echo "=== Check 1: required files ==="

# Test 1 — Happy path: real repository passes all 12 checks
assert_exit "real repo passes all 12 checks" 0 bash "$SCRIPT"

# Test 2 — spellcheck.yml is missing
d=$(make_tmp); make_valid_fixture "$d"; rm "$d/.github/workflows/spellcheck.yml"
assert_exit "fails when spellcheck.yml is missing" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 3 — workflow file exists but is empty (zero bytes)
d=$(make_tmp); make_valid_fixture "$d"; : > "$d/.github/workflows/spellcheck.yml"
assert_exit "fails when spellcheck.yml is empty (zero bytes)" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 4 — whitespace-only file passes Check 1 (non-empty by byte count)
d=$(make_tmp); make_valid_fixture "$d"; printf "\n\n\n" > "$d/.github/workflows/spellcheck.yml"
assert_exit "whitespace-only spellcheck.yml passes Check 1" 0 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 2: banned checkout version ==="

# Test 5 — checkout@v6 in rust_ci.yml
d=$(make_tmp); make_valid_fixture "$d"
sed -i 's/checkout@v4/checkout@v6/g' "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when checkout@v6 in rust_ci.yml" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 6 — checkout@v6 in testnet_smoke.yml
d=$(make_tmp); make_valid_fixture "$d"
sed -i 's/checkout@v4/checkout@v6/g' "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when checkout@v6 in testnet_smoke.yml" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 3: duplicate WASM build ==="

# Test 7 — duplicate WASM build steps
d=$(make_tmp); make_valid_fixture "$d"
echo "      - run: cargo build --release --target wasm32-unknown-unknown" \
  >> "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when duplicate WASM build steps exist" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 4: banned contract functions ==="

# Test 8 — is_initialized
d=$(make_tmp); make_valid_fixture "$d"
echo "      - run: stellar contract invoke --id \$ID -- is_initialized" \
  >> "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when smoke test calls is_initialized" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 9 — get_campaign_info
d=$(make_tmp); make_valid_fixture "$d"
echo "      - run: stellar contract invoke --id \$ID -- get_campaign_info" \
  >> "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when smoke test calls get_campaign_info" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 10 — get_stats
d=$(make_tmp); make_valid_fixture "$d"
echo "      - run: stellar contract invoke --id \$ID -- get_stats" \
  >> "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when smoke test calls get_stats" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 5: --admin flag ==="

# Test 11 — missing --admin
d=$(make_tmp); make_valid_fixture "$d"
cat > "$d/.github/workflows/testnet_smoke.yml" <<'EOF'
name: Testnet Smoke Test
permissions:
  contents: read
jobs:
  smoke-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install stellar-cli
      - run: cargo build --target wasm32-unknown-unknown --release -p crowdfund
      - run: stellar contract invoke --id $ID -- initialize --creator $A --token T --goal 1000 --deadline 9999 --min_contribution 1
EOF
assert_exit "fails when smoke test initialize is missing --admin" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 6: -p crowdfund scope ==="

# Test 12 — missing -p crowdfund
d=$(make_tmp); make_valid_fixture "$d"
cat > "$d/.github/workflows/testnet_smoke.yml" <<'EOF'
name: Testnet Smoke Test
permissions:
  contents: read
jobs:
  smoke-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install stellar-cli
      - run: cargo build --target wasm32-unknown-unknown --release
      - run: stellar contract invoke --id $ID -- initialize --admin $A --creator $A --token T --goal 1000 --deadline 9999 --min_contribution 1
EOF
assert_exit "fails when smoke test WASM build is missing -p crowdfund" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 7: deprecated soroban-cli ==="

# Test 13 — soroban-cli present
d=$(make_tmp); make_valid_fixture "$d"
cat > "$d/.github/workflows/testnet_smoke.yml" <<'EOF'
name: Testnet Smoke Test
permissions:
  contents: read
jobs:
  smoke-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install soroban-cli
      - run: cargo build --target wasm32-unknown-unknown --release -p crowdfund
      - run: stellar contract invoke --id $ID -- initialize --admin $A --creator $A --token T --goal 1000 --deadline 9999 --min_contribution 1
EOF
assert_exit "fails when smoke test uses deprecated soroban-cli" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 8: frontend job ==="

# Test 14 — missing frontend job
d=$(make_tmp); make_valid_fixture "$d"
cat > "$d/.github/workflows/rust_ci.yml" <<'EOF'
name: Rust CI
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Record job start time
        run: echo "JOB_START=$(date +%s)" >> "$GITHUB_ENV"
      - uses: actions/checkout@v4
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --target wasm32-unknown-unknown -p crowdfund
        timeout-minutes: 10
      - run: wasm-opt -Oz target/wasm32-unknown-unknown/release/crowdfund.wasm -o out.wasm
      - name: Log elapsed
        if: always()
        run: echo "elapsed: $(($(date +%s) - JOB_START))s"
EOF
assert_exit "fails when rust_ci.yml is missing the frontend job" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 9: Swatinem/rust-cache ==="

# Test 15 — missing rust-cache
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/Swatinem\/rust-cache/d' "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when rust_ci.yml is missing Swatinem/rust-cache" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 10: timeout-minutes + elapsed logging ==="

# Test 16 — missing timeout-minutes
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/timeout-minutes/d' "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when rust_ci.yml is missing timeout-minutes" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 17 — missing elapsed-time logging
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/elapsed\|JOB_START/d' "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when rust_ci.yml is missing elapsed-time logging" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 11: least-privilege permissions ==="

# Test 18 — missing permissions block
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/permissions:/d; /contents: read/d' "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when testnet_smoke.yml is missing least-privilege permissions" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Check 12: wasm-opt ==="

# Test 19 — missing wasm-opt
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/wasm-opt/d' "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when rust_ci.yml is missing the wasm-opt step" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

echo ""
echo "=== Edge cases ==="

# Test 20 — rust_ci.yml missing entirely
d=$(make_tmp); make_valid_fixture "$d"; rm "$d/.github/workflows/rust_ci.yml"
assert_exit "fails when rust_ci.yml is missing entirely" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 21 — testnet_smoke.yml missing entirely
d=$(make_tmp); make_valid_fixture "$d"; rm "$d/.github/workflows/testnet_smoke.yml"
assert_exit "fails when testnet_smoke.yml is missing entirely" 1 \
  bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'"

# Test 22 — multiple simultaneous failures all reported (no short-circuit)
d=$(make_tmp); make_valid_fixture "$d"
sed -i '/Swatinem\/rust-cache/d; /wasm-opt/d; /timeout-minutes/d' \
  "$d/.github/workflows/rust_ci.yml"
output=$(bash -c "cd '$d' && bash '$REPO_ROOT/$SCRIPT'" 2>&1 || true)
fail_count=$(echo "$output" | grep -c "^FAIL:" || true)
if [[ "$fail_count" -ge 3 ]]; then
  echo "  PASS  multiple simultaneous failures all reported ($fail_count FAIL lines)"
  passed=$((passed + 1))
else
  echo "  FAIL  expected >=3 FAIL lines for multiple failures, got $fail_count"
  failed=$((failed + 1))
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "Results: $passed passed, $failed failed out of $((passed + failed)) tests"
[[ "$failed" -eq 0 ]]
