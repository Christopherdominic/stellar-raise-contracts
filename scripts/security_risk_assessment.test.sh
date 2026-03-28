#!/usr/bin/env bash
# @title   security_risk_assessment.test.sh
# @notice  Unit tests for security_risk_assessment.sh.
#          No external test framework required — pure bash assertions.
# @dev     Run: bash scripts/security_risk_assessment.test.sh
#          Exit 0 = all tests passed.

set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/security_risk_assessment.sh"
PASS=0
FAIL=0

# ── Harness ───────────────────────────────────────────────────────────────────

assert_exit() {
  local desc="$1" expected="$2"; shift 2
  local actual=0
  "$@" &>/dev/null || actual=$?
  if [[ "$actual" -eq "$expected" ]]; then
    printf '  PASS  %s\n' "$desc"; (( PASS++ )) || true
  else
    printf '  FAIL  %s  (expected exit %d, got %d)\n' "$desc" "$expected" "$actual"
    (( FAIL++ )) || true
  fi
}

assert_output_contains() {
  local desc="$1" pattern="$2"; shift 2
  local out actual=0
  out="$("$@" 2>&1)" || actual=$?
  if echo "$out" | grep -q "$pattern"; then
    printf '  PASS  %s\n' "$desc"; (( PASS++ )) || true
  else
    printf '  FAIL  %s  (pattern "%s" not found)\n' "$desc" "$pattern"
    (( FAIL++ )) || true
  fi
}

assert_output_not_contains() {
  local desc="$1" pattern="$2"; shift 2
  local out actual=0
  out="$("$@" 2>&1)" || actual=$?
  if echo "$out" | grep -q "$pattern"; then
    printf '  FAIL  %s  (pattern "%s" was found but should not be)\n' "$desc" "$pattern"
    (( FAIL++ )) || true
  else
    printf '  PASS  %s\n' "$desc"; (( PASS++ )) || true
  fi
}

assert_file_contains() {
  local desc="$1" file="$2" pattern="$3"
  if grep -q "$pattern" "$file" 2>/dev/null; then
    printf '  PASS  %s\n' "$desc"; (( PASS++ )) || true
  else
    printf '  FAIL  %s  (pattern "%s" not found in %s)\n' "$desc" "$pattern" "$file"
    (( FAIL++ )) || true
  fi
}

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf '  PASS  %s\n' "$desc"; (( PASS++ )) || true
  else
    printf '  FAIL  %s  (expected "%s", got "%s")\n' "$desc" "$expected" "$actual"
    (( FAIL++ )) || true
  fi
}

# ── Source helpers only ───────────────────────────────────────────────────────

SOURCING=1
# shellcheck source=/dev/null
source "$SCRIPT"

# ── Temp workspace ────────────────────────────────────────────────────────────

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ── Tests: add_finding ────────────────────────────────────────────────────────

printf '\n--- add_finding ---\n'

(
  HIGH=0; MEDIUM=0; findings='[]'
  add_finding "HIGH" "test_check" "a high finding"
  assert_eq "HIGH counter increments" "1" "$HIGH"
  assert_eq "MEDIUM counter unchanged" "0" "$MEDIUM"
  if echo "$findings" | grep -q '"severity":"HIGH"'; then
    printf '  PASS  finding JSON contains severity HIGH\n'; (( PASS++ )) || true
  else
    printf '  FAIL  finding JSON missing severity HIGH\n'; (( FAIL++ )) || true
  fi
)

(
  HIGH=0; MEDIUM=0; findings='[]'
  add_finding "MEDIUM" "test_check" "a medium finding"
  assert_eq "MEDIUM counter increments" "1" "$MEDIUM"
  assert_eq "HIGH counter unchanged" "0" "$HIGH"
)

(
  HIGH=0; MEDIUM=0; findings='[]'
  add_finding "LOW" "test_check" "a low finding"
  assert_eq "LOW does not increment HIGH" "0" "$HIGH"
  assert_eq "LOW does not increment MEDIUM" "0" "$MEDIUM"
)

(
  HIGH=0; MEDIUM=0; findings='[]'
  add_finding "HIGH" "c1" "first"
  add_finding "MEDIUM" "c2" "second"
  assert_eq "multiple findings: HIGH=1" "1" "$HIGH"
  assert_eq "multiple findings: MEDIUM=1" "1" "$MEDIUM"
)

# ── Tests: check_secret_exposure ─────────────────────────────────────────────

printf '\n--- check_secret_exposure ---\n'

# Clean directory — no secrets
(
  cd "$TMPDIR_TEST"
  HIGH=0; MEDIUM=0; findings='[]'
  mkdir -p clean && echo "no secrets here" > clean/safe.txt
  out="$(cd clean && HIGH=0; MEDIUM=0; findings='[]'; check_secret_exposure 2>&1)"
  if echo "$out" | grep -q "PASS"; then
    printf '  PASS  clean dir reports PASS\n'; (( PASS++ )) || true
  else
    printf '  FAIL  clean dir should report PASS\n'; (( FAIL++ )) || true
  fi
)

# Directory with a fake secret key
(
  cd "$TMPDIR_TEST"
  mkdir -p dirty
  # Write a syntactically valid-looking Stellar secret key (fake, not real)
  printf 'SECRET=SCZANGBA5XTONSOWMNBUNTE5LCMKXHMTJWZCSMZPTZ7JKFQXJXJXJXJXJX\n' > dirty/config.env
  out="$(cd dirty && HIGH=0; MEDIUM=0; findings='[]'; check_secret_exposure 2>&1)"
  if echo "$out" | grep -q "FAIL\|potential\|Potential"; then
    printf '  PASS  secret file triggers FAIL\n'; (( PASS++ )) || true
  else
    printf '  FAIL  secret file should trigger FAIL\n'; (( FAIL++ )) || true
  fi
)

# Secret value must NOT appear in output (only file path)
(
  cd "$TMPDIR_TEST"
  mkdir -p secret_test
  FAKE_KEY="SCZANGBA5XTONSOWMNBUNTE5LCMKXHMTJWZCSMZPTZ7JKFQXJXJXJXJXJX"
  printf 'KEY=%s\n' "$FAKE_KEY" > secret_test/leak.env
  out="$(cd secret_test && HIGH=0; MEDIUM=0; findings='[]'; check_secret_exposure 2>&1)"
  if echo "$out" | grep -q "$FAKE_KEY"; then
    printf '  FAIL  secret value leaked into output\n'; (( FAIL++ )) || true
  else
    printf '  PASS  secret value not echoed in output\n'; (( PASS++ )) || true
  fi
)

# ── Tests: check_soroban_gitignore ────────────────────────────────────────────

printf '\n--- check_soroban_gitignore ---\n'

# No .soroban directory → should pass
(
  cd "$TMPDIR_TEST"
  mkdir -p no_soroban && cd no_soroban
  git init -q
  HIGH=0; MEDIUM=0; findings='[]'
  out="$(check_soroban_gitignore 2>&1)"
  if echo "$out" | grep -q "does not exist\|PASS"; then
    printf '  PASS  no .soroban dir reports pass\n'; (( PASS++ )) || true
  else
    printf '  FAIL  no .soroban dir should report pass\n'; (( FAIL++ )) || true
  fi
)

# .soroban exists and is git-ignored → should pass
(
  cd "$TMPDIR_TEST"
  mkdir -p with_ignore && cd with_ignore
  git init -q
  mkdir .soroban
  echo ".soroban" > .gitignore
  HIGH=0; MEDIUM=0; findings='[]'
  out="$(check_soroban_gitignore 2>&1)"
  if echo "$out" | grep -q "PASS\|correctly"; then
    printf '  PASS  ignored .soroban reports pass\n'; (( PASS++ )) || true
  else
    printf '  FAIL  ignored .soroban should report pass\n'; (( FAIL++ )) || true
  fi
)

# .soroban exists but NOT git-ignored → should fail and add HIGH finding
(
  cd "$TMPDIR_TEST"
  mkdir -p no_ignore && cd no_ignore
  git init -q
  mkdir .soroban
  HIGH=0; MEDIUM=0; findings='[]'
  check_soroban_gitignore &>/dev/null || true
  assert_eq ".soroban not ignored increments HIGH" "1" "$HIGH"
)

# ── Tests: check_wasm_size ────────────────────────────────────────────────────

printf '\n--- check_wasm_size ---\n'

# WASM file missing → MEDIUM finding
(
  cd "$TMPDIR_TEST"
  mkdir -p no_wasm && cd no_wasm
  HIGH=0; MEDIUM=0; findings='[]'
  WASM_PATH="nonexistent.wasm"
  check_wasm_size &>/dev/null || true
  assert_eq "missing WASM adds MEDIUM finding" "1" "$MEDIUM"
)

# WASM within size limit → pass
(
  cd "$TMPDIR_TEST"
  mkdir -p small_wasm && cd small_wasm
  dd if=/dev/zero bs=1024 count=100 of=test.wasm 2>/dev/null
  HIGH=0; MEDIUM=0; findings='[]'
  WASM_PATH="test.wasm" WASM_MAX_BYTES=$(( 256 * 1024 ))
  out="$(check_wasm_size 2>&1)"
  if echo "$out" | grep -q "PASS\|OK"; then
    printf '  PASS  small WASM passes size gate\n'; (( PASS++ )) || true
  else
    printf '  FAIL  small WASM should pass size gate\n'; (( FAIL++ )) || true
  fi
)

# WASM exceeds size limit → HIGH finding
(
  cd "$TMPDIR_TEST"
  mkdir -p big_wasm && cd big_wasm
  dd if=/dev/zero bs=1024 count=300 of=big.wasm 2>/dev/null
  HIGH=0; MEDIUM=0; findings='[]'
  WASM_PATH="big.wasm" WASM_MAX_BYTES=$(( 256 * 1024 ))
  check_wasm_size &>/dev/null || true
  assert_eq "oversized WASM adds HIGH finding" "1" "$HIGH"
)

# ── Tests: write_report ───────────────────────────────────────────────────────

printf '\n--- write_report ---\n'

# No findings → risk LOW, exit 0
(
  cd "$TMPDIR_TEST"
  HIGH=0; MEDIUM=0; findings='[]'
  start_ts="2026-01-01T00:00:00Z"
  REPORT_JSON="$TMPDIR_TEST/report_low.json"
  exit_code=0; write_report || exit_code=$?
  assert_eq "no findings → exit 0" "0" "$exit_code"
  assert_file_contains "report has risk_level LOW" "$REPORT_JSON" 'risk_level.*LOW'
  assert_file_contains "report has schema_version" "$REPORT_JSON" 'schema_version.*1.0'
  assert_file_contains "report has high_count 0" "$REPORT_JSON" 'high_count.*0'
)

# HIGH finding → exit 1
(
  cd "$TMPDIR_TEST"
  HIGH=1; MEDIUM=0; findings='[{"severity":"HIGH","check":"x","detail":"y"}]'
  start_ts="2026-01-01T00:00:00Z"
  REPORT_JSON="$TMPDIR_TEST/report_high.json"
  exit_code=0; write_report || exit_code=$?
  assert_eq "HIGH finding → exit 1" "1" "$exit_code"
  assert_file_contains "report has risk_level HIGH" "$REPORT_JSON" 'risk_level.*HIGH'
)

# MEDIUM finding (no HIGH) → exit 2
(
  cd "$TMPDIR_TEST"
  HIGH=0; MEDIUM=1; findings='[{"severity":"MEDIUM","check":"x","detail":"y"}]'
  start_ts="2026-01-01T00:00:00Z"
  REPORT_JSON="$TMPDIR_TEST/report_medium.json"
  exit_code=0; write_report || exit_code=$?
  assert_eq "MEDIUM finding → exit 2" "2" "$exit_code"
  assert_file_contains "report has risk_level MEDIUM" "$REPORT_JSON" 'risk_level.*MEDIUM'
)

# Report JSON is valid (contains expected keys)
(
  cd "$TMPDIR_TEST"
  HIGH=0; MEDIUM=0; findings='[]'
  start_ts="2026-01-01T00:00:00Z"
  REPORT_JSON="$TMPDIR_TEST/report_keys.json"
  write_report &>/dev/null || true
  assert_file_contains "report has started_at" "$REPORT_JSON" '"started_at"'
  assert_file_contains "report has finished_at" "$REPORT_JSON" '"finished_at"'
  assert_file_contains "report has findings array" "$REPORT_JSON" '"findings"'
)

# ── Summary ───────────────────────────────────────────────────────────────────

printf '\n══════════════════════════════════════\n'
printf ' Tests: %d passed, %d failed\n' "$PASS" "$FAIL"
printf '══════════════════════════════════════\n\n'

[[ "$FAIL" -eq 0 ]]
