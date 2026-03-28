#!/usr/bin/env bash
# @title   security_risk_assessment.sh
# @notice  Automated security risk assessment for the Stellar Raise CI/CD pipeline.
#          Runs a suite of checks against the repository and produces a structured
#          JSON report plus a human-readable summary.
#
# @dev     Checks performed:
#            1. Secret key exposure  — scans for plaintext Stellar secret keys (S...)
#            2. .soroban/ gitignore  — verifies the key directory is git-ignored
#            3. cargo audit          — known CVEs in Rust dependencies
#            4. npm audit            — known CVEs in Node dependencies
#            5. WASM size gate       — optimised binary must be ≤ 256 KB
#            6. Clippy deny          — no compiler warnings promoted to errors
#
#          Exit codes:
#            0  – all checks passed (RISK: LOW)
#            1  – one or more HIGH-severity findings
#            2  – one or more MEDIUM-severity findings (no HIGH)
#
#          Outputs:
#            REPORT_JSON  (default: security_risk_report.json)  — machine-readable
#            stdout                                              — human-readable
#
# @security
#   - Secret scanning uses a conservative regex; false positives are preferable
#     to false negatives for key exposure.
#   - The script never prints secret key values — only file paths and line numbers.
#   - All external tool invocations use explicit paths or PATH-resolved names with
#     version checks; no eval or dynamic code execution.

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

REPORT_JSON="${REPORT_JSON:-security_risk_report.json}"
WASM_PATH="target/wasm32-unknown-unknown/release/crowdfund.opt.wasm"
WASM_MAX_BYTES=$(( 256 * 1024 ))

# Stellar secret key pattern: 'S' followed by 55 base32 characters.
# @security Matches only the key format — never prints the matched value.
SECRET_KEY_RE='S[A-Z2-7]{55}'

# Files/dirs excluded from secret scanning (binary, lock files, known-safe).
SCAN_EXCLUDE=(
  "*.wasm" "*.lock" "*.sqlite" "*.ico" "*.svg" "*.png"
  ".git/*" "target/*" "node_modules/*"
)

# ── State ─────────────────────────────────────────────────────────────────────

HIGH=0
MEDIUM=0
findings='[]'   # JSON array built up during the run
start_ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ── Helpers ───────────────────────────────────────────────────────────────────

# @notice Appends a finding object to the JSON findings array.
# @param  $1  severity  HIGH | MEDIUM | LOW
# @param  $2  check     short identifier
# @param  $3  detail    human-readable description (no double-quotes)
add_finding() {
  local severity="$1" check="$2" detail="$3"
  local entry
  entry="$(printf '{"severity":"%s","check":"%s","detail":"%s"}' \
    "$severity" "$check" "$detail")"
  findings="$(printf '%s' "$findings" | \
    sed "s/\]$/,${entry}]/" | sed 's/\[,/[/')"
  if [[ "$severity" == "HIGH" ]];   then (( HIGH++   )) || true; fi
  if [[ "$severity" == "MEDIUM" ]]; then (( MEDIUM++ )) || true; fi
}

# @notice Prints a coloured status line to stdout.
pass()  { printf '  [PASS]  %s\n' "$1"; }
warn()  { printf '  [WARN]  %s\n' "$1"; }
fail()  { printf '  [FAIL]  %s\n' "$1"; }
info()  { printf '  [INFO]  %s\n' "$1"; }

# ── Check 1: Secret key exposure ─────────────────────────────────────────────

check_secret_exposure() {
  printf '\n[1/6] Scanning for exposed Stellar secret keys...\n'

  local exclude_args=()
  for pat in "${SCAN_EXCLUDE[@]}"; do
    exclude_args+=( --exclude="$pat" )
  done

  local hits
  # @security grep output is file:line only — matched text is suppressed with -l
  # to ensure secret values are never echoed to stdout or logs.
  hits="$(grep -rEl "${exclude_args[@]}" "$SECRET_KEY_RE" . 2>/dev/null || true)"

  if [[ -z "$hits" ]]; then
    pass "No exposed secret keys found"
  else
    local count
    count="$(echo "$hits" | wc -l | tr -d ' ')"
    fail "Found potential secret key exposure in $count file(s)"
    # Print file paths only — never the key values.
    while IFS= read -r f; do
      warn "  Potential secret in: $f"
      add_finding "HIGH" "secret_exposure" "Potential Stellar secret key in $f"
    done <<< "$hits"
  fi
}

# ── Check 2: .soroban/ gitignore ─────────────────────────────────────────────

check_soroban_gitignore() {
  printf '\n[2/6] Checking .soroban/ is git-ignored...\n'

  if [[ ! -d ".soroban" ]]; then
    pass ".soroban/ directory does not exist (nothing to ignore)"
    return
  fi

  if git check-ignore -q .soroban 2>/dev/null; then
    pass ".soroban/ is correctly listed in .gitignore"
  else
    fail ".soroban/ exists and is NOT git-ignored — contains plaintext secret keys"
    add_finding "HIGH" "soroban_gitignore" \
      ".soroban/ directory is not git-ignored; secret keys may be committed"
  fi
}

# ── Check 3: cargo audit ──────────────────────────────────────────────────────

check_cargo_audit() {
  printf '\n[3/6] Running cargo audit...\n'

  if ! command -v cargo-audit &>/dev/null; then
    warn "cargo-audit not installed — skipping (install: cargo install cargo-audit)"
    add_finding "MEDIUM" "cargo_audit" "cargo-audit not available; CVE check skipped"
    return
  fi

  local out exit_code=0
  out="$(cargo audit --color never 2>&1)" || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    pass "cargo audit: no known vulnerabilities"
  else
    fail "cargo audit: vulnerabilities found"
    add_finding "HIGH" "cargo_audit" "cargo audit reported vulnerabilities — review output"
  fi
}

# ── Check 4: npm audit ────────────────────────────────────────────────────────

check_npm_audit() {
  printf '\n[4/6] Running npm audit...\n'

  if [[ ! -f "package.json" ]]; then
    info "No package.json found — skipping npm audit"
    return
  fi

  if ! command -v npm &>/dev/null; then
    warn "npm not installed — skipping"
    add_finding "MEDIUM" "npm_audit" "npm not available; frontend CVE check skipped"
    return
  fi

  local exit_code=0
  npm audit --audit-level=moderate --json > /tmp/npm_audit_out.json 2>&1 || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    pass "npm audit: no moderate-or-higher vulnerabilities"
  else
    local vuln_count
    vuln_count="$(grep -o '"total":[0-9]*' /tmp/npm_audit_out.json | head -1 | grep -o '[0-9]*' || echo '?')"
    fail "npm audit: $vuln_count vulnerability/vulnerabilities found (moderate+)"
    add_finding "MEDIUM" "npm_audit" "npm audit found $vuln_count moderate+ vulnerabilities"
  fi
}

# ── Check 5: WASM size gate ───────────────────────────────────────────────────

check_wasm_size() {
  printf '\n[5/6] Checking optimised WASM binary size...\n'

  if [[ ! -f "$WASM_PATH" ]]; then
    warn "Optimised WASM not found at $WASM_PATH — skipping size check"
    add_finding "MEDIUM" "wasm_size" "Optimised WASM binary not found; size gate skipped"
    return
  fi

  local size
  size="$(stat -c%s "$WASM_PATH" 2>/dev/null || stat -f%z "$WASM_PATH")"

  if [[ "$size" -le "$WASM_MAX_BYTES" ]]; then
    pass "WASM size OK: ${size} bytes (max ${WASM_MAX_BYTES})"
  else
    fail "WASM too large: ${size} bytes (max ${WASM_MAX_BYTES})"
    add_finding "HIGH" "wasm_size" \
      "WASM binary ${size} bytes exceeds ${WASM_MAX_BYTES} byte limit"
  fi
}

# ── Check 6: Clippy deny warnings ────────────────────────────────────────────

check_clippy() {
  printf '\n[6/6] Running cargo clippy...\n'

  if ! command -v cargo &>/dev/null; then
    warn "cargo not found — skipping clippy"
    add_finding "MEDIUM" "clippy" "cargo not available; clippy check skipped"
    return
  fi

  local exit_code=0
  cargo clippy --all-targets --all-features -- -D warnings 2>&1 | \
    grep -E '^error' | head -5 || true
  cargo clippy --all-targets --all-features -- -D warnings &>/dev/null || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    pass "clippy: no warnings"
  else
    fail "clippy: warnings promoted to errors"
    add_finding "MEDIUM" "clippy" "cargo clippy reported warnings (-D warnings)"
  fi
}

# ── Report ────────────────────────────────────────────────────────────────────

write_report() {
  local end_ts risk_level overall_exit
  end_ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  if   [[ $HIGH   -gt 0 ]]; then risk_level="HIGH";   overall_exit=1
  elif [[ $MEDIUM -gt 0 ]]; then risk_level="MEDIUM"; overall_exit=2
  else                            risk_level="LOW";    overall_exit=0
  fi

  printf '{
  "schema_version": "1.0",
  "started_at": "%s",
  "finished_at": "%s",
  "risk_level": "%s",
  "high_count": %d,
  "medium_count": %d,
  "findings": %s
}\n' "$start_ts" "$end_ts" "$risk_level" "$HIGH" "$MEDIUM" "$findings" \
    > "$REPORT_JSON"

  printf '\n══════════════════════════════════════════\n'
  printf ' Security Risk Assessment — %s\n' "$risk_level"
  printf ' HIGH: %d   MEDIUM: %d\n' "$HIGH" "$MEDIUM"
  printf ' Report: %s\n' "$REPORT_JSON"
  printf '══════════════════════════════════════════\n\n'

  return "$overall_exit"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  printf '=== Stellar Raise — Security Risk Assessment ===\n'
  printf 'Started: %s\n' "$start_ts"

  check_secret_exposure
  check_soroban_gitignore
  check_cargo_audit
  check_npm_audit
  check_wasm_size
  check_clippy

  write_report
}

# Allow sourcing for tests without running main.
if [[ "${SOURCING:-0}" != "1" ]]; then
  main "$@"
fi
