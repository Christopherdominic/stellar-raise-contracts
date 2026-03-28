# github_actions_test.sh

Validates GitHub Actions workflow files for correctness, speed, and security.
All magic strings and numeric thresholds are extracted into named `readonly`
constants at the top of the script — change once, affects every check.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/github_actions_test.sh` | Validator (12 checks) |
| `scripts/github_actions_test.test.sh` | Test suite (22 tests) |

```bash
# Run from repo root
bash scripts/github_actions_test.sh
bash scripts/github_actions_test.test.sh

# Verbose test output
VERBOSE=1 bash scripts/github_actions_test.test.sh
```

## Constants reference

All constants are declared `readonly` at the top of `github_actions_test.sh`.

### Path constants

| Constant | Value | Purpose |
|---|---|---|
| `WORKFLOWS_DIR` | `.github/workflows` | Root directory for all workflow YAML files |
| `RUST_CI_YML` | `$WORKFLOWS_DIR/rust_ci.yml` | Main Rust CI workflow |
| `SMOKE_YML` | `$WORKFLOWS_DIR/testnet_smoke.yml` | Testnet smoke-test workflow |
| `SPELLCHECK_YML` | `$WORKFLOWS_DIR/spellcheck.yml` | Spellcheck workflow |
| `REQUIRED_WORKFLOW_FILES` | array of the three above | Files checked in Check 1 |

### Versioning constants

| Constant | Value | Purpose |
|---|---|---|
| `CHECKOUT_BANNED_VERSION` | `actions/checkout@v6` | Non-existent version that must not appear (Check 2) |
| `RUST_CACHE_ACTION` | `Swatinem/rust-cache` | Required caching action (Check 9) |

### Build configuration constants

| Constant | Value | Purpose |
|---|---|---|
| `WASM_BUILD_PATTERN` | `cargo build --release --target wasm32-unknown-unknown` | Detects duplicate build steps (Check 3) |
| `WASM_SCOPE_PATTERN` | `cargo build.*-p crowdfund` | Confirms build is scoped (Check 6) |
| `WASM_OPT_TOOL` | `wasm-opt` | Required optimisation tool (Check 12) |
| `MAX_WASM_BUILD_STEPS` | `1` | Maximum allowed WASM build steps (Check 3) |

### CLI tooling constants

| Constant | Value | Purpose |
|---|---|---|
| `DEPRECATED_CLI` | `soroban-cli` | Deprecated CLI that must not appear (Check 7) |
| `REQUIRED_ADMIN_FLAG` | `--admin` | Required initialize argument (Check 5) |

### Contract function constants

| Constant | Value | Purpose |
|---|---|---|
| `BANNED_CONTRACT_FUNCTIONS` | `is_initialized`, `get_campaign_info`, `get_stats` | Non-existent ABI functions (Check 4) |

### Security constants

| Constant | Value | Purpose |
|---|---|---|
| `LEAST_PRIVILEGE_PERM` | `contents: read` | Required permissions declaration (Check 11) |

### Performance threshold constants

| Constant | Value | Purpose |
|---|---|---|
| `TIMEOUT_PATTERN` | `timeout-minutes:` | Confirms timeout bound exists (Check 10) |
| `ELAPSED_TIME_PATTERN` | `elapsed\|JOB_START` | Confirms elapsed-time logging exists (Check 10) |
| `FRONTEND_JOB_PATTERN` | `^  frontend:` | Confirms frontend job exists (Check 8) |

### Exit code constants

| Constant | Value | Purpose |
|---|---|---|
| `EXIT_PASS` | `0` | All checks passed |
| `EXIT_FAIL` | `1` | One or more checks failed |
| `TOTAL_CHECKS` | `12` | Total checks performed |

## Checks

### Check 1 — Required workflow files exist and are non-empty
Missing or empty workflow files silently disable CI jobs with no error message.

### Check 2 — No workflow references `actions/checkout@v6`
`actions/checkout@v6` does not exist. Any reference blocks CI at the checkout
step. A non-existent version could also be registered by a malicious actor.

### Check 3 — No duplicate WASM build step in `rust_ci.yml`
Building the WASM binary twice compiles identical artifacts and wastes 60–90 s
of CI time per run. Controlled by `MAX_WASM_BUILD_STEPS=1`.

### Check 4 — Smoke test does not call non-existent contract functions
`is_initialized`, `get_campaign_info`, and `get_stats` are not in the crowdfund
ABI. Calling them causes confusing on-chain errors. Controlled by
`BANNED_CONTRACT_FUNCTIONS`.

### Check 5 — Smoke test `initialize` includes `--admin`
The crowdfund `initialize` entry point requires `--admin`. Omitting it causes
on-chain rejection. Controlled by `REQUIRED_ADMIN_FLAG`.

### Check 6 — Smoke test WASM build scoped to `-p crowdfund`
A full workspace build compiles unnecessary crates and is 2–4x slower.
Controlled by `WASM_SCOPE_PATTERN`.

### Check 7 — Smoke test uses `stellar-cli`, not `soroban-cli`
`soroban-cli` is unmaintained and may contain unpatched vulnerabilities.
Controlled by `DEPRECATED_CLI`.

### Check 8 — `rust_ci.yml` includes a `frontend` job
Without a frontend job, Jest tests never run in CI. The frontend job runs in
parallel — zero added wall-clock time. Controlled by `FRONTEND_JOB_PATTERN`.

### Check 9 — `rust_ci.yml` uses `Swatinem/rust-cache`
Without caching, every run re-downloads all Rust dependencies. `rust-cache`
reduces cold-build time by 60–80%. Controlled by `RUST_CACHE_ACTION`.

### Check 10 — `rust_ci.yml` has `timeout-minutes` and elapsed-time logging
Without a timeout, a hung build can block a runner for up to 6 hours.
Elapsed-time logging surfaces slow steps for future optimisation.
Controlled by `TIMEOUT_PATTERN` and `ELAPSED_TIME_PATTERN`.

### Check 11 — `testnet_smoke.yml` has least-privilege permissions
The smoke test only needs read access. `permissions: contents: read` prevents
a compromised job from pushing commits. Controlled by `LEAST_PRIVILEGE_PERM`.

### Check 12 — `rust_ci.yml` includes a `wasm-opt` step
Raw rustc WASM is not size-optimised. `wasm-opt -Oz` reduces binary size by
20–40%, lowering Stellar deployment fees. Controlled by `WASM_OPT_TOOL`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed |
| 1 | One or more checks failed |

## Security assumptions

- The validator reads workflow files only — never writes or executes them.
- No secrets or credentials are accessed.
- `set -euo pipefail` ensures unset variables and pipeline errors are fatal.
- All `grep` calls use `--` to prevent flag injection from filenames.
- Extracting constants prevents silent drift: updating `CHECKOUT_BANNED_VERSION`
  or `DEPRECATED_CLI` in one place updates every check that uses them.

## Test coverage

22 tests across 12 checks:

| Test | Scenario |
|---|---|
| 1 | Real repo passes all 12 checks (happy path) |
| 2 | `spellcheck.yml` missing |
| 3 | Workflow file empty (zero bytes) |
| 4 | Whitespace-only file passes Check 1 (documents behaviour) |
| 5 | `checkout@v6` in `rust_ci.yml` |
| 6 | `checkout@v6` in `testnet_smoke.yml` |
| 7 | Duplicate WASM build steps |
| 8 | Smoke test calls `is_initialized` |
| 9 | Smoke test calls `get_campaign_info` |
| 10 | Smoke test calls `get_stats` |
| 11 | `initialize` missing `--admin` |
| 12 | WASM build missing `-p crowdfund` |
| 13 | Deprecated `soroban-cli` present |
| 14 | `frontend` job missing |
| 15 | `Swatinem/rust-cache` missing |
| 16 | `timeout-minutes` missing |
| 17 | Elapsed-time logging missing |
| 18 | Least-privilege permissions missing |
| 19 | `wasm-opt` step missing |
| 20 | `rust_ci.yml` missing entirely |
| 21 | `testnet_smoke.yml` missing entirely |
| 22 | Multiple simultaneous failures all reported (no short-circuit) |

## What changed in this branch

| File | Change |
|---|---|
| `scripts/github_actions_test.sh` | Extracted all magic strings and numeric thresholds into named `readonly` constants; grouped into sections (paths, versioning, build config, CLI tooling, contract functions, security, performance, exit codes); updated all checks to reference constants; bumped to v4.0.0 |
| `scripts/github_actions_test.test.sh` | Rewrote fixture harness with `make_tmp` + `TMPDIRS` array for reliable cleanup; added tests 17 (elapsed logging), 22 (multi-failure); aligned all 22 tests with constant-driven checks; bumped to v4.0.0 |
| `scripts/github_actions_test.md` | Full constants reference table; updated check descriptions to reference constant names |
