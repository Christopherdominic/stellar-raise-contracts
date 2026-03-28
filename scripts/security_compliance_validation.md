# Security Compliance Validation

> **Script:** `scripts/security_compliance_validation.sh`
> **Tests:** `scripts/security_compliance_validation.test.sh`
> **Workflow:** `.github/workflows/security.yml`
> **Issue:** #1050 — Automated Security Compliance Validation for CI/CD

---

## Compliance Baseline

| Requirement | Minimum Version | Notes |
|---|---|---|
| Rust (stable) | 1.74 | `rustup update stable` |
| soroban-sdk | 22.0.0 | Required for `extend_ttl` API |
| cargo-audit | latest | `cargo install cargo-audit` |
| wasm-opt (Binaryen) | any | `apt-get install binaryen` |
| WASM binary size | ≤ 256 KB (optimised) | Stellar network deployment limit |

---

## Exit Code Policy

| Code | Meaning | CI Action |
|---|---|---|
| `0` | All checks passed | PR may be merged |
| `1` | One or more security checks failed | PR is blocked |
| `2` | Required tooling is missing | PR is blocked; install tools and re-run |

---

## Checks Performed

### 1. Static Analysis (`cargo clippy`)

Runs clippy with the following deny flags:

- `-D warnings` — every warning is an error
- `-D clippy::unwrap_used` — forbids `unwrap()` in production code
- `-D clippy::expect_used` — forbids `expect()` in production code
- `-D clippy::panic` — forbids `panic!()` in production code

**Why:** `unwrap()`/`panic!()` in Soroban contracts cause unrecoverable aborts
that are indistinguishable from legitimate errors on-chain.

### 2. Vulnerability Scanning (`cargo audit`)

Checks the dependency tree against the [RustSec advisory database](https://rustsec.org/).

**Why:** A single unpatched critical advisory in a dependency can expose the
contract to fund-draining exploits.

### 3. Build-Time Invariants

- Compiles the contract to WASM with `--release` optimisations.
- Runs `wasm-opt -Oz` and asserts the output is ≤ 256 KB.

**Why:** An oversized WASM is silently rejected by the Stellar network at
deployment time. Catching it in CI prevents wasted deploy cycles.

### 4. Storage Rent Audit

- Verifies `soroban-sdk >= 22.0.0` (ships with the `extend_ttl` API).
- Counts `extend_ttl` calls in the contract source.

**Why:** A contract whose instance storage expires becomes permanently
inaccessible. Contributors would lose their funds with no recourse.

---

## Allow-listing False Positives

If `cargo audit` reports an advisory that does not affect this project, add it
to `.security-allowlist` in the repository root:

```
# .security-allowlist
# Format: <ADVISORY-ID>  # <reason it is safe to ignore>

# RUSTSEC-2023-0001 — only affects async runtime; this project is sync-only
RUSTSEC-2023-0001
```

**Rules for allow-listing:**

1. Every entry must have a comment explaining why it is safe to ignore.
2. The entry must be reviewed and re-justified on every dependency update.
3. Allow-list entries must be approved by at least one reviewer in the PR.
4. Remove the entry as soon as a patched version of the dependency is available.

---

## Running Locally

```bash
# Install tools
cargo install cargo-audit
sudo apt-get install binaryen   # or brew install binaryen on macOS

# Run the full validation
chmod +x scripts/security_compliance_validation.sh
./scripts/security_compliance_validation.sh

# Run the test suite
chmod +x scripts/security_compliance_validation.test.sh
./scripts/security_compliance_validation.test.sh
```

---

## CI Integration

The `security.yml` workflow runs on every push and pull request to `main` and
`develop`. It blocks merging if the validation script exits with a non-zero
code.

To add a new check to the pipeline:

1. Add a `check_*` function to `security_compliance_validation.sh`.
2. Call it from `main()`.
3. Add a corresponding test in `security_compliance_validation.test.sh`.
4. Update this document.
