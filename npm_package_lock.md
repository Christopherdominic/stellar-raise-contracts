# NPM package-lock.json Minor Vulnerabilities — Documentation

## Summary

This update resolves two vulnerabilities found by `npm audit` and updates the
`npm_package_lock.rs` auditor module to track all three known advisories.

## Vulnerabilities Fixed (2026-03)

| Package | Advisory | Severity | Vulnerable range | Fixed in |
|---------|----------|----------|-----------------|----------|
| `brace-expansion` | [GHSA-f886-m6hf-6m8v](https://github.com/advisories/GHSA-f886-m6hf-6m8v) | Moderate | `<1.1.13` or `>=2.0.0 <2.0.3` | `2.0.3` |
| `handlebars` | [GHSA-xjpj-3mr7-gcpf](https://github.com/advisories/GHSA-xjpj-3mr7-gcpf) + related | Critical | `4.0.0 - 4.7.8` | `4.7.9` |

`svgo` was already at `3.3.3` (patched for GHSA-xpqw-6gx7-v673).

### brace-expansion — GHSA-f886-m6hf-6m8v

A zero-step sequence (e.g. `{0..0}`) causes the parser to enter an infinite
loop, exhausting memory and hanging the process. CWE-400 (Uncontrolled Resource
Consumption). CVSS 6.5 (Moderate).

### handlebars — GHSA-xjpj-3mr7-gcpf and related

Multiple JavaScript injection vulnerabilities via AST type confusion, unescaped
names in the CLI precompiler, and prototype pollution through partial template
injection. All fixed in 4.7.9.

---

## How the Fix Was Applied

```bash
npm install --package-lock-only   # regenerate lockfile
npm audit fix                     # resolve vulnerable transitive deps
# Result: 0 vulnerabilities, 3 packages changed
```

The fix updates transitive dependencies in `package-lock.json` only — no
direct dependency versions in `package.json` were changed.

---

## Auditor Module Changes (`npm_package_lock.rs`)

### New: `MAX_PACKAGES` constant

```rust
pub const MAX_PACKAGES: usize = 500;
```

Hard cap for `audit_all_bounded` to prevent unbounded processing.

### New: `default_min_safe_versions()`

Returns the canonical advisory map including all three known advisories.
Update this function whenever a new advisory is published.

### New: `audit_all_bounded()`

Bounded variant of `audit_all` that rejects inputs exceeding `MAX_PACKAGES`.
Use this wherever input size is not statically known.

---

## Security Assumptions

- `package-lock.json` is committed to version control and reviewed on every PR.
- `npm audit` is run in CI on every push (see `.github/workflows/`).
- Only `lockfileVersion` 2 and 3 are accepted (npm >=7).
- Integrity hashes (`sha512-`) are validated to be non-empty.
- The `default_min_safe_versions()` map must be kept up to date as new
  advisories are published.

---

## Test Coverage

New tests in `npm_package_lock.test.rs` (`advisory_update_tests` module):

| Test | Verifies |
|------|---------|
| `test_default_map_contains_brace_expansion` | Advisory map has brace-expansion entry |
| `test_default_map_contains_handlebars` | Advisory map has handlebars entry |
| `test_brace_expansion_vulnerable_2_0_2_fails` | 2.0.2 detected as vulnerable |
| `test_brace_expansion_patched_2_0_3_passes` | 2.0.3 passes |
| `test_handlebars_vulnerable_4_7_8_fails` | 4.7.8 detected as vulnerable |
| `test_handlebars_patched_4_7_9_passes` | 4.7.9 passes |
| `test_full_snapshot_all_patched_passes` | All three patched versions pass together |
| `test_full_snapshot_all_vulnerable_fails` | All three vulnerable versions fail together |
| `test_bounded_one_over_limit_err` | MAX_PACKAGES cap enforced |
