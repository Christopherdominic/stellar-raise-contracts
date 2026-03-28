# `cargo_toml_rust` — Cargo.toml-style dependency policy for CI/CD

This module is a **Soroban contract** that models dependency governance (approved crates, security policy, compliance rules) with **explicit logging bounds** so CI outputs and on-chain work stay predictable.

## Purpose

- Centralize **pinned SDK / dev-dependency versions** (`SOROBAN_SDK_VERSION`, `PROPTEST_VERSION`) for documentation parity with real `Cargo.toml` files.
- Enforce **security policy** (max risk level, blocked crates, licenses) and **compliance rules** analogous to CI checks.
- Cap **list sizes and string lengths** so scans and stored data cannot grow without bound (gas / log-style DoS resistance).

## Logging bounds (summary)

| Constant | Role |
|----------|------|
| `MAX_COMPLIANCE_RULES` | Max stored compliance rules; bounds `run_compliance_check` iteration. |
| `MAX_APPROVED_DEPENDENCIES` | Max approved dependency records. |
| `MAX_BLOCKED_CRATES` | Max entries in `SecurityPolicy::blocked_crates`. |
| `MAX_ALLOWED_LICENSES` | Max entries in `SecurityPolicy::allowed_licenses`. |
| `MAX_COMPLIANCE_RULE_SHORT_FIELD_BYTES` | `rule_name`, `check_type`, `severity` UTF-8 length. |
| `MAX_COMPLIANCE_DESCRIPTION_BYTES` | `description` UTF-8 length. |
| `MAX_CRATE_NAME_BYTES` / `MAX_VERSION_STRING_BYTES` | Dependency identity strings. |
| `MAX_LICENSE_STRING_BYTES` | Each allowed license string. |
| `MAX_CI_COMPLIANCE_MESSAGE_BYTES` | Per-row message size from `run_compliance_check`. |

Pure helpers (`ci_string_within_bounds`, `validate_*`) allow **off-chain CI** or other Rust tools to reuse the same limits without deploying the contract.

## Security assumptions

1. **Bounds are enforcement, not cryptography** — They reduce unbounded iteration and oversized strings; they do not replace audit of real `Cargo.toml` / lockfiles.
2. **Defaults must satisfy bounds** — `initialize` validates built-in policy and rules; a failed invariant panics at deploy/init (fail-fast).
3. **Instance storage** — Callers must run contract logic under the correct Soroban contract frame (`env.as_contract` in tests; real invocations via the contract address).
4. **Trust model** — Anyone who can invoke mutating entrypoints controls policy; this module is suited to **test / demo / internal tooling** governance, not permissionless multi-tenant admin without access control at a higher layer.

## Testing

Run the dedicated test module:

```bash
cargo test -p crowdfund --lib cargo_toml_rust
```

Integration tests use `with_cargo_contract` so instance storage matches Soroban SDK 22 expectations.

## CI suggestion

Add the command above to your pipeline next to `cargo fmt`, `cargo clippy`, and `cargo test` for the workspace so **logging-bound regressions** fail the build.
