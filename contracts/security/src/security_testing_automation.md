# Security Testing Automation

> **Module:** `contracts/security/src/security_testing_automation.rs`
> **Tests:** `contracts/security/src/security_testing_automation.test.rs`
> **Issue:** #1047 — Automated Security Testing Automation

---

## Threat Model

The Stellar Raise crowdfunding DApp operates on the Soroban smart-contract
platform. The following actors and threat vectors are in scope.

### Actors

| Actor | Trust Level | Capabilities |
|---|---|---|
| Campaign Creator | Semi-trusted | Initialize, withdraw, cancel, update metadata |
| Contributor | Untrusted | Contribute, refund_single, pledge |
| Admin | Trusted (but misconfiguration possible) | Upgrade contract WASM |
| Platform | Trusted (but fee misconfiguration possible) | Receive platform fee |
| Automated Bot | Untrusted | Call any permissionless function (finalize, audit) |

### Threat Vectors

| ID | Threat | Mitigation |
|---|---|---|
| T-01 | **Zero-value contribution** — attacker calls `contribute(amount=0)` to manipulate state without transferring tokens | `ContractError::ZeroAmount` guard + `probe_contribution_amount` check |
| T-02 | **Negative-value contribution** — attacker passes `amount < 0` to inflate `TotalRaised` | `ContractError::NegativeAmount` guard + `probe_contribution_amount` check |
| T-03 | **Unauthorized withdrawal** — non-creator calls `withdraw()` | `creator.require_auth()` + `probe_withdraw_authorization` check |
| T-04 | **Post-deadline contribution** — attacker contributes after deadline to inflate totals | Deadline guard in `contribute()` + `check_contribution_within_deadline` |
| T-05 | **State-machine bypass** — attacker attempts `Expired → Active` transition | `check_valid_status_transition` rejects all non-`Active` source states |
| T-06 | **Re-initialization** — attacker calls `initialize()` on an already-active campaign | `ContractError::AlreadyInitialized` guard |
| T-07 | **Accounting invariant violation** — `TotalRaised` drifts from sum of contributions | `check_total_raised_equals_sum` invariant check |
| T-08 | **Integer overflow** — large contributions overflow `TotalRaised` | `checked_add` in `contribute()` + overflow saturation in sum check |
| T-09 | **Storage expiration / rent** — persistent keys expire, causing silent data loss | TTL extension on every `Contribution(addr)` write; see Security Note below |
| T-10 | **Platform fee misconfiguration** — fee_bps set above 10 000 | `InvalidPlatformFee` guard at initialization |

---

## Security Assumptions

1. **The admin is trusted, but the contract must still prevent accidental
   misconfigurations.** The upgrade function validates the WASM hash is
   non-zero before executing. A zero hash would brick the contract.

2. **The Soroban host enforces `require_auth()`.** All authorization checks
   in this module are defence-in-depth identity checks that run *before* the
   host-level auth enforcement.

3. **Token transfers are atomic.** The SEP-41 token contract either transfers
   the full amount or reverts. There is no partial-transfer risk.

4. **`i128` arithmetic is exact.** Soroban uses integer arithmetic with no
   floating-point rounding. The precision-loss tests confirm this assumption.

5. **The contributor list is bounded.** `contract_state_size` enforces a
   maximum contributor count to prevent unbounded iteration in `cancel()`.

6. **Storage TTL is managed explicitly.** Every persistent key write is
   followed by `extend_ttl(100, 100)`. Monitoring bots should alert if any
   key's TTL drops below the minimum threshold.

---

## Security Notes (Soroban-Specific Pitfalls)

### Storage Expiration / Rent

Soroban charges rent for persistent storage. Keys that are not accessed for
a long time will expire and return `None` on the next read. The contract
mitigates this by calling `extend_ttl` after every write to
`DataKey::Contribution(addr)`. Monitoring bots should:

1. Periodically call `contribution(addr)` for all known contributors to
   bump TTL.
2. Alert if `total_raised()` returns a value inconsistent with the sum of
   known contributions (which would indicate expired keys).

### Reentrancy-Like Patterns (State-Order Violations)

Soroban does not have traditional reentrancy (no mid-execution callbacks),
but state-order violations are still possible. The contract follows the
**checks-effects-interactions** pattern:

1. **Check** — validate status, deadline, amount, auth.
2. **Effect** — update storage (`TotalRaised`, `Contribution`).
3. **Interact** — call the token contract (`transfer`).

The `check_total_raised_equals_sum` invariant detects any deviation from
this pattern in post-execution audits.

### Upgrade Safety

- Only the admin (set to the creator at initialization) can call `upgrade()`.
- The zero-hash guard prevents accidental bricking.
- All storage and state persist across upgrades.
- **Recommendation:** Require two reviewers to approve upgrade PRs and run
  the full security test suite against the new WASM before merging.

---

## How to Add a New Security Rule

1. **Define the check** in `security_testing_automation.rs`:

   ```rust
   /// @notice  One-line description of what the check verifies.
   /// @dev     Technical assumption or storage key being checked.
   /// @custom:security-note  What exploit this prevents.
   pub fn check_my_new_rule(value: i128) -> InvariantResult {
       if value > 0 {
           InvariantResult::Passed
       } else {
           InvariantResult::Failed("MY RULE VIOLATION: value must be positive")
       }
   }
   ```

2. **Add it to `run_security_audit`** if it should run in the aggregate:

   ```rust
   ("my_new_rule", check_my_new_rule(some_value)),
   ```

3. **Write tests** in `security_testing_automation.test.rs`:

   ```rust
   #[test]
   fn test_my_new_rule_pass() {
       assert_eq!(check_my_new_rule(1), InvariantResult::Passed);
   }

   #[test]
   fn test_my_new_rule_fail() {
       let result = check_my_new_rule(0);
       assert!(!result.is_passed());
       assert!(result.message().contains("MY RULE VIOLATION"));
   }
   ```

4. **Run the suite** and confirm coverage:

   ```bash
   cargo test -p security
   ```

5. **Update this document** — add a row to the Threat Model table and a
   Security Assumption if applicable.

---

## Running the Tests

```bash
# Run all security tests
cargo test -p security

# Run with output (see Security Notes in test output)
cargo test -p security -- --nocapture

# Run only property-based tests
cargo test -p security prop_

# Run a specific test
cargo test -p security test_transition_expired_to_active_fail
```
