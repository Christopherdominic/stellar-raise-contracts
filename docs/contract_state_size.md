# Contract State Size Limits

## Overview

The `contract_state_size` module enforces upper-bound limits on every
unbounded collection and user-supplied string stored in the crowdfund
contract's ledger state.

Without these limits an adversary could:

- Flood the `Contributors` or `Pledgers` list until `withdraw` / `refund` /
  `collect_pledges` iterations exceed Soroban's per-transaction resource budget.
- Supply oversized `String` values that push a ledger entry past the host's
  hard serialisation cap, causing a host panic.

---

## Limits

| Constant            | Value | Applies to                                                  |
|---------------------|-------|-------------------------------------------------------------|
| `MAX_CONTRIBUTORS`  |   128 | `Contributors` list (`contribute`), `Pledgers` list (`pledge`) |
| `MAX_ROADMAP_ITEMS` |    32 | `Roadmap` list (`add_roadmap_item`)                         |
| `MAX_STRETCH_GOALS` |    32 | `StretchGoals` list (`add_stretch_goal`)                    |
| `MAX_STRING_LEN`    |   256 | title, description, social links, roadmap description       |

### Rationale

**`MAX_CONTRIBUTORS = 128`**
The `cancel` function iterates over every contributor to issue refunds in a
single transaction. Keeping the list at ≤ 128 entries ensures the iteration
stays within Soroban's instruction budget. The `MAX_NFT_MINT_BATCH = 50` cap
in `withdraw` provides an additional safety layer for NFT minting.

**`MAX_ROADMAP_ITEMS = 32`**
The roadmap is stored in instance storage (loaded on every invocation).
32 items is generous for any realistic campaign roadmap while keeping the
instance entry well below the ledger entry size limit.

**`MAX_STRETCH_GOALS = 32`**
Stretch goals are also in instance storage and iterated in `current_milestone`.
32 entries is more than sufficient for any realistic campaign.

**`MAX_STRING_LEN = 256`**
Soroban's ledger entry size limit is 64 KiB. A single 256-byte string field
is negligible, but without a cap a malicious creator could supply a multi-KiB
description and exhaust the entry budget for other fields. The aggregate limit
across title + description + social links is `256 * 3 = 768` bytes.

---

## Error Codes

| Variant                    | Code | Meaning                                      |
|----------------------------|------|----------------------------------------------|
| `ContributorLimitExceeded` |  100 | Contributors / pledgers list is full         |
| `RoadmapLimitExceeded`     |  101 | Roadmap list is full                         |
| `StretchGoalLimitExceeded` |  102 | Stretch-goals list is full                   |
| `StringTooLong`            |  103 | A string field exceeds `MAX_STRING_LEN` bytes |

Error codes start at 100 to avoid collisions with `ContractError` (1–17).
**Do not renumber these** — they are stable across contract upgrades.

---

## Integration Points

Guards are called inside contract methods **before** any state mutation
(checks-before-effects pattern):

| Contract method    | Guard(s) called                                          |
|--------------------|----------------------------------------------------------|
| `contribute`       | `validate_contributor_capacity`, `check_contributor_limit` |
| `pledge`           | `validate_pledger_capacity`, `check_pledger_limit`       |
| `add_roadmap_item` | `check_string_len`, `check_roadmap_limit`, `validate_roadmap_capacity`, `validate_roadmap_description` |
| `add_stretch_goal` | `check_stretch_goal_limit`, `validate_stretch_goal_capacity` |
| `update_metadata`  | `validate_metadata_total_length`, `validate_title`, `validate_description`, `validate_social_links` |

---

## Security Assumptions

1. Limits are enforced on every write path; read paths are unaffected.
2. Existing entries that pre-date this module are not retroactively removed.
   If a list already exceeds a limit (e.g. after a migration), new entries
   are still rejected.
3. Limits can only be changed via a contract upgrade (admin-only).
4. The `StateSizeError` discriminants are stable across upgrades; do not
   renumber them.
5. `validate_metadata_total_length` uses saturating addition to prevent
   integer overflow when computing the aggregate length.

---

## Testing

Run the unit tests with:

```bash
cargo test --package crowdfund contract_state_size
```

The test suite (`contract_state_size_test.rs`) covers:

- Constant sanity checks — all four constants match their documented values.
- Error discriminant stability — codes 100–103 are verified.
- `check_string_len`: empty → `Ok`; at `MAX_STRING_LEN` → `Ok`; one over → `Err(StringTooLong)`; well over → `Err(StringTooLong)`.
- Pure capacity helpers (`validate_contributor_capacity`, `validate_pledger_capacity`, `validate_roadmap_capacity`, `validate_stretch_goal_capacity`): zero, one-below, at-limit, over-limit.
- `validate_metadata_total_length`: all-zero, at aggregate limit, one over aggregate limit.
- Storage-backed helpers (`check_contributor_limit`, `check_pledger_limit`, `check_roadmap_limit`, `check_stretch_goal_limit`): empty list, below max, at max, over max.
