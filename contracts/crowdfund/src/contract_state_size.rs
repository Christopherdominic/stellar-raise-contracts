//! Contract State Size Limits
//!
//! @title   ContractStateSize — On-chain size-limit constants and enforcement helpers.
//! @notice  Defines upper bounds for every unbounded collection and user-supplied
//!          string stored in the crowdfund contract's ledger state.
//! @dev     All `check_*` helpers follow a checks-before-effects pattern: they
//!          read current state and return a typed `StateSizeError` **before** any
//!          mutation occurs in the calling function.
//!
//! ## Security Rationale
//!
//! Without these limits an adversary could:
//! - Flood `Contributors` / `Pledgers` until iteration in `withdraw` / `refund` /
//!   `collect_pledges` exceeds Soroban's per-transaction resource budget.
//! - Supply oversized `String` values that push a ledger entry past the host's
//!   hard serialisation cap, causing a host panic.
//!
//! ## Limits
//!
//! | Constant            | Value | Applies to                                      |
//! |---------------------|-------|-------------------------------------------------|
//! | `MAX_CONTRIBUTORS`  |   128 | `Contributors` list, `Pledgers` list            |
//! | `MAX_ROADMAP_ITEMS` |    32 | `Roadmap` list (`add_roadmap_item`)             |
//! | `MAX_STRETCH_GOALS` |    32 | `StretchGoals` list (`add_stretch_goal`)        |
//! | `MAX_STRING_LEN`    |   256 | title, description, social links, roadmap desc  |

use soroban_sdk::{contract, contractimpl, contracterror, Env, String, Vec};

// ── Error type ────────────────────────────────────────────────────────────────

/// Typed errors returned by state-size enforcement helpers.
///
/// @dev Discriminants start at 100 to avoid collisions with `ContractError` (1–17).
///      Do **not** renumber these — they are stable across contract upgrades.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StateSizeError {
    /// The `Contributors` or `Pledgers` list has reached `MAX_CONTRIBUTORS`.
    ContributorLimitExceeded = 100,
    /// The `Roadmap` list has reached `MAX_ROADMAP_ITEMS`.
    RoadmapLimitExceeded = 101,
    /// The `StretchGoals` list has reached `MAX_STRETCH_GOALS`.
    StretchGoalLimitExceeded = 102,
    /// A string field exceeds `MAX_STRING_LEN` bytes.
    StringTooLong = 103,
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of unique contributors (and pledgers) tracked per campaign.
pub const MAX_CONTRIBUTORS: u32 = 128;

/// Maximum number of roadmap milestones stored per campaign.
pub const MAX_ROADMAP_ITEMS: u32 = 32;

/// Maximum number of stretch-goal milestones stored per campaign.
pub const MAX_STRETCH_GOALS: u32 = 32;

/// Maximum byte length for any user-supplied string field.
pub const MAX_STRING_LEN: u32 = 256;

// ── Standalone helpers (called from lib.rs) ───────────────────────────────────

/// Returns `Ok(())` if `s.len() <= MAX_STRING_LEN`, else `Err(StateSizeError::StringTooLong)`.
#[inline]
pub fn check_string_len(s: &String) -> Result<(), StateSizeError> {
    if s.len() > MAX_STRING_LEN {
        Err(StateSizeError::StringTooLong)
    } else {
        Ok(())
    }
}

/// Returns `Ok(())` if `count < MAX_CONTRIBUTORS`, else `Err(ContributorLimitExceeded)`.
#[inline]
pub fn validate_contributor_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_CONTRIBUTORS {
        Err(StateSizeError::ContributorLimitExceeded)
    } else {
        Ok(())
    }
}

/// Reads the `Contributors` list length from persistent storage and enforces the cap.
#[inline]
pub fn check_contributor_limit(env: &Env) -> Result<(), StateSizeError> {
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<soroban_sdk::Address>>(&crate::DataKey::Contributors)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_contributor_capacity(count)
}

/// Returns `Ok(())` if `count < MAX_CONTRIBUTORS`, else `Err(ContributorLimitExceeded)`.
#[inline]
pub fn validate_pledger_capacity(count: u32) -> Result<(), StateSizeError> {
    validate_contributor_capacity(count)
}

/// Reads the `Pledgers` list length from persistent storage and enforces the cap.
#[inline]
pub fn check_pledger_limit(env: &Env) -> Result<(), StateSizeError> {
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<soroban_sdk::Address>>(&crate::DataKey::Pledgers)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_contributor_capacity(count)
}

/// Returns `Ok(())` if `count < MAX_ROADMAP_ITEMS`, else `Err(RoadmapLimitExceeded)`.
#[inline]
pub fn validate_roadmap_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_ROADMAP_ITEMS {
        Err(StateSizeError::RoadmapLimitExceeded)
    } else {
        Ok(())
    }
}

/// Reads the `Roadmap` list length from instance storage and enforces the cap.
#[inline]
pub fn check_roadmap_limit(env: &Env) -> Result<(), StateSizeError> {
    let count: u32 = env
        .storage()
        .instance()
        .get::<_, Vec<crate::RoadmapItem>>(&crate::DataKey::Roadmap)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_roadmap_capacity(count)
}

/// Validates a roadmap item description length (delegates to `check_string_len`).
#[inline]
pub fn validate_roadmap_description(desc: &String) -> Result<(), StateSizeError> {
    check_string_len(desc)
}

/// Returns `Ok(())` if `count < MAX_STRETCH_GOALS`, else `Err(StretchGoalLimitExceeded)`.
#[inline]
pub fn validate_stretch_goal_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_STRETCH_GOALS {
        Err(StateSizeError::StretchGoalLimitExceeded)
    } else {
        Ok(())
    }
}

/// Reads the `StretchGoals` list length from instance storage and enforces the cap.
#[inline]
pub fn check_stretch_goal_limit(env: &Env) -> Result<(), StateSizeError> {
    let count: u32 = env
        .storage()
        .instance()
        .get::<_, Vec<i128>>(&crate::DataKey::StretchGoals)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_stretch_goal_capacity(count)
}

/// Validates a title string length.
#[inline]
pub fn validate_title(title: &String) -> Result<(), StateSizeError> {
    check_string_len(title)
}

/// Validates a description string length.
#[inline]
pub fn validate_description(desc: &String) -> Result<(), StateSizeError> {
    check_string_len(desc)
}

/// Validates a social-links string length.
#[inline]
pub fn validate_social_links(links: &String) -> Result<(), StateSizeError> {
    check_string_len(links)
}

/// Validates the aggregate metadata length across title, description, and social links.
///
/// @param title_len       Byte length of the title field.
/// @param description_len Byte length of the description field.
/// @param socials_len     Byte length of the social-links field.
/// @return `Ok(())` if the sum is within the aggregate limit.
#[inline]
pub fn validate_metadata_total_length(
    title_len: u32,
    description_len: u32,
    socials_len: u32,
) -> Result<(), StateSizeError> {
    const AGGREGATE_LIMIT: u32 = MAX_STRING_LEN * 3;
    if title_len.saturating_add(description_len).saturating_add(socials_len) > AGGREGATE_LIMIT {
        Err(StateSizeError::StringTooLong)
    } else {
        Ok(())
    }
}

// ── Standalone contract (exposes constants on-chain) ─────────────────────────

/// On-chain contract that exposes state-size constants and validation functions.
///
/// @notice Frontend UIs can call these view functions to retrieve the current
///         limits without hard-coding them, ensuring UI validation stays in sync
///         with the contract after upgrades.
#[contract]
pub struct ContractStateSize;

#[contractimpl]
impl ContractStateSize {
    /// Returns the maximum allowed byte length for any string field.
    pub fn max_string_len(_env: Env) -> u32 {
        MAX_STRING_LEN
    }

    /// Returns the maximum number of contributors per campaign.
    pub fn max_contributors(_env: Env) -> u32 {
        MAX_CONTRIBUTORS
    }

    /// Returns the maximum number of roadmap items.
    pub fn max_roadmap_items(_env: Env) -> u32 {
        MAX_ROADMAP_ITEMS
    }

    /// Returns the maximum number of stretch goals.
    pub fn max_stretch_goals(_env: Env) -> u32 {
        MAX_STRETCH_GOALS
    }

    /// Returns `true` if `s.len() <= MAX_STRING_LEN`.
    pub fn validate_string(_env: Env, s: String) -> bool {
        s.len() <= MAX_STRING_LEN
    }
}
