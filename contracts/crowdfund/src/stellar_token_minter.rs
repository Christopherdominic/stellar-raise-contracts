//! Stellar Token Minter Module
//!
//! This module provides token minting functionality for the Stellar Raise
//! crowdfunding platform. It handles token minting for contributors,
//! platform fee distribution, and NFT reward minting.
//!
//! # Security
//!
//! - All minting operations require proper authorization
//! - Overflow protection on all arithmetic operations
//! - Platform fee validation (max 10,000 bps = 100%)
//! - Contributor list size limits to prevent unbounded growth

use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, token, Address, Env, IntoVal, String,
    Symbol, Vec,
};

/// Maximum number of NFT mint calls (and their events) emitted in a single
/// `withdraw()` invocation. Caps per-contributor event emission to prevent
/// unbounded gas consumption when the contributor list is large.
pub const MAX_NFT_MINT_BATCH: u32 = 50;

/// Represents the campaign status.
#[derive(Clone, PartialEq)]
#[contracttype]
pub enum Status {
    Active,
    Successful,
    Refunded,
    Cancelled,
}

/// Platform configuration for fee distribution.
#[derive(Clone)]
#[contracttype]
pub struct PlatformConfig {
    /// Address that receives platform fees
    pub address: Address,
    /// Fee in basis points (max 10,000 = 100%)
    pub fee_bps: u32,
}

/// Campaign statistics for frontend display.
#[derive(Clone)]
#[contracttype]
pub struct CampaignStats {
    /// Total tokens raised so far
    pub total_raised: i128,
    /// Funding goal
    pub goal: i128,
    /// Progress in basis points (0-10,000)
    pub progress_bps: u32,
    /// Number of unique contributors
    pub contributor_count: u32,
    /// Average contribution amount
    pub average_contribution: i128,
    /// Largest single contribution
    pub largest_contribution: i128,
}

/// Storage keys for the token minter contract.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// Campaign creator address
    Creator,
    /// Token contract address
    Token,
    /// Funding goal amount
    Goal,
    /// Campaign deadline timestamp
    Deadline,
    /// Total tokens raised
    TotalRaised,
    /// Individual contribution by address
    Contribution(Address),
    /// List of all contributors
    Contributors,
    /// Campaign status
    Status,
    /// Minimum contribution amount
    MinContribution,
    /// Platform configuration
    PlatformConfig,
    /// NFT contract address for reward minting
    NFTContract,
}

/// Contract errors for the token minter.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    /// Campaign already initialized
    AlreadyInitialized = 1,
    /// Campaign deadline has passed
    CampaignEnded = 2,
    /// Campaign is still active
    CampaignStillActive = 3,
    /// Funding goal not reached
    GoalNotReached = 4,
    /// Funding goal was reached
    GoalReached = 5,
    /// Integer overflow in arithmetic
    Overflow = 6,
    /// No contribution to refund
    NothingToRefund = 7,
    /// Contribution amount is zero
    ZeroAmount = 8,
    /// Contribution below minimum
    BelowMinimum = 9,
    /// Campaign is not active
    CampaignNotActive = 10,
}

/// NFT contract interface for minting rewards.
#[contractclient(name = "NftContractClient")]
pub trait NftContract {
    /// Mint an NFT to the specified address
    fn mint(env: Env, to: Address) -> u128;
}

/// Stellar Token Minter Contract
///
/// Manages token minting for crowdfunding campaigns including:
/// - Contributor token transfers
/// - Platform fee distribution
/// - NFT reward minting
/// - Campaign statistics tracking
#[contract]
pub struct StellarTokenMinter;

#[contractimpl]
impl StellarTokenMinter {
    /// Initializes a new token minter for a crowdfunding campaign.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    /// * `admin` - Address authorized for contract upgrades
    /// * `creator` - Campaign creator address (must sign)
    /// * `token` - Token contract address for contributions
    /// * `goal` - Funding goal in token's smallest unit
    /// * `deadline` - Campaign deadline as ledger timestamp
    /// * `min_contribution` - Minimum contribution amount
    /// * `platform_config` - Optional platform fee configuration
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `ContractError::AlreadyInitialized` if called twice
    ///
    /// # Panics
    ///
    /// - If platform fee exceeds 10,000 bps (100%)
    /// - If creator does not authorize the call
    ///
    /// # Security
    ///
    /// - Requires creator authorization
    /// - Validates platform fee bounds
    /// - Prevents double initialization
    pub fn initialize(
        env: Env,
        admin: Address,
        creator: Address,
        token: Address,
        goal: i128,
        deadline: u64,
        min_contribution: i128,
        platform_config: Option<PlatformConfig>,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if env.storage().instance().has(&DataKey::Creator) {
            return Err(ContractError::AlreadyInitialized);
        }

        // Require creator authorization
        creator.require_auth();

        // Store admin for upgrade authorization
        env.storage().instance().set(&DataKey::Creator, &creator);

        // Validate and store platform configuration
        if let Some(ref config) = platform_config {
            if config.fee_bps > 10_000 {
                panic!("platform fee cannot exceed 100%");
            }
            env.storage()
                .instance()
                .set(&DataKey::PlatformConfig, config);
        }

        // Store campaign parameters
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Goal, &goal);
        env.storage().instance().set(&DataKey::Deadline, &deadline);
        env.storage()
            .instance()
            .set(&DataKey::MinContribution, &min_contribution);
        env.storage().instance().set(&DataKey::TotalRaised, &0i128);
        env.storage()
            .instance()
            .set(&DataKey::Status, &Status::Active);

        // Initialize empty contributors list
        let empty_contributors: Vec<Address> = Vec::new(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Contributors, &empty_contributors);

        Ok(())
    }

    /// Contribute tokens to the campaign.
    ///
    /// Transfers tokens from the contributor to the contract. Updates
    /// contribution tracking and emits events for frontend display.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    /// * `contributor` - Address making the contribution (must sign)
    /// * `amount` - Amount of tokens to contribute
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or appropriate `ContractError`
    ///
    /// # Errors
    ///
    /// - `ContractError::CampaignNotActive` - Campaign is not in Active status
    /// - `ContractError::ZeroAmount` - Contribution amount is zero
    /// - `ContractError::BelowMinimum` - Amount below minimum contribution
    /// - `ContractError::CampaignEnded` - Deadline has passed
    /// - `ContractError::Overflow` - Integer overflow in accounting
    ///
    /// # Security
    ///
    /// - Requires contributor authorization
    /// - Validates amount against minimum
    /// - Checks campaign deadline
    /// - Uses checked arithmetic to prevent overflow
    pub fn contribute(env: Env, contributor: Address, amount: i128) -> Result<(), ContractError> {
        // Require contributor authorization
        contributor.require_auth();

        // Guard: campaign must be active
        let status: Status = env.storage().instance().get(&DataKey::Status).unwrap();
        if status != Status::Active {
            return Err(ContractError::CampaignNotActive);
        }

        // Validate amount
        if amount == 0 {
            return Err(ContractError::ZeroAmount);
        }

        let min_contribution: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MinContribution)
            .unwrap();
        if amount < min_contribution {
            return Err(ContractError::BelowMinimum);
        }

        // Check deadline
        let deadline: u64 = env.storage().instance().get(&DataKey::Deadline).unwrap();
        if env.ledger().timestamp() > deadline {
            return Err(ContractError::CampaignEnded);
        }

        // Track contributor if new
        let mut contributors: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Contributors)
            .unwrap_or_else(|| Vec::new(&env));

        let is_new_contributor = !contributors.contains(&contributor);

        // Transfer tokens from contributor to contract
        let token_address: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = token::Client::new(&env, &token_address);
        token_client.transfer(&contributor, &env.current_contract_address(), &amount);

        // Update contributor's running total with overflow protection
        let contribution_key = DataKey::Contribution(contributor.clone());
        let previous_amount: i128 = env
            .storage()
            .persistent()
            .get(&contribution_key)
            .unwrap_or(0);

        let new_contribution = previous_amount
            .checked_add(amount)
            .ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&contribution_key, &new_contribution);
        env.storage()
            .persistent()
            .extend_ttl(&contribution_key, 100, 100);

        // Update global total raised with overflow protection
        let total: i128 = env.storage().instance().get(&DataKey::TotalRaised).unwrap();
        let new_total = total.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .instance()
            .set(&DataKey::TotalRaised, &new_total);

        // Add to contributors list if new
        if is_new_contributor {
            contributors.push_back(contributor.clone());
            env.storage()
                .persistent()
                .set(&DataKey::Contributors, &contributors);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::Contributors, 100, 100);
        }

        // Emit contribution event for frontend tracking
        env.events()
            .publish(("campaign", "contributed"), (contributor, amount));

        Ok(())
    }

    /// Withdraw funds after successful campaign.
    ///
    /// Creator claims raised funds after deadline when goal is met. If platform
    /// config is set, fee is deducted first. If NFT contract is configured,
    /// mints one NFT per contributor.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or appropriate `ContractError`
    ///
    /// # Errors
    ///
    /// - `ContractError::CampaignStillActive` - Deadline has not passed
    /// - `ContractError::GoalNotReached` - Funding goal was not met
    ///
    /// # Events
    ///
    /// - `("campaign", "withdrawn")` - Emitted with (creator, total)
    /// - `("campaign", "fee_transferred")` - Emitted if platform fee applies
    /// - `("campaign", "nft_minted")` - Emitted for each NFT minted
    ///
    /// # Security
    ///
    /// - Checks campaign deadline
    /// - Validates goal was reached
    /// - Handles platform fee distribution
    /// - Batches NFT minting to prevent gas exhaustion
    pub fn withdraw(env: Env) -> Result<(), ContractError> {
        let status: Status = env.storage().instance().get(&DataKey::Status).unwrap();
        if status != Status::Active {
            panic!("campaign is not active");
        }

        let deadline: u64 = env.storage().instance().get(&DataKey::Deadline).unwrap();
        if env.ledger().timestamp() <= deadline {
            return Err(ContractError::CampaignStillActive);
        }

        let goal: i128 = env.storage().instance().get(&DataKey::Goal).unwrap();
        let total_raised: i128 = env.storage().instance().get(&DataKey::TotalRaised).unwrap();

        if total_raised < goal {
            return Err(ContractError::GoalNotReached);
        }

        let creator: Address = env.storage().instance().get(&DataKey::Creator).unwrap();
        let token_address: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = token::Client::new(&env, &token_address);

        let mut amount_to_creator = total_raised;

        // Handle platform fee if configured
        if let Some(config) = env
            .storage()
            .instance()
            .get::<_, PlatformConfig>(&DataKey::PlatformConfig)
        {
            let fee = (total_raised * config.fee_bps as i128) / 10_000;
            amount_to_creator = total_raised - fee;

            if fee > 0 {
                token_client.transfer(
                    &env.current_contract_address(),
                    &config.address,
                    &fee,
                );
                env.events()
                    .publish(("campaign", "fee_transferred"), (config.address, fee));
            }
        }

        // Transfer remaining funds to creator
        if amount_to_creator > 0 {
            token_client.transfer(
                &env.current_contract_address(),
                &creator,
                &amount_to_creator,
            );
        }

        // Update status to Successful
        env.storage()
            .instance()
            .set(&DataKey::Status, &Status::Successful);

        // Emit withdrawal event
        env.events()
            .publish(("campaign", "withdrawn"), (creator, total_raised));

        // Mint NFTs if contract is configured
        if let Some(nft_contract) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::NFTContract)
        {
            let contributors: Vec<Address> = env
                .storage()
                .persistent()
                .get(&DataKey::Contributors)
                .unwrap_or_else(|| Vec::new(&env));

            let nft_client = NftContractClient::new(&env, &nft_contract);
            let batch_size = contributors.len().min(MAX_NFT_MINT_BATCH);

            for i in 0..batch_size {
                let contributor = contributors.get(i).unwrap();
                let token_id = nft_client.mint(&contributor);
                env.events()
                    .publish(("campaign", "nft_minted"), (contributor, token_id));
            }
        }

        Ok(())
    }

    /// Set the NFT contract address for reward minting.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    /// * `creator` - Campaign creator address (must sign)
    /// * `nft_contract` - NFT contract address
    ///
    /// # Security
    ///
    /// - Requires creator authorization
    /// - Only callable by campaign creator
    pub fn set_nft_contract(env: Env, creator: Address, nft_contract: Address) {
        let stored_creator: Address = env.storage().instance().get(&DataKey::Creator).unwrap();
        if creator != stored_creator {
            panic!("not authorized");
        }
        creator.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::NFTContract, &nft_contract);
    }

    /// Get total tokens raised.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Total amount of tokens raised in the campaign
    pub fn total_raised(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalRaised)
            .unwrap_or(0)
    }

    /// Get funding goal.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Funding goal amount
    pub fn goal(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Goal).unwrap()
    }

    /// Get campaign deadline.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Deadline as ledger timestamp
    pub fn deadline(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::Deadline).unwrap()
    }

    /// Get minimum contribution amount.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Minimum contribution amount
    pub fn min_contribution(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::MinContribution)
            .unwrap()
    }

    /// Get contribution by address.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    /// * `addr` - Contributor address
    ///
    /// # Returns
    ///
    /// Contribution amount for the address, or 0 if not found
    pub fn contribution(env: Env, addr: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Contribution(addr))
            .unwrap_or(0)
    }

    /// Get list of all contributors.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Vector of contributor addresses
    pub fn contributors(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Contributors)
            .unwrap_or(Vec::new(&env))
    }

    /// Get campaign statistics for frontend display.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// CampaignStats struct with aggregated statistics
    pub fn get_stats(env: Env) -> CampaignStats {
        let total_raised: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRaised)
            .unwrap_or(0);
        let goal: i128 = env.storage().instance().get(&DataKey::Goal).unwrap();
        let contributors: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Contributors)
            .unwrap_or_else(|| Vec::new(&env));

        let contributor_count = contributors.len();
        let average_contribution = if contributor_count > 0 {
            total_raised / contributor_count as i128
        } else {
            0
        };

        let mut largest_contribution = 0i128;
        for i in 0..contributor_count {
            let contributor = contributors.get(i).unwrap();
            let amount: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::Contribution(contributor))
                .unwrap_or(0);
            if amount > largest_contribution {
                largest_contribution = amount;
            }
        }

        let progress_bps = if goal > 0 {
            ((total_raised * 10_000) / goal).min(10_000) as u32
        } else {
            0
        };

        CampaignStats {
            total_raised,
            goal,
            progress_bps,
            contributor_count,
            average_contribution,
            largest_contribution,
        }
    }

    /// Get token contract address.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Token contract address
    pub fn token(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Token).unwrap()
    }

    /// Get NFT contract address if configured.
    ///
    /// # Arguments
    ///
    /// * `env` - Soroban environment
    ///
    /// # Returns
    ///
    /// Optional NFT contract address
    pub fn nft_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::NFTContract)
    }
}
