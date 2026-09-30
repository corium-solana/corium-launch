//! # Corium Launch: fee router and supernova bounty distributor
//!
//! Every coin launches on a Meteora DBC config whose partner fee claimer is
//! this program's vault PDA, so Corium's share of every curve fee can only
//! leave through here, and only split the fixed way:
//!
//! - `claim_fees` (anyone): claims a pool's partner fees and splits them in the
//!   same instruction - `bounty_bps` into that coin's escrow (its `Bounty`),
//!   the rest to the treasury. The split is set once per DBC config by
//!   `create_route` and can never change.
//! - `create_distribution` (crank): posts a graduated coin's merkle root of
//!   winners. The coin's curve must be finished on chain, every partner fee
//!   swept, and the total must equal the escrow exactly. Nothing moves; the
//!   bounty is already in the vault.
//! - `claim` (winner): pays against the root. `sweep_expired` (anyone): after
//!   the claim window, what nobody claimed goes to the treasury.
//! - `release_bounty` (anyone): a graduated coin that never got a distribution
//!   (nobody held through the window) releases its escrow to the treasury,
//!   once the claim window has passed since graduation.
//! - `claim_lp_fees`, `claim_surplus` (anyone): the vault also owns Corium's
//!   permanently locked half of each graduated coin's DAMM v2 liquidity and
//!   any curve surplus; both go only to the treasury's own token accounts.
//!
//! ## Trust surface
//!
//! The crank's only power is the root: who wins how much of a coin's escrow.
//! Scoring is off chain; every distribution carries the URI of its published
//! scores (IPFS) and the scoring script is public, so anyone can recompute a
//! root from chain data. The crank cannot touch fees, escrow or the treasury.
//! `admin` (the upgrade authority at `initialize`) can rotate the crank and
//! the treasury, and add routes for new DBC configs; it cannot change a
//! route's split, a posted distribution, or an escrow.
//!
//! ## Merkle tree
//!
//! leaf = sha256("corium:leaf" ‖ distribution ‖ wallet ‖ amount_le)
//! node = sha256("corium:node" ‖ min(a, b) ‖ max(a, b))
//!
//! Distinct prefixes keep an inner node from ever passing as a leaf; sorted
//! pairs mean a proof is just the sibling hashes.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::system_program::{self, Transfer};
use solana_sha256_hasher::hashv;
use solana_security_txt::security_txt;

pub mod pots;
pub use pots::*;

declare_id!("NovanpiewpH4zvYgtzAQN2zWQ94KcKWrHCTswWdZ1Y1");

// Read by explorers (Solscan, Solana Explorer): who to tell about a bug.
#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Corium Launch",
    project_url: "https://corium.so",
    contacts: "email:corium.so@proton.me,twitter:@corium_so,link:https://corium.so",
    policy: "https://corium.so/security.txt",
    preferred_languages: "en",
    source_code: "https://github.com/corium-solana/corium-launch",
    auditors: "None"
}

pub const CONFIG_SEED: &[u8] = b"config";
pub const VAULT_SEED: &[u8] = b"vault";
pub const DIST_SEED: &[u8] = b"dist";
pub const CLAIM_SEED: &[u8] = b"claim";
pub const ROUTE_SEED: &[u8] = b"route";
pub const BOUNTY_SEED: &[u8] = b"bounty";
pub const QUOTE_TEMP_SEED: &[u8] = b"quote";
pub const BASE_TEMP_SEED: &[u8] = b"base";
pub const ADMIN_OFFER_SEED: &[u8] = b"admin-offer";
pub const BPS: u64 = 10_000;
pub const URI_MAX: usize = 160;
pub const PROOF_MAX: usize = 24;

const BPF_LOADER_UPGRADEABLE: Pubkey = pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");
/// Meteora Dynamic Bonding Curve and DAMM v2 (same ids on devnet and mainnet).
pub const DBC_PROGRAM: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
pub const DAMM_PROGRAM: Pubkey = pubkey!("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");
pub const TOKEN_PROGRAM: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const NATIVE_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

// DBC VirtualPool account layout (8-byte discriminator included), checked
// against live pools: see launch/scripts/fee-router-test.ts.
const POOL_CONFIG: usize = 72;
const POOL_BASE_MINT: usize = 136;
const POOL_PARTNER_QUOTE_FEE: usize = 272;
const POOL_FINISH_CURVE_TS: usize = 344;
const POOL_MIN_LEN: usize = 352;
const DBC_CLAIM_TRADING_FEE: [u8; 8] = [0x08, 0xec, 0x59, 0x31, 0x98, 0x7d, 0xb1, 0x51];
const DBC_PARTNER_WITHDRAW_SURPLUS: [u8; 8] = [0xa8, 0xad, 0x48, 0x64, 0xc9, 0x62, 0x26, 0x5c];
const DAMM_CLAIM_POSITION_FEE: [u8; 8] = [0xb4, 0x26, 0x9a, 0x11, 0x85, 0x21, 0xa2, 0xd3];
const TOKEN_ACCOUNT_LEN: usize = 165;

#[program]
pub mod corium_launch {
    use super::*;

    /// Once, by the program's upgrade authority (the same gate as the game's
    /// `initialize`, and for the same reason: it names the treasury).
    pub fn initialize(ctx: Context<Initialize>, crank: Pubkey, treasury: Pubkey, claim_window: i64) -> Result<()> {
        require!(claim_window > 0, LaunchError::BadWindow);
        let authority = upgrade_authority(&ctx.accounts.program_data)?;
        require!(authority == Some(ctx.accounts.payer.key()), LaunchError::NotUpgradeAuthority);

        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.payer.key();
        cfg.crank = crank;
        cfg.treasury = treasury;
        cfg.claim_window = claim_window;
        cfg.bump = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;

        // The vault holds no data; it only has to stay rent exempt.
        let floor = Rent::get()?.minimum_balance(0);
        let have = ctx.accounts.vault.lamports();
        if have < floor {
            system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    Transfer { from: ctx.accounts.payer.to_account_info(), to: ctx.accounts.vault.to_account_info() },
                ),
                floor - have,
            )?;
        }
        Ok(())
    }

    pub fn set_crank(ctx: Context<Admin>, crank: Pubkey) -> Result<()> {
        ctx.accounts.config.crank = crank;
        Ok(())
    }

    pub fn set_treasury(ctx: Context<Admin>, treasury: Pubkey) -> Result<()> {
        ctx.accounts.config.treasury = treasury;
        Ok(())
    }

    /// Admin hands over in two steps: offer, then the new admin accepts. A
    /// mistyped address can never take control, because it can't sign.
    pub fn propose_admin(ctx: Context<ProposeAdmin>, new_admin: Pubkey) -> Result<()> {
        require!(new_admin != Pubkey::default(), LaunchError::BadAdmin);
        let o = &mut ctx.accounts.offer;
        o.new_admin = new_admin;
        o.proposer = ctx.accounts.admin.key();
        o.bump = ctx.bumps.offer;
        emit!(AdminProposed { from: o.proposer, to: new_admin });
        Ok(())
    }

    /// The current admin withdraws an open offer.
    pub fn cancel_admin_offer(_ctx: Context<CancelAdminOffer>) -> Result<()> {
        Ok(())
    }

    /// The offered admin takes over; the offer's rent goes back to whoever made it.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let from = ctx.accounts.config.admin;
        ctx.accounts.config.admin = ctx.accounts.new_admin.key();
        emit!(AdminChanged { from, to: ctx.accounts.new_admin.key() });
        Ok(())
    }

    /// Once per DBC config, by admin: route its partner fees here with a fixed
    /// bounty share. There is no instruction that changes a route.
    pub fn create_route(ctx: Context<CreateRoute>, dbc_config: Pubkey, bounty_bps: u16) -> Result<()> {
        require!(bounty_bps as u64 <= BPS, LaunchError::BadBps);
        let r = &mut ctx.accounts.route;
        r.dbc_config = dbc_config;
        r.bounty_bps = bounty_bps;
        r.bump = ctx.bumps.route;
        emit!(RouteCreated { dbc_config, bounty_bps });
        Ok(())
    }

    /// Anyone: claim a pool's partner trading fees and split them - the
    /// route's share into the coin's escrow, the rest to the treasury.
    pub fn claim_fees(ctx: Context<ClaimFees>) -> Result<()> {
        let a = &ctx.accounts;
        {
            let data = a.pool.try_borrow_data()?;
            require!(data.len() >= POOL_MIN_LEN, LaunchError::BadPool);
            require!(data[POOL_CONFIG..POOL_CONFIG + 32] == a.dbc_config.key().to_bytes(), LaunchError::WrongConfig);
            require!(data[POOL_BASE_MINT..POOL_BASE_MINT + 32] == a.base_mint.key().to_bytes(), LaunchError::BadPool);
        }
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, core::slice::from_ref(&ctx.accounts.config.vault_bump)];
        let pool_key = a.pool.key();
        let quote_bump = ctx.bumps.quote_temp;
        let base_bump = ctx.bumps.base_temp;
        let quote_seeds: &[&[u8]] = &[QUOTE_TEMP_SEED, pool_key.as_ref(), core::slice::from_ref(&quote_bump)];
        let base_seeds: &[&[u8]] = &[BASE_TEMP_SEED, pool_key.as_ref(), core::slice::from_ref(&base_bump)];

        // Scratch token accounts owned by the vault, for this instruction only.
        let rent = create_token_account(&a.caller, &a.quote_temp, &a.quote_mint, &a.vault.key(), &a.token_program, &a.system_program, quote_seeds)?;
        let base_rent = create_token_account(&a.caller, &a.base_temp, &a.base_mint, &a.vault.key(), &a.token_program, &a.system_program, base_seeds)?;

        invoke_signed(
            &Instruction {
                program_id: DBC_PROGRAM,
                accounts: vec![
                    AccountMeta::new_readonly(a.dbc_pool_authority.key(), false),
                    AccountMeta::new_readonly(a.dbc_config.key(), false),
                    AccountMeta::new(a.pool.key(), false),
                    AccountMeta::new(a.base_temp.key(), false),
                    AccountMeta::new(a.quote_temp.key(), false),
                    AccountMeta::new(a.base_vault.key(), false),
                    AccountMeta::new(a.quote_vault.key(), false),
                    AccountMeta::new_readonly(a.base_mint.key(), false),
                    AccountMeta::new_readonly(a.quote_mint.key(), false),
                    AccountMeta::new_readonly(a.vault.key(), true),
                    AccountMeta::new_readonly(a.token_program.key(), false),
                    AccountMeta::new_readonly(a.token_program.key(), false),
                    AccountMeta::new_readonly(a.dbc_event_authority.key(), false),
                    AccountMeta::new_readonly(DBC_PROGRAM, false),
                ],
                data: [&DBC_CLAIM_TRADING_FEE[..], &0u64.to_le_bytes(), &u64::MAX.to_le_bytes()].concat(),
            },
            &[
                a.dbc_pool_authority.to_account_info(),
                a.dbc_config.to_account_info(),
                a.pool.to_account_info(),
                a.base_temp.to_account_info(),
                a.quote_temp.to_account_info(),
                a.base_vault.to_account_info(),
                a.quote_vault.to_account_info(),
                a.base_mint.to_account_info(),
                a.quote_mint.to_account_info(),
                a.vault.to_account_info(),
                a.token_program.to_account_info(),
                a.dbc_event_authority.to_account_info(),
                a.dbc_program.to_account_info(),
            ],
            &[vault_seeds],
        )?;

        let amount = token_amount(&a.quote_temp)?;
        // The base scratch holds nothing (fees are collected in SOL): rent back to the caller.
        close_token_account(&a.base_temp, &a.caller, &a.vault, &a.token_program, vault_seeds)?;
        // WSOL closes to lamports: fees and scratch rent land in the vault.
        close_token_account(&a.quote_temp, &a.vault, &a.vault, &a.token_program, vault_seeds)?;
        pay(&a.system_program, &a.vault.to_account_info(), &a.caller.to_account_info(), ctx.accounts.config.vault_bump, rent)?;
        let _ = base_rent;

        let b = &mut ctx.accounts.bounty;
        if b.pool == Pubkey::default() {
            b.pool = pool_key;
            b.bump = ctx.bumps.bounty;
        }
        // After a coin's bounty is posted or released, its fees are Corium's.
        let to_bounty = if b.distributed { 0 } else { (amount as u128 * ctx.accounts.route.bounty_bps as u128 / BPS as u128) as u64 };
        b.accrued = b.accrued.checked_add(to_bounty).ok_or(LaunchError::Overflow)?;
        b.fees = b.fees.checked_add(amount).ok_or(LaunchError::Overflow)?;
        let to_treasury = amount - to_bounty;
        pay(&ctx.accounts.system_program, &ctx.accounts.vault.to_account_info(), &ctx.accounts.treasury.to_account_info(), ctx.accounts.config.vault_bump, to_treasury)?;
        emit!(FeesClaimed { pool: pool_key, amount, to_bounty, to_treasury, accrued: b.accrued });
        Ok(())
    }

    /// Anyone: fees on Corium's locked DAMM v2 position (owned by the vault),
    /// straight to the treasury's own token accounts.
    pub fn claim_lp_fees(ctx: Context<ClaimLpFees>) -> Result<()> {
        let a = &ctx.accounts;
        check_treasury_account(&a.treasury_token_a, &a.treasury.key(), &a.token_a_mint.key())?;
        check_treasury_account(&a.treasury_token_b, &a.treasury.key(), &a.token_b_mint.key())?;
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, core::slice::from_ref(&a.config.vault_bump)];
        invoke_signed(
            &Instruction {
                program_id: DAMM_PROGRAM,
                accounts: vec![
                    AccountMeta::new_readonly(a.damm_pool_authority.key(), false),
                    AccountMeta::new_readonly(a.damm_pool.key(), false),
                    AccountMeta::new(a.position.key(), false),
                    AccountMeta::new(a.treasury_token_a.key(), false),
                    AccountMeta::new(a.treasury_token_b.key(), false),
                    AccountMeta::new(a.token_a_vault.key(), false),
                    AccountMeta::new(a.token_b_vault.key(), false),
                    AccountMeta::new_readonly(a.token_a_mint.key(), false),
                    AccountMeta::new_readonly(a.token_b_mint.key(), false),
                    AccountMeta::new_readonly(a.position_nft_account.key(), false),
                    AccountMeta::new_readonly(a.vault.key(), true),
                    AccountMeta::new_readonly(a.token_a_program.key(), false),
                    AccountMeta::new_readonly(a.token_b_program.key(), false),
                    AccountMeta::new_readonly(a.damm_event_authority.key(), false),
                    AccountMeta::new_readonly(DAMM_PROGRAM, false),
                ],
                data: DAMM_CLAIM_POSITION_FEE.to_vec(),
            },
            &[
                a.damm_pool_authority.to_account_info(),
                a.damm_pool.to_account_info(),
                a.position.to_account_info(),
                a.treasury_token_a.to_account_info(),
                a.treasury_token_b.to_account_info(),
                a.token_a_vault.to_account_info(),
                a.token_b_vault.to_account_info(),
                a.token_a_mint.to_account_info(),
                a.token_b_mint.to_account_info(),
                a.position_nft_account.to_account_info(),
                a.vault.to_account_info(),
                a.token_a_program.to_account_info(),
                a.token_b_program.to_account_info(),
                a.damm_event_authority.to_account_info(),
                a.damm_program.to_account_info(),
            ],
            &[vault_seeds],
        )?;
        Ok(())
    }

    /// Anyone: a graduated curve's partner surplus, to the treasury's WSOL account.
    pub fn claim_surplus(ctx: Context<ClaimSurplus>) -> Result<()> {
        let a = &ctx.accounts;
        check_treasury_account(&a.treasury_quote, &a.treasury.key(), &a.quote_mint.key())?;
        {
            let data = a.pool.try_borrow_data()?;
            require!(data.len() >= POOL_MIN_LEN, LaunchError::BadPool);
            require!(data[POOL_CONFIG..POOL_CONFIG + 32] == a.dbc_config.key().to_bytes(), LaunchError::WrongConfig);
        }
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, core::slice::from_ref(&a.config.vault_bump)];
        invoke_signed(
            &Instruction {
                program_id: DBC_PROGRAM,
                accounts: vec![
                    AccountMeta::new_readonly(a.dbc_pool_authority.key(), false),
                    AccountMeta::new_readonly(a.dbc_config.key(), false),
                    AccountMeta::new(a.pool.key(), false),
                    AccountMeta::new(a.treasury_quote.key(), false),
                    AccountMeta::new(a.quote_vault.key(), false),
                    AccountMeta::new_readonly(a.quote_mint.key(), false),
                    AccountMeta::new_readonly(a.vault.key(), true),
                    AccountMeta::new_readonly(a.token_program.key(), false),
                    AccountMeta::new_readonly(a.dbc_event_authority.key(), false),
                    AccountMeta::new_readonly(DBC_PROGRAM, false),
                ],
                data: DBC_PARTNER_WITHDRAW_SURPLUS.to_vec(),
            },
            &[
                a.dbc_pool_authority.to_account_info(),
                a.dbc_config.to_account_info(),
                a.pool.to_account_info(),
                a.treasury_quote.to_account_info(),
                a.quote_vault.to_account_info(),
                a.quote_mint.to_account_info(),
                a.vault.to_account_info(),
                a.token_program.to_account_info(),
                a.dbc_event_authority.to_account_info(),
                a.dbc_program.to_account_info(),
            ],
            &[vault_seeds],
        )?;
        Ok(())
    }

    /// Crank: post a graduated coin's winners against its escrow. The curve
    /// must be finished, every partner fee swept into the escrow, and the
    /// total equal to the escrow. One per pool, forever. Nothing moves: the
    /// bounty is already in the vault.
    pub fn create_distribution(
        ctx: Context<CreateDistribution>,
        pool: Pubkey,
        root: [u8; 32],
        total: u64,
        wallets: u32,
        uri: String,
    ) -> Result<()> {
        require!(total > 0, LaunchError::EmptyDistribution);
        require!(uri.len() <= URI_MAX, LaunchError::UriTooLong);
        {
            let data = ctx.accounts.pool_account.try_borrow_data()?;
            require!(data.len() >= POOL_MIN_LEN, LaunchError::BadPool);
            require!(read_u64(&data, POOL_FINISH_CURVE_TS) != 0, LaunchError::NotGraduated);
            require!(read_u64(&data, POOL_PARTNER_QUOTE_FEE) == 0, LaunchError::FeesNotSwept);
        }
        let b = &mut ctx.accounts.bounty;
        require!(!b.distributed, LaunchError::AlreadyDistributed);
        require!(total == b.accrued, LaunchError::TotalNotEscrow);
        b.distributed = true;

        let now = Clock::get()?.unix_timestamp;
        let d = &mut ctx.accounts.distribution;
        d.pool = pool;
        d.root = root;
        d.total = total;
        d.claimed = 0;
        d.wallets = wallets;
        d.claims = 0;
        d.created_at = now;
        d.expires_at = now.checked_add(ctx.accounts.config.claim_window).ok_or(LaunchError::Overflow)?;
        d.swept = false;
        d.bump = ctx.bumps.distribution;
        d.uri = uri;

        emit!(DistributionCreated { pool, distribution: d.key(), root, total, wallets });
        Ok(())
    }

    /// Pay `amount` to the signer if `(distribution, signer, amount)` proves
    /// against the root. The claim record's existence blocks a second claim.
    pub fn claim(ctx: Context<Claim>, amount: u64, proof: Vec<[u8; 32]>) -> Result<()> {
        require!(amount > 0, LaunchError::EmptyClaim);
        require!(proof.len() <= PROOF_MAX, LaunchError::ProofTooLong);
        let d = &mut ctx.accounts.distribution;
        require!(Clock::get()?.unix_timestamp < d.expires_at, LaunchError::Expired);

        let wallet = ctx.accounts.wallet.key();
        let mut node = leaf(&d.key(), &wallet, amount);
        for sibling in &proof {
            node = parent(&node, sibling);
        }
        require!(node == d.root, LaunchError::BadProof);

        let claimed = d.claimed.checked_add(amount).ok_or(LaunchError::Overflow)?;
        require!(claimed <= d.total, LaunchError::OverClaim);
        d.claimed = claimed;
        d.claims += 1;

        let r = &mut ctx.accounts.claim_record;
        r.amount = amount;
        r.claimed_at = Clock::get()?.unix_timestamp;
        r.bump = ctx.bumps.claim_record;

        pay(
            &ctx.accounts.system_program,
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.wallet.to_account_info(),
            ctx.accounts.config.vault_bump,
            amount,
        )?;
        emit!(Claimed { distribution: d.key(), wallet, amount });
        Ok(())
    }

    /// Anyone: a graduated coin that never got a distribution (nobody held
    /// through the window) releases its escrow to the treasury once the claim
    /// window has passed since its curve finished.
    pub fn release_bounty(ctx: Context<ReleaseBounty>) -> Result<()> {
        let finished = {
            let data = ctx.accounts.pool.try_borrow_data()?;
            require!(data.len() >= POOL_MIN_LEN, LaunchError::BadPool);
            read_u64(&data, POOL_FINISH_CURVE_TS) as i64
        };
        require!(finished != 0, LaunchError::NotGraduated);
        let open_until = finished.checked_add(ctx.accounts.config.claim_window).ok_or(LaunchError::Overflow)?;
        require!(Clock::get()?.unix_timestamp >= open_until, LaunchError::NotExpired);
        let b = &mut ctx.accounts.bounty;
        require!(!b.distributed, LaunchError::AlreadyDistributed);
        let amount = b.accrued;
        b.distributed = true;
        pay(&ctx.accounts.system_program, &ctx.accounts.vault.to_account_info(), &ctx.accounts.treasury.to_account_info(), ctx.accounts.config.vault_bump, amount)?;
        emit!(BountyReleased { pool: b.pool, amount });
        Ok(())
    }

    /// After the claim window, anyone can send what nobody claimed to the treasury.
    pub fn sweep_expired(ctx: Context<Sweep>) -> Result<()> {
        let d = &mut ctx.accounts.distribution;
        require!(Clock::get()?.unix_timestamp >= d.expires_at, LaunchError::NotExpired);
        require!(!d.swept, LaunchError::AlreadySwept);
        let rest = d.total - d.claimed;
        d.swept = true;
        pay(
            &ctx.accounts.system_program,
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.treasury.to_account_info(),
            ctx.accounts.config.vault_bump,
            rest,
        )?;
        emit!(Swept { distribution: d.key(), amount: rest });
        Ok(())
    }

    // ---- pots: sponsored bounties and requests (see pots.rs)

    pub fn init_pot_config(ctx: Context<InitPotConfig>, params: PotParams) -> Result<()> {
        pots::init_pot_config_ix(ctx, params)
    }

    pub fn set_pot_config(ctx: Context<SetPotConfig>, params: PotParams) -> Result<()> {
        pots::set_pot_config_ix(ctx, params)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_pot(
        ctx: Context<OpenPot>,
        nonce: u64,
        kind: u8,
        deadline: i64,
        creator_bps: u16,
        min_stake: u64,
        amount: u64,
        brief: String,
    ) -> Result<()> {
        pots::open_pot_ix(ctx, nonce, kind, deadline, creator_bps, min_stake, amount, brief)
    }

    pub fn fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
        pots::fund_ix(ctx, amount)
    }

    pub fn enter(ctx: Context<Enter>, stake: u64) -> Result<()> {
        pots::enter_ix(ctx, stake)
    }

    pub fn claim_stake(ctx: Context<ClaimStake>) -> Result<()> {
        pots::claim_stake_ix(ctx)
    }

    pub fn release_stake(ctx: Context<ReleaseStake>) -> Result<()> {
        pots::release_stake_ix(ctx)
    }

    pub fn reject_entry(ctx: Context<RejectEntry>) -> Result<()> {
        pots::reject_entry_ix(ctx)
    }

    pub fn mark_winner(ctx: Context<MarkWinner>) -> Result<()> {
        pots::mark_winner_ix(ctx)
    }

    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        pots::settle_ix(ctx)
    }

    pub fn claim_finisher(ctx: Context<ClaimFinisher>) -> Result<()> {
        pots::claim_finisher_ix(ctx)
    }

    // ---- the stretch ledger (see pots.rs)

    pub fn stretch_begin(ctx: Context<StretchBegin>) -> Result<()> {
        pots::stretch_begin_ix(ctx)
    }

    pub fn stretch_end(ctx: Context<StretchEnd>) -> Result<()> {
        pots::stretch_end_ix(ctx)
    }

    pub fn stretch_finish(ctx: Context<StretchFinish>) -> Result<()> {
        pots::stretch_finish_ix(ctx)
    }

    pub fn stretch_unlock(ctx: Context<StretchUnlock>) -> Result<()> {
        pots::stretch_unlock_ix(ctx)
    }

    pub fn close_credit(ctx: Context<CloseCredit>) -> Result<()> {
        pots::close_credit_ix(ctx)
    }

    pub fn start_return(ctx: Context<StartReturn>) -> Result<()> {
        pots::start_return_ix(ctx)
    }

    pub fn refund(ctx: Context<Refund>) -> Result<()> {
        pots::refund_ix(ctx)
    }
}

// ------------------------------------------------------------------ tokens

pub(crate) fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// A fresh SPL token account at a PDA, owned by `owner`, rent from `payer`. Returns its rent.
fn create_token_account<'info>(
    payer: &Signer<'info>,
    account: &UncheckedAccount<'info>,
    mint: &UncheckedAccount<'info>,
    owner: &Pubkey,
    token_program: &UncheckedAccount<'info>,
    system: &Program<'info, System>,
    seeds: &[&[u8]],
) -> Result<u64> {
    let rent = Rent::get()?.minimum_balance(TOKEN_ACCOUNT_LEN);
    system_program::create_account(
        CpiContext::new_with_signer(
            system.key(),
            system_program::CreateAccount { from: payer.to_account_info(), to: account.to_account_info() },
            &[seeds],
        ),
        rent,
        TOKEN_ACCOUNT_LEN as u64,
        &TOKEN_PROGRAM,
    )?;
    // InitializeAccount3 (tag 18): owner in the data, no rent sysvar.
    invoke(
        &Instruction {
            program_id: TOKEN_PROGRAM,
            accounts: vec![AccountMeta::new(account.key(), false), AccountMeta::new_readonly(mint.key(), false)],
            data: [&[18u8][..], owner.as_ref()].concat(),
        },
        &[account.to_account_info(), mint.to_account_info(), token_program.to_account_info()],
    )?;
    Ok(rent)
}

/// CloseAccount (tag 9), signed by the vault: every lamport to `to`.
fn close_token_account<'info>(
    account: &UncheckedAccount<'info>,
    to: &impl ToAccountInfo<'info>,
    vault: &UncheckedAccount<'info>,
    token_program: &UncheckedAccount<'info>,
    vault_seeds: &[&[u8]],
) -> Result<()> {
    invoke_signed(
        &Instruction {
            program_id: TOKEN_PROGRAM,
            accounts: vec![
                AccountMeta::new(account.key(), false),
                AccountMeta::new(to.to_account_info().key(), false),
                AccountMeta::new_readonly(vault.key(), true),
            ],
            data: vec![9u8],
        },
        &[account.to_account_info(), to.to_account_info(), vault.to_account_info(), token_program.to_account_info()],
        &[vault_seeds],
    )?;
    Ok(())
}

fn token_amount(account: &UncheckedAccount) -> Result<u64> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 72, LaunchError::BadTokenAccount);
    Ok(read_u64(&data, 64))
}

/// A token account the treasury owns, for `mint`: the only place LP fees and surplus may go.
fn check_treasury_account(account: &UncheckedAccount, treasury: &Pubkey, mint: &Pubkey) -> Result<()> {
    require_keys_eq!(*account.owner, TOKEN_PROGRAM, LaunchError::BadTokenAccount);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 72, LaunchError::BadTokenAccount);
    require!(data[0..32] == mint.to_bytes(), LaunchError::BadTokenAccount);
    require!(data[32..64] == treasury.to_bytes(), LaunchError::NotTreasury);
    Ok(())
}

// ------------------------------------------------------------------ merkle

pub fn leaf(distribution: &Pubkey, wallet: &Pubkey, amount: u64) -> [u8; 32] {
    hashv(&[b"corium:leaf", distribution.as_ref(), wallet.as_ref(), &amount.to_le_bytes()]).to_bytes()
}

pub fn parent(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    hashv(&[b"corium:node", lo, hi]).to_bytes()
}

fn pay<'info>(
    system_program_ai: &Program<'info, System>,
    vault: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    vault_bump: u8,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let seeds: &[&[u8]] = &[VAULT_SEED, core::slice::from_ref(&vault_bump)];
    system_program::transfer(
        CpiContext::new_with_signer(system_program_ai.key(), Transfer { from: vault.clone(), to: to.clone() }, &[seeds]),
        amount,
    )
}

/// This program's upgrade authority, from its ProgramData (bincode layout:
/// u32 tag = 3, u64 slot, Option<Pubkey>).
fn upgrade_authority(program_data: &AccountInfo) -> Result<Option<Pubkey>> {
    require_keys_eq!(*program_data.owner, BPF_LOADER_UPGRADEABLE, LaunchError::MalformedProgramData);
    let data = program_data.try_borrow_data()?;
    require!(data.len() >= 45, LaunchError::MalformedProgramData);
    require!(u32::from_le_bytes(data[..4].try_into().unwrap()) == 3, LaunchError::MalformedProgramData);
    match data[12] {
        0 => Ok(None),
        1 => Ok(Some(Pubkey::new_from_array(data[13..45].try_into().unwrap()))),
        _ => err!(LaunchError::MalformedProgramData),
    }
}

// ------------------------------------------------------------------ accounts

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub crank: Pubkey,
    pub treasury: Pubkey,
    pub claim_window: i64,
    pub bump: u8,
    pub vault_bump: u8,
}

/// An open admin handover. At most one: the PDA has a fixed seed.
#[account]
#[derive(InitSpace)]
pub struct AdminOffer {
    pub new_admin: Pubkey,
    pub proposer: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Distribution {
    pub pool: Pubkey,
    pub root: [u8; 32],
    pub total: u64,
    pub claimed: u64,
    pub wallets: u32,
    pub claims: u32,
    pub created_at: i64,
    pub expires_at: i64,
    pub swept: bool,
    pub bump: u8,
    /// Published scores and proofs (IPFS), so anyone can check the root.
    #[max_len(URI_MAX)]
    pub uri: String,
}

/// Where one DBC config's partner fees go: `bounty_bps` to each coin's
/// escrow, the rest to the treasury. Fixed forever.
#[account]
#[derive(InitSpace)]
pub struct Route {
    pub dbc_config: Pubkey,
    pub bounty_bps: u16,
    pub bump: u8,
}

/// A coin's escrow: its share of every partner fee claimed from its curve,
/// held in the vault until a distribution pays it out or it is released.
#[account]
#[derive(InitSpace)]
pub struct Bounty {
    pub pool: Pubkey,
    /// Lamports escrowed for the bounty.
    pub accrued: u64,
    /// Every partner fee claimed from the pool, both halves.
    pub fees: u64,
    /// A distribution was posted, or the escrow released.
    pub distributed: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ClaimRecord {
    pub amount: u64,
    pub claimed_at: i64,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: system-owned, zero data; lamports only leave through `pay`.
    #[account(mut, seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: this program's ProgramData, parsed in `upgrade_authority`.
    #[account(seeds = [crate::ID.as_ref()], bump, seeds::program = BPF_LOADER_UPGRADEABLE)]
    pub program_data: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Admin<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct ProposeAdmin<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(init, payer = admin, space = 8 + AdminOffer::INIT_SPACE, seeds = [ADMIN_OFFER_SEED], bump)]
    pub offer: Account<'info, AdminOffer>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CancelAdminOffer<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ADMIN_OFFER_SEED], bump = offer.bump, close = admin)]
    pub offer: Account<'info, AdminOffer>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ADMIN_OFFER_SEED], bump = offer.bump, has_one = new_admin, has_one = proposer, close = proposer)]
    pub offer: Account<'info, AdminOffer>,
    /// CHECK: receives the offer's rent; pinned by `has_one = proposer`.
    #[account(mut)]
    pub proposer: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(dbc_config: Pubkey)]
pub struct CreateRoute<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(init, payer = admin, space = 8 + Route::INIT_SPACE, seeds = [ROUTE_SEED, dbc_config.as_ref()], bump)]
    pub route: Account<'info, Route>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimFees<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ROUTE_SEED, dbc_config.key().as_ref()], bump = route.bump)]
    pub route: Account<'info, Route>,
    #[account(init_if_needed, payer = caller, space = 8 + Bounty::INIT_SPACE, seeds = [BOUNTY_SEED, pool.key().as_ref()], bump)]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: the vault PDA: DBC fee claimer, scratch-account owner, escrow.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one` on config.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: scratch WSOL account, created and closed in this instruction.
    #[account(mut, seeds = [QUOTE_TEMP_SEED, pool.key().as_ref()], bump)]
    pub quote_temp: UncheckedAccount<'info>,
    /// CHECK: scratch base-token account, created and closed in this instruction.
    #[account(mut, seeds = [BASE_TEMP_SEED, pool.key().as_ref()], bump)]
    pub base_temp: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    pub dbc_pool_authority: UncheckedAccount<'info>,
    /// CHECK: pinned by the route's seeds; DBC checks the pool belongs to it.
    pub dbc_config: UncheckedAccount<'info>,
    /// CHECK: a DBC pool; its config is checked against the route.
    #[account(mut, owner = DBC_PROGRAM)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    #[account(mut)]
    pub base_vault: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    #[account(mut)]
    pub quote_vault: UncheckedAccount<'info>,
    /// CHECK: checked against the pool.
    pub base_mint: UncheckedAccount<'info>,
    /// CHECK: SOL.
    #[account(address = NATIVE_MINT)]
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: SPL Token.
    #[account(address = TOKEN_PROGRAM)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    pub dbc_event_authority: UncheckedAccount<'info>,
    /// CHECK: Meteora DBC.
    #[account(address = DBC_PROGRAM)]
    pub dbc_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimLpFees<'info> {
    pub caller: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = treasury)]
    pub config: Account<'info, Config>,
    /// CHECK: the vault PDA, owner of Corium's position NFTs.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one` on config.
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: must be the treasury's token account for token A (checked).
    #[account(mut)]
    pub treasury_token_a: UncheckedAccount<'info>,
    /// CHECK: must be the treasury's token account for token B (checked).
    #[account(mut)]
    pub treasury_token_b: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub damm_pool_authority: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub damm_pool: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    #[account(mut)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub token_a_mint: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub token_b_mint: UncheckedAccount<'info>,
    /// CHECK: the vault's NFT account for the position; DAMM v2 checks it.
    pub position_nft_account: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub token_a_program: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub token_b_program: UncheckedAccount<'info>,
    /// CHECK: DAMM v2 checks it.
    pub damm_event_authority: UncheckedAccount<'info>,
    /// CHECK: Meteora DAMM v2.
    #[account(address = DAMM_PROGRAM)]
    pub damm_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ClaimSurplus<'info> {
    pub caller: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ROUTE_SEED, dbc_config.key().as_ref()], bump = route.bump)]
    pub route: Account<'info, Route>,
    /// CHECK: the vault PDA (DBC fee claimer).
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one` on config.
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: must be the treasury's WSOL account (checked).
    #[account(mut)]
    pub treasury_quote: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    pub dbc_pool_authority: UncheckedAccount<'info>,
    /// CHECK: pinned by the route's seeds.
    pub dbc_config: UncheckedAccount<'info>,
    /// CHECK: a DBC pool on the routed config (checked).
    #[account(mut, owner = DBC_PROGRAM)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    #[account(mut)]
    pub quote_vault: UncheckedAccount<'info>,
    /// CHECK: SOL.
    #[account(address = NATIVE_MINT)]
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: SPL Token.
    #[account(address = TOKEN_PROGRAM)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: DBC checks it.
    pub dbc_event_authority: UncheckedAccount<'info>,
    /// CHECK: Meteora DBC.
    #[account(address = DBC_PROGRAM)]
    pub dbc_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(pool: Pubkey)]
pub struct CreateDistribution<'info> {
    #[account(mut)]
    pub crank: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = crank)]
    pub config: Account<'info, Config>,
    #[account(init, payer = crank, space = 8 + Distribution::INIT_SPACE, seeds = [DIST_SEED, pool.as_ref()], bump)]
    pub distribution: Account<'info, Distribution>,
    #[account(mut, seeds = [BOUNTY_SEED, pool.as_ref()], bump = bounty.bump)]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: the DBC pool itself; read for graduation and swept fees.
    #[account(address = pool, owner = DBC_PROGRAM)]
    pub pool_account: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ReleaseBounty<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [BOUNTY_SEED, pool.key().as_ref()], bump = bounty.bump)]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: the DBC pool; read for graduation.
    #[account(owner = DBC_PROGRAM)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: the vault PDA.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one` on config.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [DIST_SEED, distribution.pool.as_ref()], bump = distribution.bump)]
    pub distribution: Account<'info, Distribution>,
    #[account(
        init,
        payer = wallet,
        space = 8 + ClaimRecord::INIT_SPACE,
        seeds = [CLAIM_SEED, distribution.key().as_ref(), wallet.key().as_ref()],
        bump
    )]
    pub claim_record: Account<'info, ClaimRecord>,
    /// CHECK: the vault PDA.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Sweep<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [DIST_SEED, distribution.pool.as_ref()], bump = distribution.bump)]
    pub distribution: Account<'info, Distribution>,
    /// CHECK: the vault PDA.
    #[account(mut, seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one` on config.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ------------------------------------------------------------------ events, errors

#[event]
pub struct AdminProposed {
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct AdminChanged {
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct RouteCreated {
    pub dbc_config: Pubkey,
    pub bounty_bps: u16,
}

#[event]
pub struct FeesClaimed {
    pub pool: Pubkey,
    pub amount: u64,
    pub to_bounty: u64,
    pub to_treasury: u64,
    pub accrued: u64,
}

#[event]
pub struct BountyReleased {
    pub pool: Pubkey,
    pub amount: u64,
}

#[event]
pub struct DistributionCreated {
    pub pool: Pubkey,
    pub distribution: Pubkey,
    pub root: [u8; 32],
    pub total: u64,
    pub wallets: u32,
}

#[event]
pub struct Claimed {
    pub distribution: Pubkey,
    pub wallet: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Swept {
    pub distribution: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum LaunchError {
    #[msg("Signer is not the program's upgrade authority")]
    NotUpgradeAuthority,
    #[msg("ProgramData account is malformed")]
    MalformedProgramData,
    #[msg("Claim window must be positive")]
    BadWindow,
    #[msg("Distribution total must be positive")]
    EmptyDistribution,
    #[msg("URI is too long")]
    UriTooLong,
    #[msg("Claim amount must be positive")]
    EmptyClaim,
    #[msg("Proof is too long")]
    ProofTooLong,
    #[msg("Proof does not match the distribution root")]
    BadProof,
    #[msg("Claims would exceed the distribution total")]
    OverClaim,
    #[msg("The claim window has closed")]
    Expired,
    #[msg("The claim window is still open")]
    NotExpired,
    #[msg("Already swept")]
    AlreadySwept,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Basis points must be at most 10000")]
    BadBps,
    #[msg("Not a DBC pool this program can read")]
    BadPool,
    #[msg("The pool is not on a routed config")]
    WrongConfig,
    #[msg("The curve has not finished")]
    NotGraduated,
    #[msg("Claim the pool's fees first (claim_fees)")]
    FeesNotSwept,
    #[msg("The distribution total must equal the coin's escrow")]
    TotalNotEscrow,
    #[msg("This coin's bounty was already posted or released")]
    AlreadyDistributed,
    #[msg("Not a token account for that mint")]
    BadTokenAccount,
    #[msg("Only the treasury's token accounts may receive this")]
    NotTreasury,
    #[msg("The new admin cannot be the default address")]
    BadAdmin,
    #[msg("A pot needs a positive amount")]
    EmptyPot,
    #[msg("Deadline is outside the allowed range")]
    BadDeadline,
    #[msg("The coin has already graduated")]
    AlreadyGraduated,
    #[msg("Unknown pot kind")]
    BadKind,
    #[msg("The pot is not in the right state for this")]
    PotClosed,
    #[msg("The pot's deadline has passed")]
    PastDeadline,
    #[msg("Signer is not the coin's creator")]
    NotCreator,
    #[msg("The coin is past the point where it can enter a request")]
    EntryTooLate,
    #[msg("The coin is not entered in this request")]
    NotEntered,
    #[msg("The coin did not graduate before the current winner")]
    NotEarlier,
    #[msg("The pot has no winner")]
    NoWinner,
    #[msg("Still in the grace period after the winner graduated")]
    InGrace,
    #[msg("The pot has a winner")]
    HasWinner,
    #[msg("Already refunded")]
    AlreadyRefunded,
    #[msg("Not a supported mint")]
    BadMint,
    #[msg("The mint has an extension pots do not accept")]
    MintExtension,
    #[msg("Only the request's opener can do this")]
    NotSponsor,
    #[msg("The request's opener rejected this coin")]
    Rejected,
    #[msg("The pot would exceed the SOL cap")]
    PotTooLarge,
    #[msg("The stake is below the request's minimum")]
    StakeTooSmall,
    #[msg("The entry staked nothing")]
    NothingStaked,
    #[msg("Only the winning entry's stake goes to the funders")]
    NotWinner,
    #[msg("The request isn't decided for this entry yet")]
    NotDecided,
    #[msg("Already claimed")]
    AlreadyClaimed,
    #[msg("Not this contribution's funder")]
    NotFunder,
    #[msg("The pot is below the minimum")]
    PotTooSmall,
    #[msg("A stretch bracket must end in the same transaction")]
    NoBracketEnd,
    #[msg("This wallet already has an open stretch bracket")]
    BracketOpen,
    #[msg("No open stretch bracket")]
    NoBracket,
    #[msg("Still inside the hold window")]
    InHold,
    #[msg("This wallet gave up its share by unlocking early")]
    Forfeited,
    #[msg("No stretch credit")]
    NoCredit,
    #[msg("Nothing locked")]
    NothingLocked,
    #[msg("Tokens are still locked")]
    StillLocked,
}
