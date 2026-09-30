//! # Pots: sponsored bounties and requests
//!
//! A pot escrows one token (SOL as WSOL, SPL Token, or plain Token-2022) in
//! its own associated token account, never in the fee vault. It pays out
//! only if its condition is met on chain before its deadline:
//!
//! - **Bounty**: a target coin graduates, on Corium or on pump.fun.
//! - **Request**: some Corium coin entered into it graduates; the earliest
//!   wins. To enter, a creator escrows a stake of their own coin (at least
//!   the opener's `min_stake`); the winner's stake goes to the funders pro
//!   rata, the others go back to their creators once the request is decided.
//!
//! On a win, `settle` pays Corium's fee and (requests) the winning coin's
//! creator; the rest goes to the coin's **finishers**, entirely on chain.
//!
//! ## Finishers: the stretch ledger
//!
//! A finisher is anyone who bought into the coin's final stretch (the last
//! 10% of its curve) through a *bracketed* buy, and held. A bracket is one
//! transaction: `stretch_begin`, then any buy (a pump.fun or Meteora swap,
//! built however that program currently wants it), then `stretch_end`. The
//! program never calls pump.fun or Meteora: it only reads the curve's
//! reserves and the buyer's token balance on both sides of the buy, credits
//! the SOL that landed past the stretch line, and locks the tokens bought
//! there in the coin's `Stretch` vault. A buy that completes the curve also
//! records the finish time, so graduation times are exact even on pump.fun.
//!
//! Locked tokens are what "held" means. A finisher can unlock at any time:
//! before graduation their credit leaves the total; during the hold window
//! after it, they give up their share (it goes back to the funders). After
//! the hold, `claim_finisher` pays each finisher `credit / total` of every
//! pot on that coin, and `stretch_unlock` returns their tokens.
//!
//! Nobody is trusted to decide who gets paid: every step is permissionless
//! or signed by the wallet it pays, and every failure path ends in a refund
//! (no winner in time, no finishers, unclaimed shares).
//!
//! Terms (mint, deadline, split, windows) are fixed at `open_pot`. Anyone can
//! add to an open pot with `fund`; each funder's `Contribution` makes refunds exact.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::Discriminator;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::{read_u64, Config, LaunchError, Route, BPS, CONFIG_SEED, DBC_PROGRAM, NATIVE_MINT, ROUTE_SEED, TOKEN_PROGRAM};

pub const POT_CONFIG_SEED: &[u8] = b"pot-rules";
pub const POT_SEED: &[u8] = b"pot";
pub const CONTRIB_SEED: &[u8] = b"contrib";
pub const ENTRY_SEED: &[u8] = b"entry";
pub const POT_CLAIM_SEED: &[u8] = b"pot-claim";
pub const STRETCH_SEED: &[u8] = b"stretch";
pub const CREDIT_SEED: &[u8] = b"credit";
/// The final stretch starts this far along a curve (basis points).
pub const STRETCH_LINE_BPS: u64 = 9_000;
/// A request's title and brief, in bytes.
pub const BRIEF_MAX: usize = 160;

pub const TOKEN_2022_PROGRAM: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

pub const KIND_BOUNTY: u8 = 0;
pub const KIND_REQUEST: u8 = 1;
/// Where a pot's coin lives. Requests are Corium only; bounties can target pump.fun.
pub const LAUNCHPAD_CORIUM: u8 = 0;
pub const LAUNCHPAD_PUMP: u8 = 1;

pub const PUMP_PROGRAM: Pubkey = pubkey!("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
// pump.fun BondingCurve (public IDL, checked against live mainnet curves of
// 125 and 151 bytes, and pump-sdk 2.0's IDL): discriminator, five u64
// reserves (virtual/real tokens and quote, supply), `complete`, `creator`;
// newer fields (mayhem, quote mint, creator fee...) are appended after.
const PUMP_CURVE_DISC: [u8; 8] = [23, 183, 248, 55, 96, 216, 172, 96];
const PUMP_REAL_TOKENS: usize = 24;
const PUMP_REAL_SOL: usize = 32;
const PUMP_SUPPLY: usize = 40;
/// The only curve shape the stretch ledger measures: 1B tokens, 6 decimals.
const PUMP_STANDARD_SUPPLY: u64 = 1_000_000_000_000_000;
const PUMP_COMPLETE: usize = 48;
const PUMP_CREATOR: usize = 49;
const PUMP_MIN_LEN: usize = 81;
/// Tokens a pump.fun curve sells before it completes (793.1M, 6 decimals).
pub const PUMP_INITIAL_REAL_TOKENS: u64 = 793_100_000_000_000;

pub const STATUS_OPEN: u8 = 0;
/// Fee and creator paid; finishers claim (after the hold) until `expires_at`.
pub const STATUS_PAYING: u8 = 2;
/// Whatever is left goes back to the funders, pro rata.
pub const STATUS_RETURNING: u8 = 3;

// DBC VirtualPool fields beyond the ones lib.rs reads (checked against the
// SDK 1.5.13 IDL: volatility tracker, config, creator, base mint, vaults, reserves).
const POOL_CONFIG: usize = 72;
const POOL_CREATOR: usize = 104;
const POOL_BASE_MINT: usize = 136;
const POOL_BASE_RESERVE: usize = 232;
const POOL_QUOTE_RESERVE: usize = 240;
const POOL_FINISH_CURVE_TS: usize = 344;
const POOL_MIN_LEN: usize = 352;
// Account discriminators (checked on devnet): a VirtualPool and a PoolConfig.
const DBC_POOL_DISC: [u8; 8] = [213, 224, 5, 209, 98, 69, 119, 92];
const DBC_CONFIG_DISC: [u8; 8] = [26, 108, 14, 123, 116, 230, 129, 43];
// DBC PoolConfig: quote mint and the migration threshold (checked on devnet
// against the SDK's decode of the same account).
const CONFIG_QUOTE_MINT: usize = 8;
const CONFIG_THRESHOLD: usize = 264;
const CONFIG_MIN_LEN: usize = 272;
// SPL / Token-2022 token account: mint, owner, amount.
const TA_MINT: usize = 0;
const TA_OWNER: usize = 32;
const TA_AMOUNT: usize = 64;

const MINT_BASE_LEN: usize = 82;
const MINT_DECIMALS: usize = 44;
/// The mint's freeze authority, a COption: a zero tag means none.
const MINT_FREEZE_TAG: usize = 46;
/// A token account's state byte (1 initialized, 2 frozen).
const TA_STATE: usize = 108;
// Bounds on the pot rules, so no window can overflow a clock or strand a pot.
const MAX_WINDOW: i64 = 90 * 86_400;
const MAX_HOLD: i64 = 30 * 86_400;
/// Token-2022 extensions a pot's mint may carry: metadata, groups, close
/// authority. Anything that can move, freeze, tax or hook a transfer is refused.
const ALLOWED_EXTENSIONS: [u16; 7] = [3, 18, 19, 20, 21, 22, 23];

// ------------------------------------------------------------------ handlers

pub fn init_pot_config_ix(ctx: Context<InitPotConfig>, p: PotParams) -> Result<()> {
    p.check()?;
    let c = &mut ctx.accounts.pot_config;
    c.params = p;
    c.bump = ctx.bumps.pot_config;
    Ok(())
}

/// Also grows a pot config written by an older, smaller layout (the admin pays the rent).
pub fn set_pot_config_ix(ctx: Context<SetPotConfig>, p: PotParams) -> Result<()> {
    p.check()?;
    let acc = ctx.accounts.pot_config.to_account_info();
    require_keys_eq!(*acc.owner, crate::ID, LaunchError::BadPool);
    let size = 8 + PotConfig::INIT_SPACE;
    if acc.data_len() < size {
        let need = Rent::get()?.minimum_balance(size).saturating_sub(acc.lamports());
        if need > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new(ctx.accounts.system_program.key(), anchor_lang::system_program::Transfer { from: ctx.accounts.admin.to_account_info(), to: acc.clone() }),
                need,
            )?;
        }
        acc.resize(size)?;
    }
    let bump = ctx.bumps.pot_config;
    let mut data = acc.try_borrow_mut_data()?;
    PotConfig { params: p, bump }.try_serialize(&mut &mut data[..])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn open_pot_ix(
    ctx: Context<OpenPot>,
    nonce: u64,
    kind: u8,
    deadline: i64,
    creator_bps: u16,
    min_stake: u64,
    amount: u64,
    brief: String,
) -> Result<()> {
    let p = ctx.accounts.pot_config.params;
    let now = Clock::get()?.unix_timestamp;
    require!(brief.len() <= BRIEF_MAX, LaunchError::UriTooLong);
    require!(amount > 0, LaunchError::EmptyPot);
    require!(
        deadline >= now.checked_add(p.min_duration).ok_or(LaunchError::Overflow)?
            && deadline <= now.checked_add(p.max_duration).ok_or(LaunchError::Overflow)?,
        LaunchError::BadDeadline
    );
    check_mint(&ctx.accounts.mint, &ctx.accounts.token_program.key())?;
    if ctx.accounts.mint.key() == NATIVE_MINT {
        require!(amount <= p.max_sol, LaunchError::PotTooLarge);
        require!(amount >= p.min_sol, LaunchError::PotTooSmall);
    }

    let (target, coin, launchpad) = match kind {
        KIND_BOUNTY => {
            require!(creator_bps == 0 && min_stake == 0, LaunchError::BadBps);
            let pool = ctx.accounts.target_pool.as_ref().ok_or(LaunchError::BadPool)?;
            if *pool.owner == PUMP_PROGRAM {
                // pump.fun: the curve must be the mint's own PDA, and still open.
                let mint = ctx.accounts.target_mint.as_ref().ok_or(LaunchError::BadPool)?;
                let curve = Pubkey::find_program_address(&[b"bonding-curve", mint.key.as_ref()], &PUMP_PROGRAM).0;
                require_keys_eq!(pool.key(), curve, LaunchError::BadPool);
                require!(!read_pump(pool)?.complete, LaunchError::AlreadyGraduated);
                // Only curves the stretch ledger can measure: others could never have finishers.
                require!(read_u64(&pool.try_borrow_data()?, PUMP_SUPPLY) == PUMP_STANDARD_SUPPLY, LaunchError::BadPool);
                (pool.key(), mint.key(), LAUNCHPAD_PUMP)
            } else {
                let (Some(dbc_config), Some(route)) = (&ctx.accounts.dbc_config, &ctx.accounts.route) else {
                    return err!(LaunchError::BadPool);
                };
                check_route(route, &dbc_config.key())?;
                let v = read_pool(pool)?;
                require_keys_eq!(v.config, dbc_config.key(), LaunchError::WrongConfig);
                require!(v.finished == 0, LaunchError::AlreadyGraduated);
                (pool.key(), v.base_mint, LAUNCHPAD_CORIUM)
            }
        }
        KIND_REQUEST => {
            require!(creator_bps <= p.max_creator_bps, LaunchError::BadBps);
            (Pubkey::default(), Pubkey::default(), LAUNCHPAD_CORIUM)
        }
        _ => return err!(LaunchError::BadKind),
    };

    let a = &ctx.accounts;
    create_ata(&a.sponsor, &a.vault, &a.pot.to_account_info(), &a.mint, &a.token_program, &a.system_program, &a.ata_program)?;
    transfer_checked(&a.sponsor_token, &a.mint, &a.vault, &a.sponsor.to_account_info(), &a.token_program, amount, None)?;

    let pot = &mut ctx.accounts.pot;
    pot.sponsor = ctx.accounts.sponsor.key();
    pot.nonce = nonce;
    pot.kind = kind;
    pot.launchpad = launchpad;
    pot.coin = coin;
    pot.min_stake = min_stake;
    pot.status = STATUS_OPEN;
    pot.mint = ctx.accounts.mint.key();
    pot.token_program = ctx.accounts.token_program.key();
    pot.vault = ctx.accounts.vault.key();
    pot.target = target;
    pot.deadline = deadline;
    pot.grace = p.grace;
    pot.claim_window = p.claim_window;
    pot.entry_max_reserve = p.entry_max_reserve;
    pot.max_sol = p.max_sol;
    pot.creator_bps = creator_bps;
    pot.fee_bps = if kind == KIND_BOUNTY && launchpad == LAUNCHPAD_PUMP { p.bounty_fee_bps } else { 0 };
    pot.funded = amount;
    pot.funders = 1;
    pot.brief = brief;
    pot.bump = ctx.bumps.pot;

    let c = &mut ctx.accounts.contribution;
    c.pot = pot.key();
    c.funder = pot.sponsor;
    c.amount = amount;
    c.bump = ctx.bumps.contribution;

    emit!(PotOpened { pot: pot.key(), sponsor: pot.sponsor, kind, launchpad, mint: pot.mint, target, coin, deadline, creator_bps, min_stake, amount });
    Ok(())
}

pub fn fund_ix(ctx: Context<Fund>, amount: u64) -> Result<()> {
    require!(amount > 0, LaunchError::EmptyPot);
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_OPEN && pot.winner_pool == Pubkey::default(), LaunchError::PotClosed);
    require!(Clock::get()?.unix_timestamp < pot.deadline, LaunchError::PastDeadline);
    let after = pot.funded.checked_add(amount).ok_or(LaunchError::Overflow)?;
    require!(pot.mint != NATIVE_MINT || after <= pot.max_sol, LaunchError::PotTooLarge);

    let a = &ctx.accounts;
    transfer_checked(&a.funder_token, &a.mint, &a.vault, &a.funder.to_account_info(), &a.token_program, amount, None)?;

    let pot = &mut ctx.accounts.pot;
    let c = &mut ctx.accounts.contribution;
    if c.amount == 0 {
        c.pot = pot.key();
        c.funder = ctx.accounts.funder.key();
        c.bump = ctx.bumps.contribution;
        pot.funders = pot.funders.checked_add(1).ok_or(LaunchError::Overflow)?;
    }
    c.amount = c.amount.checked_add(amount).ok_or(LaunchError::Overflow)?;
    pot.funded = pot.funded.checked_add(amount).ok_or(LaunchError::Overflow)?;
    emit!(PotFunded { pot: pot.key(), funder: c.funder, amount, funded: pot.funded });
    Ok(())
}

/// The coin's creator enters it into a request, escrowing `stake` of the coin
/// (at least the opener's `min_stake`). One request per coin, ever, and only
/// while the coin's curve is still early.
pub fn enter_ix(ctx: Context<Enter>, stake: u64) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.kind == KIND_REQUEST, LaunchError::BadKind);
    require!(pot.status == STATUS_OPEN, LaunchError::PotClosed);
    require!(Clock::get()?.unix_timestamp < pot.deadline, LaunchError::PastDeadline);
    check_route(&ctx.accounts.route, &ctx.accounts.dbc_config.key())?;
    let v = read_pool(&ctx.accounts.pool)?;
    require_keys_eq!(v.config, ctx.accounts.dbc_config.key(), LaunchError::WrongConfig);
    require_keys_eq!(v.creator, ctx.accounts.creator.key(), LaunchError::NotCreator);
    require!(v.finished == 0, LaunchError::AlreadyGraduated);
    require!(v.quote_reserve <= pot.entry_max_reserve, LaunchError::EntryTooLate);
    require_keys_eq!(v.base_mint, ctx.accounts.coin_mint.key(), LaunchError::BadMint);
    check_mint(&ctx.accounts.coin_mint, &ctx.accounts.coin_token_program.key())?;
    require!(stake >= pot.min_stake, LaunchError::StakeTooSmall);

    let a = &ctx.accounts;
    if stake > 0 {
        create_ata(&a.creator, &a.stake_vault, &a.entry.to_account_info(), &a.coin_mint, &a.coin_token_program, &a.system_program, &a.ata_program)?;
        transfer_checked(&a.creator_token, &a.coin_mint, &a.stake_vault, &a.creator.to_account_info(), &a.coin_token_program, stake, None)?;
    }

    let e = &mut ctx.accounts.entry;
    e.pot = ctx.accounts.pot.key();
    e.pool = ctx.accounts.pool.key();
    e.creator = ctx.accounts.creator.key();
    e.coin = ctx.accounts.coin_mint.key();
    e.coin_token_program = ctx.accounts.coin_token_program.key();
    e.stake = stake;
    e.bump = ctx.bumps.entry;
    let pot = &mut ctx.accounts.pot;
    pot.entries = pot.entries.checked_add(1).ok_or(LaunchError::Overflow)?;
    emit!(PotEntered { pot: pot.key(), pool: e.pool, creator: e.creator, stake });
    Ok(())
}

/// The request's opener removes an off-topic coin, before it graduates. The
/// entry stays (marked rejected), so the coin can't enter again here or
/// anywhere else. Co-funders join trusting the opener's call.
pub fn reject_entry_ix(ctx: Context<RejectEntry>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_OPEN, LaunchError::PotClosed);
    let e = &ctx.accounts.entry;
    require!(e.pot == pot.key() && !e.rejected, LaunchError::NotEntered);
    // Only while the coin is still early (as it was to enter): an opener can't
    // wait for a coin to near graduation and then cancel it out.
    let v = read_pool(&ctx.accounts.pool)?;
    require!(v.finished == 0, LaunchError::AlreadyGraduated);
    require!(v.quote_reserve <= pot.entry_max_reserve, LaunchError::EntryTooLate);
    ctx.accounts.entry.rejected = true;
    let pot = &mut ctx.accounts.pot;
    pot.entries -= 1;
    emit!(PotEntryRejected { pot: pot.key(), pool: ctx.accounts.pool.key() });
    Ok(())
}

/// Anyone: a coin that graduated by the deadline becomes the winner, or
/// replaces the current winner if it graduated earlier.
pub fn mark_winner_ix(ctx: Context<MarkWinner>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_OPEN, LaunchError::PotClosed);
    // Winners are recorded by the deadline + grace; after it the pot only
    // returns (start_return), and losing stakes go home. The two never race.
    require!(Clock::get()?.unix_timestamp < pot.deadline.checked_add(pot.grace).ok_or(LaunchError::Overflow)?, LaunchError::PastDeadline);
    let pool_key = ctx.accounts.pool.key();
    let mut coin = pot.coin;
    match pot.kind {
        KIND_BOUNTY => require_keys_eq!(pool_key, pot.target, LaunchError::BadPool),
        _ => {
            let entry = ctx.accounts.entry.as_ref().ok_or(LaunchError::NotEntered)?;
            require!(entry.pot == pot.key() && entry.pool == pool_key, LaunchError::NotEntered);
            require!(!entry.rejected, LaunchError::Rejected);
            coin = entry.coin;
        }
    }
    let (finished, creator) = if pot.launchpad == LAUNCHPAD_PUMP {
        // pump.fun curves keep no finish time. A bracketed buy that completed
        // the curve recorded it exactly in the stretch; otherwise the moment
        // it's recorded here counts, and that must be by the deadline.
        let c = read_pump(&ctx.accounts.pool)?;
        require!(c.complete, LaunchError::NotGraduated);
        let now = Clock::get()?.unix_timestamp;
        let recorded = with_stretch(&ctx.accounts.stretch, |s| {
            finish(s, now);
            Ok(s.finished_at)
        })?;
        (recorded.unwrap_or(now), c.creator)
    } else {
        let v = read_pool(&ctx.accounts.pool)?;
        require!(v.finished != 0, LaunchError::NotGraduated);
        (v.finished, v.creator)
    };
    require!(finished <= pot.deadline, LaunchError::PastDeadline);
    let replaces = pot.winner_pool == Pubkey::default() || finished < pot.winner_finish_ts;
    require!(replaces, LaunchError::NotEarlier);

    let pot = &mut ctx.accounts.pot;
    pot.winner_pool = pool_key;
    pot.winner_finish_ts = finished;
    pot.winner_creator = creator;
    pot.coin = coin;
    emit!(PotWinner { pot: pot.key(), pool: pool_key, finished });
    Ok(())
}

/// Anyone, once the grace period after the winner's graduation has passed:
/// Corium's fee to the treasury, the creator's share to the winning coin's
/// creator (requests). The rest is the finisher share, claimed from the
/// winning coin's stretch ledger after its hold; with no finishers there, it
/// goes straight back to the funders.
pub fn settle_ix(ctx: Context<Settle>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_OPEN, LaunchError::PotClosed);
    require!(pot.winner_pool != Pubkey::default(), LaunchError::NoWinner);
    let now = Clock::get()?.unix_timestamp;
    let open_until = pot.winner_finish_ts.checked_add(pot.grace).ok_or(LaunchError::Overflow)?;
    require!(now >= open_until, LaunchError::InGrace);
    require_keys_eq!(ctx.accounts.treasury.key(), ctx.accounts.config.treasury, LaunchError::NotTreasury);
    require_keys_eq!(ctx.accounts.creator.key(), pot.winner_creator, LaunchError::NotCreator);

    let total = pot.funded;
    let fee = mul_bps(total, pot.fee_bps);
    let creator_amount = mul_bps(total - fee, pot.creator_bps);

    let a = &ctx.accounts;
    let seeds = pot_seeds(pot);
    let seeds: &[&[u8]] = &[POT_SEED, &seeds.0, &seeds.1, &seeds.2];
    let pot_ai = a.pot.to_account_info();
    if fee > 0 {
        create_ata(&a.caller, &a.treasury_token, &a.treasury.to_account_info(), &a.mint, &a.token_program, &a.system_program, &a.ata_program)?;
        transfer_checked(&a.vault, &a.mint, &a.treasury_token, &pot_ai, &a.token_program, fee, Some(seeds))?;
    }
    // A creator whose token account can't take it (owner reassigned, frozen)
    // would otherwise block settle forever: their share goes to the finishers.
    let creator_amount = if creator_amount > 0 && payable(&a.creator_token, &a.creator.key())? {
        create_ata(&a.caller, &a.creator_token, &a.creator.to_account_info(), &a.mint, &a.token_program, &a.system_program, &a.ata_program)?;
        transfer_checked(&a.vault, &a.mint, &a.creator_token, &pot_ai, &a.token_program, creator_amount, Some(seeds))?;
        creator_amount
    } else {
        0
    };

    let finishers = total - fee - creator_amount;

    // The winning coin's ledger (its PDA is pinned, so nobody can hide it):
    // freeze its total if nobody has yet, and see when finishers can claim.
    let finish_ts = pot.winner_finish_ts;
    let ledger = with_stretch(&ctx.accounts.stretch, |s| {
        finish(s, finish_ts);
        Ok((s.total_at_finish, s.finished_at.checked_add(s.hold).ok_or(LaunchError::Overflow)?))
    })?;

    let pot = &mut ctx.accounts.pot;
    pot.fee_paid = fee;
    pot.creator_paid = creator_amount;
    pot.finisher_total = finishers;
    match ledger {
        Some((credit, hold_ends)) if credit > 0 && finishers > 0 => {
            pot.status = STATUS_PAYING;
            pot.expires_at = now.max(hold_ends).checked_add(pot.claim_window).ok_or(LaunchError::Overflow)?;
        }
        _ => begin_return(pot, finishers),
    }
    emit!(PotSettled { pot: pot.key(), fee, creator: pot.winner_creator, creator_amount, finishers });
    Ok(())
}

/// A finisher's share of a paying pot: `credit / total` of the finisher
/// share, once the coin's hold window has passed. One claim per wallet per pot.
pub fn claim_finisher_ix(ctx: Context<ClaimFinisher>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_PAYING, LaunchError::PotClosed);
    let now = Clock::get()?.unix_timestamp;
    require!(now < pot.expires_at, LaunchError::Expired);
    let s = &ctx.accounts.stretch;
    require!(s.finished_at != 0 && now >= s.finished_at.checked_add(s.hold).ok_or(LaunchError::Overflow)?, LaunchError::InHold);
    let c = &ctx.accounts.credit;
    require!(!c.forfeited, LaunchError::Forfeited);
    require!(c.credit > 0 && s.total_at_finish > 0, LaunchError::NoCredit);
    let amount = (pot.finisher_total as u128 * c.credit as u128 / s.total_at_finish as u128) as u64;
    require!(amount > 0, LaunchError::EmptyClaim);
    let claimed = pot.claimed.checked_add(amount).ok_or(LaunchError::Overflow)?;
    require!(claimed <= pot.finisher_total, LaunchError::OverClaim);

    let a = &ctx.accounts;
    create_ata(&a.wallet, &a.wallet_token, &a.wallet.to_account_info(), &a.mint, &a.token_program, &a.system_program, &a.ata_program)?;
    let seeds = pot_seeds(pot);
    let seeds: &[&[u8]] = &[POT_SEED, &seeds.0, &seeds.1, &seeds.2];
    transfer_checked(&a.vault, &a.mint, &a.wallet_token, &a.pot.to_account_info(), &a.token_program, amount, Some(seeds))?;

    let pot = &mut ctx.accounts.pot;
    pot.claimed = claimed;
    pot.claims += 1;
    let r = &mut ctx.accounts.claim_record;
    r.amount = amount;
    r.claimed_at = now;
    r.bump = ctx.bumps.claim_record;
    emit!(PotClaimed { pot: pot.key(), wallet: ctx.accounts.wallet.key(), amount });
    Ok(())
}

/// Anyone: start returning what the pot will never pay out. Open with no
/// winner past deadline + grace (everything); paying past the claim window
/// (what the finishers didn't claim, forfeited shares and rounding included).
pub fn start_return_ix(ctx: Context<StartReturn>) -> Result<()> {
    let pot = &mut ctx.accounts.pot;
    let now = Clock::get()?.unix_timestamp;
    let returnable = match pot.status {
        STATUS_OPEN => {
            require!(pot.winner_pool == Pubkey::default(), LaunchError::HasWinner);
            require!(now >= pot.deadline.checked_add(pot.grace).ok_or(LaunchError::Overflow)?, LaunchError::NotExpired);
            pot.funded
        }
        STATUS_PAYING => {
            require!(now >= pot.expires_at, LaunchError::NotExpired);
            pot.finisher_total - pot.claimed
        }
        _ => return err!(LaunchError::PotClosed),
    };
    begin_return(pot, returnable);
    Ok(())
}

/// A funder takes back their share of what's being returned. The last one
/// also gets the rounding dust, so the vault ends empty.
pub fn refund_ix(ctx: Context<Refund>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    require!(pot.status == STATUS_RETURNING, LaunchError::PotClosed);
    let c = &ctx.accounts.contribution;
    require!(!c.refunded, LaunchError::AlreadyRefunded);
    let last = pot.refunds + 1 == pot.funders;
    let amount = if last {
        pot.returnable - pot.returned
    } else {
        (c.amount as u128 * pot.returnable as u128 / pot.funded as u128) as u64
    };

    let a = &ctx.accounts;
    create_ata(&a.funder, &a.funder_token, &a.funder.to_account_info(), &a.mint, &a.token_program, &a.system_program, &a.ata_program)?;
    let seeds = pot_seeds(pot);
    let seeds: &[&[u8]] = &[POT_SEED, &seeds.0, &seeds.1, &seeds.2];
    transfer_checked(&a.vault, &a.mint, &a.funder_token, &a.pot.to_account_info(), &a.token_program, amount, Some(seeds))?;

    let pot = &mut ctx.accounts.pot;
    pot.returned = pot.returned.checked_add(amount).ok_or(LaunchError::Overflow)?;
    pot.refunds += 1;
    ctx.accounts.contribution.refunded = true;
    emit!(PotRefunded { pot: pot.key(), funder: ctx.accounts.funder.key(), amount });
    Ok(())
}

/// Anyone: a funder's share of the winning coin's stake, to the funder's
/// token account. Pro rata to their contribution; the last one also gets the
/// rounding dust. Open once the pot has settled on that coin.
pub fn claim_stake_ix(ctx: Context<ClaimStake>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    let e = &ctx.accounts.entry;
    require!(e.pot == pot.key(), LaunchError::NotEntered);
    require!(pot.status != STATUS_OPEN && pot.winner_pool == e.pool, LaunchError::NotWinner);
    require!(e.stake > 0 && !e.released, LaunchError::NothingStaked);
    let c = &ctx.accounts.contribution;
    require!(!c.stake_claimed, LaunchError::AlreadyClaimed);
    require_keys_eq!(ctx.accounts.funder.key(), c.funder, LaunchError::NotFunder);
    let last = e.stake_claims + 1 == pot.funders;
    let amount = if last { e.stake - e.stake_claimed } else { (e.stake as u128 * c.amount as u128 / pot.funded as u128) as u64 };

    let a = &ctx.accounts;
    create_ata(&a.caller, &a.funder_token, &a.funder.to_account_info(), &a.coin_mint, &a.coin_token_program, &a.system_program, &a.ata_program)?;
    let pool = e.pool;
    let bump = [e.bump];
    let seeds: &[&[u8]] = &[ENTRY_SEED, pool.as_ref(), &bump];
    transfer_checked(&a.stake_vault, &a.coin_mint, &a.funder_token, &a.entry.to_account_info(), &a.coin_token_program, amount, Some(seeds))?;

    let e = &mut ctx.accounts.entry;
    e.stake_claimed = e.stake_claimed.checked_add(amount).ok_or(LaunchError::Overflow)?;
    e.stake_claims += 1;
    ctx.accounts.contribution.stake_claimed = true;
    emit!(PotStakeClaimed { pot: ctx.accounts.pot.key(), funder: ctx.accounts.funder.key(), amount });
    Ok(())
}

/// Anyone: a losing (or rejected) entry's stake back to its creator, once
/// the request is decided: settled on another coin, returning with no
/// winner, or past deadline + grace with none.
pub fn release_stake_ix(ctx: Context<ReleaseStake>) -> Result<()> {
    let pot = &ctx.accounts.pot;
    let e = &ctx.accounts.entry;
    require!(e.pot == pot.key(), LaunchError::NotEntered);
    require!(e.stake > 0, LaunchError::NothingStaked);
    require!(!e.released, LaunchError::AlreadyClaimed);
    require_keys_eq!(ctx.accounts.creator.key(), e.creator, LaunchError::NotCreator);
    let now = Clock::get()?.unix_timestamp;
    let no_winner_past_deadline =
        pot.winner_pool == Pubkey::default() && now >= pot.deadline.checked_add(pot.grace).ok_or(LaunchError::Overflow)?;
    let lost = e.rejected || (pot.status != STATUS_OPEN && pot.winner_pool != e.pool) || (pot.status == STATUS_OPEN && no_winner_past_deadline);
    require!(lost, LaunchError::NotDecided);

    let a = &ctx.accounts;
    create_ata(&a.caller, &a.creator_token, &a.creator.to_account_info(), &a.coin_mint, &a.coin_token_program, &a.system_program, &a.ata_program)?;
    let pool = e.pool;
    let bump = [e.bump];
    let seeds: &[&[u8]] = &[ENTRY_SEED, pool.as_ref(), &bump];
    let stake = e.stake;
    transfer_checked(&a.stake_vault, &a.coin_mint, &a.creator_token, &a.entry.to_account_info(), &a.coin_token_program, stake, Some(seeds))?;
    ctx.accounts.entry.released = true;
    emit!(PotStakeReleased { pot: ctx.accounts.pot.key(), pool, creator: ctx.accounts.creator.key(), amount: stake });
    Ok(())
}

// ------------------------------------------------------------------ the stretch ledger

/// Open a bracket around a buy of `pool`'s coin: snapshot the curve and the
/// buyer's balance. The same transaction must end it with `stretch_end` for
/// this wallet and coin (checked here), so nothing but that transaction's own
/// instructions can land between the two snapshots.
pub fn stretch_begin_ix(ctx: Context<StretchBegin>) -> Result<()> {
    let curve = read_curve(&ctx.accounts.pool, ctx.accounts.dbc_config.as_ref(), &ctx.accounts.coin_mint.key())?;
    require!(!curve.complete, LaunchError::AlreadyGraduated);
    let wallet = ctx.accounts.wallet.key();
    let token_program = ctx.accounts.token_program.key();
    check_mint(&ctx.accounts.coin_mint, &token_program)?;
    let user = token_balance(&ctx.accounts.wallet_token, &wallet, &ctx.accounts.coin_mint.key(), &token_program)?;

    // The matching end, later in this transaction, for this credit account.
    let ixs = ctx.accounts.instructions.to_account_info();
    let here = load_current_index_checked(&ixs)? as usize;
    let credit_key = ctx.accounts.credit.key();
    let mut ended = false;
    for i in here + 1.. {
        let Ok(ix) = load_instruction_at_checked(i, &ixs) else { break };
        if ix.program_id == crate::ID && ix.data.starts_with(crate::instruction::StretchEnd::DISCRIMINATOR) && ix.accounts.get(END_CREDIT_AT).map(|m| m.pubkey) == Some(credit_key) {
            ended = true;
            break;
        }
    }
    require!(ended, LaunchError::NoBracketEnd);

    let s = &mut ctx.accounts.stretch;
    if s.pool == Pubkey::default() {
        s.pool = ctx.accounts.pool.key();
        s.mint = ctx.accounts.coin_mint.key();
        s.token_program = token_program;
        s.launchpad = curve.launchpad;
        s.line = curve.line;
        s.hold = ctx.accounts.pot_config.params.hold;
        s.bump = ctx.bumps.stretch;
    }
    let c = &mut ctx.accounts.credit;
    if c.wallet == Pubkey::default() {
        c.pool = s.pool;
        c.wallet = wallet;
        c.bump = ctx.bumps.credit;
    }
    require!(!c.open, LaunchError::BracketOpen);
    // One bracket per coin at a time: brackets can't overlap on the same buy.
    let s = &mut ctx.accounts.stretch;
    require!(s.bracket == Pubkey::default(), LaunchError::BracketOpen);
    s.bracket = credit_key;
    let c = &mut ctx.accounts.credit;
    c.open = true;
    c.snap_sol = curve.sol;
    c.snap_progress = curve.progress;
    c.snap_tokens = curve.tokens;
    c.snap_user = user;
    Ok(())
}

/// Close the bracket: credit the SOL that entered the curve past the stretch
/// line, and lock the tokens bought there. The buyer must have received every
/// token the curve let go of in between, or nothing is credited (someone
/// else's buy inside the bracket earns this wallet nothing). Never fails
/// because of where the price went: a buy that stayed below the line just
/// earns no credit. A buy that completed the curve records the finish.
pub fn stretch_end_ix(ctx: Context<StretchEnd>) -> Result<()> {
    let c = &ctx.accounts.credit;
    require!(c.open && ctx.accounts.stretch.bracket == c.key(), LaunchError::NoBracket);
    ctx.accounts.stretch.bracket = Pubkey::default();
    let s = &ctx.accounts.stretch;
    let curve = read_curve(&ctx.accounts.pool, ctx.accounts.dbc_config.as_ref(), &s.mint)?;
    let wallet = ctx.accounts.wallet.key();
    let user = token_balance(&ctx.accounts.wallet_token, &wallet, &s.mint, &s.token_program)?;

    // A frozen ledger takes no more credit: every pot divides by the total at
    // the finish, so credit added after it (a `stretch_finish` slipped into the
    // bracket) would be paid out of everyone else's share.
    let (credit, lock) = if s.finished_at == 0 {
        stretch_credit(s.line.max(s.high_water), c.snap_sol, curve.sol, c.snap_progress, curve.progress, c.snap_tokens, curve.tokens, user.saturating_sub(c.snap_user))
    } else {
        (0, 0)
    };
    let c = &mut ctx.accounts.credit;
    c.open = false;
    if curve.progress > ctx.accounts.stretch.high_water && ctx.accounts.stretch.finished_at == 0 {
        ctx.accounts.stretch.high_water = curve.progress;
    }
    if credit > 0 && lock > 0 {
        let a = &ctx.accounts;
        create_ata(&a.wallet, &a.vault, &a.stretch.to_account_info(), &a.coin_mint, &a.token_program, &a.system_program, &a.ata_program)?;
        transfer_checked(&a.wallet_token, &a.coin_mint, &a.vault, &a.wallet.to_account_info(), &a.token_program, lock, None)?;
        let c = &mut ctx.accounts.credit;
        c.credit = c.credit.checked_add(credit).ok_or(LaunchError::Overflow)?;
        c.tokens = c.tokens.checked_add(lock).ok_or(LaunchError::Overflow)?;
        let s = &mut ctx.accounts.stretch;
        s.total_credit = s.total_credit.checked_add(credit).ok_or(LaunchError::Overflow)?;
        emit!(StretchCredited { pool: s.pool, wallet, credit, tokens: lock });
    }
    if curve.complete {
        let at = if curve.finished != 0 { curve.finished } else { Clock::get()?.unix_timestamp };
        finish(&mut ctx.accounts.stretch, at);
    }
    Ok(())
}

/// Anyone: record that the coin's curve completed (and freeze its credit).
pub fn stretch_finish_ix(ctx: Context<StretchFinish>) -> Result<()> {
    let s = &ctx.accounts.stretch;
    let curve = read_curve(&ctx.accounts.pool, ctx.accounts.dbc_config.as_ref(), &s.mint)?;
    require!(curve.complete, LaunchError::NotGraduated);
    let at = if curve.finished != 0 { curve.finished } else { Clock::get()?.unix_timestamp };
    finish(&mut ctx.accounts.stretch, at);
    Ok(())
}

/// The finisher takes their locked tokens back. Before graduation this
/// withdraws their credit; inside the hold window after it, it forfeits
/// their share of every pot on the coin; after the hold it just returns the
/// tokens (their credit still claims).
pub fn stretch_unlock_ix(ctx: Context<StretchUnlock>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let curve = read_curve(&ctx.accounts.pool, ctx.accounts.dbc_config.as_ref(), &ctx.accounts.stretch.mint)?;
    if curve.complete {
        finish(&mut ctx.accounts.stretch, if curve.finished != 0 { curve.finished } else { now });
    }
    let c = &ctx.accounts.credit;
    require!(!c.open, LaunchError::BracketOpen);
    let tokens = c.tokens;
    require!(tokens > 0, LaunchError::NothingLocked);
    let s = &ctx.accounts.stretch;
    let forfeited = if s.finished_at == 0 {
        let s = &mut ctx.accounts.stretch;
        s.total_credit = s.total_credit.saturating_sub(ctx.accounts.credit.credit);
        ctx.accounts.credit.credit = 0;
        false
    } else if now < s.finished_at.checked_add(s.hold).ok_or(LaunchError::Overflow)? {
        ctx.accounts.credit.forfeited = true;
        true
    } else {
        false
    };

    let a = &ctx.accounts;
    create_ata(&a.wallet, &a.wallet_token, &a.wallet.to_account_info(), &a.coin_mint, &a.token_program, &a.system_program, &a.ata_program)?;
    let pool = a.stretch.pool;
    let bump = [a.stretch.bump];
    let seeds: &[&[u8]] = &[STRETCH_SEED, pool.as_ref(), &bump];
    transfer_checked(&a.vault, &a.coin_mint, &a.wallet_token, &a.stretch.to_account_info(), &a.token_program, tokens, Some(seeds))?;
    let wallet = a.wallet.key();
    ctx.accounts.credit.tokens = 0;
    emit!(StretchUnlocked { pool, wallet, tokens, forfeited });
    Ok(())
}

/// The wallet closes its (empty) credit account for the rent. Its claims on
/// pots it hasn't claimed yet go with it.
pub fn close_credit_ix(ctx: Context<CloseCredit>) -> Result<()> {
    let c = &ctx.accounts.credit;
    require!(c.tokens == 0 && !c.open, LaunchError::StillLocked);
    Ok(())
}

// ------------------------------------------------------------------ helpers

fn begin_return(pot: &mut Account<Pot>, returnable: u64) {
    pot.returnable = returnable;
    pot.status = STATUS_RETURNING;
    emit!(PotReturning { pot: pot.key(), returnable });
}

/// Freeze the ledger at the curve's completion (first call wins).
fn finish(s: &mut Stretch, at: i64) {
    if s.finished_at == 0 {
        s.finished_at = at;
        s.total_at_finish = s.total_credit;
        emit!(StretchFinished { pool: s.pool, finished_at: at, total_credit: s.total_credit });
    }
}

/// Run `f` on the stretch ledger at `acc` (its address is pinned by the
/// caller's seeds) and write it back; `None` if nobody ever bracketed a buy
/// of that coin, so the account doesn't exist.
fn with_stretch<T>(acc: &UncheckedAccount, f: impl FnOnce(&mut Stretch) -> Result<T>) -> Result<Option<T>> {
    if acc.data_is_empty() {
        return Ok(None);
    }
    require_keys_eq!(*acc.owner, crate::ID, LaunchError::BadPool);
    let mut s = Stretch::try_deserialize(&mut &acc.try_borrow_data()?[..])?;
    let out = f(&mut s)?;
    s.try_serialize(&mut &mut acc.try_borrow_mut_data()?[..])?;
    Ok(Some(out))
}

/// Credit and tokens to lock for one bracket, from the curve before and after.
/// `progress` is the curve's own measure (DBC: SOL reserve; pump.fun: tokens
/// sold) and `from` where credit starts in it: the stretch line, or the
/// ledger's high-water mark once buys have been credited past it. Only new
/// ground counts, so selling down and buying the same stretch again, or
/// nesting brackets around one buy, credits nothing twice: all the credit on
/// a coin together never covers more than its stretch once. The SOL that
/// entered and the tokens that left are both split by how much of the move
/// landed past `from`. Nothing unless the buyer received at least every token
/// the curve released.
#[allow(clippy::too_many_arguments)]
pub fn stretch_credit(from: u64, sol0: u64, sol1: u64, p0: u64, p1: u64, tokens0: u64, tokens1: u64, received: u64) -> (u64, u64) {
    if sol1 <= sol0 || p1 <= p0 || tokens1 >= tokens0 {
        return (0, 0);
    }
    let start = p0.max(from);
    if p1 <= start {
        return (0, 0);
    }
    let (sol_in, moved, past, released) = ((sol1 - sol0) as u128, (p1 - p0) as u128, (p1 - start) as u128, tokens0 - tokens1);
    if received < released {
        return (0, 0);
    }
    ((sol_in * past / moved) as u64, (released as u128 * past / moved) as u64)
}

/// A curve as the stretch ledger reads it.
struct CurveView {
    launchpad: u8,
    /// Quote in the curve (DBC quote reserve / pump.fun real quote, SOL for
    /// most coins). Credit only ever compares within one coin, so the unit
    /// just has to be the same for all its buyers.
    sol: u64,
    /// Where along the curve it is (DBC: quote reserve; pump.fun: tokens sold).
    progress: u64,
    /// Where the stretch starts, in `progress` units.
    line: u64,
    /// Tokens the curve still holds for sale (DBC base reserve / pump.fun real tokens).
    tokens: u64,
    complete: bool,
    /// DBC's own completion time; 0 on pump.fun (none kept).
    finished: i64,
}

/// A DBC pool (SOL-quoted, with its config) or a pump.fun curve for `mint`.
fn read_curve(pool: &UncheckedAccount, dbc_config: Option<&UncheckedAccount>, mint: &Pubkey) -> Result<CurveView> {
    if *pool.owner == PUMP_PROGRAM {
        let expected = Pubkey::find_program_address(&[b"bonding-curve", mint.as_ref()], &PUMP_PROGRAM).0;
        require_keys_eq!(pool.key(), expected, LaunchError::BadPool);
        let data = pool.try_borrow_data()?;
        require!(data.len() >= PUMP_MIN_LEN && data[..8] == PUMP_CURVE_DISC, LaunchError::BadPool);
        // Other supplies (mayhem mode) sell a different amount: their stretch
        // line isn't known, so they get no ledger (their pots' finisher share refunds).
        require!(read_u64(&data, PUMP_SUPPLY) == PUMP_STANDARD_SUPPLY, LaunchError::BadPool);
        let real_tokens = read_u64(&data, PUMP_REAL_TOKENS);
        let sold = PUMP_INITIAL_REAL_TOKENS.saturating_sub(real_tokens);
        return Ok(CurveView {
            launchpad: LAUNCHPAD_PUMP,
            sol: read_u64(&data, PUMP_REAL_SOL),
            progress: sold,
            line: (PUMP_INITIAL_REAL_TOKENS as u128 * STRETCH_LINE_BPS as u128 / BPS as u128) as u64,
            tokens: real_tokens,
            complete: data[PUMP_COMPLETE] != 0,
            finished: 0,
        });
    }
    let v = read_pool(pool)?;
    require_keys_eq!(v.base_mint, *mint, LaunchError::BadMint);
    let cfg = dbc_config.ok_or(LaunchError::WrongConfig)?;
    require_keys_eq!(cfg.key(), v.config, LaunchError::WrongConfig);
    require_keys_eq!(*cfg.owner, DBC_PROGRAM, LaunchError::WrongConfig);
    let data = cfg.try_borrow_data()?;
    require!(data.len() >= CONFIG_MIN_LEN && data[..8] == DBC_CONFIG_DISC, LaunchError::WrongConfig);
    require_keys_eq!(Pubkey::new_from_array(data[CONFIG_QUOTE_MINT..CONFIG_QUOTE_MINT + 32].try_into().unwrap()), NATIVE_MINT, LaunchError::BadMint);
    let threshold = read_u64(&data, CONFIG_THRESHOLD);
    let base = {
        let p = pool.try_borrow_data()?;
        read_u64(&p, POOL_BASE_RESERVE)
    };
    Ok(CurveView {
        launchpad: LAUNCHPAD_CORIUM,
        sol: v.quote_reserve,
        progress: v.quote_reserve,
        line: (threshold as u128 * STRETCH_LINE_BPS as u128 / BPS as u128) as u64,
        tokens: base,
        complete: v.finished != 0,
        finished: v.finished,
    })
}

/// `wallet`'s balance of `mint` in its associated token account; 0 before it exists.
fn token_balance(acc: &UncheckedAccount, wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<u64> {
    let expected = Pubkey::find_program_address(&[wallet.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_PROGRAM).0;
    require_keys_eq!(acc.key(), expected, LaunchError::BadTokenAccount);
    if acc.data_is_empty() {
        return Ok(0);
    }
    require_keys_eq!(*acc.owner, *token_program, LaunchError::BadTokenAccount);
    let data = acc.try_borrow_data()?;
    require!(data.len() >= TA_AMOUNT + 8, LaunchError::BadTokenAccount);
    require_keys_eq!(Pubkey::new_from_array(data[TA_MINT..TA_MINT + 32].try_into().unwrap()), *mint, LaunchError::BadTokenAccount);
    require_keys_eq!(Pubkey::new_from_array(data[TA_OWNER..TA_OWNER + 32].try_into().unwrap()), *wallet, LaunchError::BadTokenAccount);
    Ok(read_u64(&data, TA_AMOUNT))
}

fn mul_bps(amount: u64, bps: u16) -> u64 {
    (amount as u128 * bps as u128 / BPS as u128) as u64
}

fn pot_seeds(pot: &Pot) -> ([u8; 32], [u8; 8], [u8; 1]) {
    (pot.sponsor.to_bytes(), pot.nonce.to_le_bytes(), [pot.bump])
}

/// The DBC pool fields pots read, copied out.
struct PoolView {
    config: Pubkey,
    creator: Pubkey,
    base_mint: Pubkey,
    quote_reserve: u64,
    finished: i64,
}

fn read_pool(pool: &UncheckedAccount) -> Result<PoolView> {
    require_keys_eq!(*pool.owner, DBC_PROGRAM, LaunchError::BadPool);
    let data = pool.try_borrow_data()?;
    require!(data.len() >= POOL_MIN_LEN && data[..8] == DBC_POOL_DISC, LaunchError::BadPool);
    let key = |at: usize| Pubkey::new_from_array(data[at..at + 32].try_into().unwrap());
    Ok(PoolView {
        config: key(POOL_CONFIG),
        creator: key(POOL_CREATOR),
        base_mint: key(POOL_BASE_MINT),
        quote_reserve: read_u64(&data, POOL_QUOTE_RESERVE),
        finished: read_u64(&data, POOL_FINISH_CURVE_TS) as i64,
    })
}

struct PumpView {
    complete: bool,
    creator: Pubkey,
}

fn read_pump(curve: &UncheckedAccount) -> Result<PumpView> {
    require_keys_eq!(*curve.owner, PUMP_PROGRAM, LaunchError::BadPool);
    let data = curve.try_borrow_data()?;
    require!(data.len() >= PUMP_MIN_LEN && data[..8] == PUMP_CURVE_DISC, LaunchError::BadPool);
    Ok(PumpView { complete: data[PUMP_COMPLETE] != 0, creator: Pubkey::new_from_array(data[PUMP_CREATOR..PUMP_CREATOR + 32].try_into().unwrap()) })
}

fn check_route(route: &Account<Route>, dbc_config: &Pubkey) -> Result<()> {
    require_keys_eq!(route.dbc_config, *dbc_config, LaunchError::WrongConfig);
    Ok(())
}

/// The mint belongs to `token_program`, nobody can freeze its accounts (a
/// frozen vault would strand everyone in it), and a Token-2022 mint carries
/// only harmless extensions. For pot mints and coin mints alike.
fn check_mint(mint: &UncheckedAccount, token_program: &Pubkey) -> Result<()> {
    require!(*token_program == TOKEN_PROGRAM || *token_program == TOKEN_2022_PROGRAM, LaunchError::BadMint);
    require_keys_eq!(*mint.owner, *token_program, LaunchError::BadMint);
    let data = mint.try_borrow_data()?;
    require!(data.len() >= MINT_BASE_LEN, LaunchError::BadMint);
    require!(data[MINT_FREEZE_TAG..MINT_FREEZE_TAG + 4] == [0; 4], LaunchError::BadMint);
    if *token_program == TOKEN_PROGRAM {
        return Ok(());
    }
    require_keys_eq!(*token_program, TOKEN_2022_PROGRAM, LaunchError::BadMint);
    if data.len() == MINT_BASE_LEN {
        return Ok(());
    }
    // Extended mints: base padded to 165, account type (1 = mint), then TLV.
    require!(data.len() > 166 && data[165] == 1, LaunchError::BadMint);
    let mut at = 166;
    while at + 4 <= data.len() {
        let kind = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        if kind == 0 {
            break;
        }
        require!(ALLOWED_EXTENSIONS.contains(&kind), LaunchError::MintExtension);
        at += 4 + len;
    }
    Ok(())
}

/// Whether a transfer to `owner`'s associated token account can land: it
/// doesn't exist yet (it will be created), or it's still `owner`'s and not frozen.
fn payable(ata: &UncheckedAccount, owner: &Pubkey) -> Result<bool> {
    if ata.data_is_empty() {
        return Ok(true);
    }
    let data = ata.try_borrow_data()?;
    Ok(data.len() > TA_STATE && data[TA_OWNER..TA_OWNER + 32] == owner.to_bytes() && data[TA_STATE] == 1)
}

/// CreateIdempotent on the associated token program: `owner`'s account for `mint`.
fn create_ata<'info>(
    payer: &Signer<'info>,
    ata: &UncheckedAccount<'info>,
    owner: &AccountInfo<'info>,
    mint: &UncheckedAccount<'info>,
    token_program: &UncheckedAccount<'info>,
    system: &Program<'info, System>,
    ata_program: &UncheckedAccount<'info>,
) -> Result<()> {
    let expected = Pubkey::find_program_address(&[owner.key.as_ref(), token_program.key.as_ref(), mint.key.as_ref()], &ATA_PROGRAM).0;
    require_keys_eq!(ata.key(), expected, LaunchError::BadTokenAccount);
    invoke(
        &Instruction {
            program_id: ATA_PROGRAM,
            accounts: vec![
                AccountMeta::new(payer.key(), true),
                AccountMeta::new(ata.key(), false),
                AccountMeta::new_readonly(owner.key(), false),
                AccountMeta::new_readonly(mint.key(), false),
                AccountMeta::new_readonly(system.key(), false),
                AccountMeta::new_readonly(token_program.key(), false),
            ],
            data: vec![1],
        },
        &[
            payer.to_account_info(),
            ata.to_account_info(),
            owner.clone(),
            mint.to_account_info(),
            system.to_account_info(),
            token_program.to_account_info(),
            ata_program.to_account_info(),
        ],
    )?;
    Ok(())
}

/// TransferChecked (tag 12), valid on both token programs. `seeds` signs for a pot.
fn transfer_checked<'info>(
    from: &UncheckedAccount<'info>,
    mint: &UncheckedAccount<'info>,
    to: &UncheckedAccount<'info>,
    authority: &AccountInfo<'info>,
    token_program: &UncheckedAccount<'info>,
    amount: u64,
    seeds: Option<&[&[u8]]>,
) -> Result<()> {
    let decimals = {
        let data = mint.try_borrow_data()?;
        require!(data.len() >= MINT_BASE_LEN, LaunchError::BadMint);
        data[MINT_DECIMALS]
    };
    let ix = Instruction {
        program_id: token_program.key(),
        accounts: vec![
            AccountMeta::new(from.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new(to.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data: [&[12u8][..], &amount.to_le_bytes(), &[decimals]].concat(),
    };
    let infos = [from.to_account_info(), mint.to_account_info(), to.to_account_info(), authority.clone(), token_program.to_account_info()];
    match seeds {
        Some(s) => invoke_signed(&ix, &infos, &[s])?,
        None => invoke(&ix, &infos)?,
    }
    Ok(())
}

// ------------------------------------------------------------------ accounts

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace)]
pub struct PotParams {
    /// Corium's cut of a pump.fun bounty that pays out. Bounties on Corium
    /// coins and requests pay none: every coin in them trades on Corium's
    /// curve, and that volume already earns Corium its fees.
    pub bounty_fee_bps: u16,
    /// Most a request opener can give the winning creator.
    pub max_creator_bps: u16,
    pub min_duration: i64,
    pub max_duration: i64,
    /// After the winner's graduation, time for an earlier graduate to replace it.
    pub grace: i64,
    pub claim_window: i64,
    /// A coin can enter a request only while its quote reserve is at most this.
    pub entry_max_reserve: u64,
    /// Most a SOL pot may hold. Faking a graduation costs roughly a fifth of
    /// the curve (buy it all, dump into the migrated pool), so pots stay
    /// below that. Other mints can't be priced on chain.
    pub max_sol: u64,
    /// Least a SOL pot opens with, so boards aren't flooded with dust pots.
    /// (Opening already costs ~0.007 SOL of rent nobody gets back.)
    pub min_sol: u64,
    /// How long finishers' stretch tokens stay locked after the coin
    /// graduates, for their share to count. Copied into each coin's ledger
    /// when it opens.
    pub hold: i64,
}

impl PotParams {
    fn check(&self) -> Result<()> {
        require!(self.bounty_fee_bps as u64 <= BPS && self.max_creator_bps as u64 <= BPS, LaunchError::BadBps);
        require!(self.min_duration > 0 && self.max_duration >= self.min_duration, LaunchError::BadDeadline);
        require!(self.max_duration <= MAX_WINDOW, LaunchError::BadDeadline);
        require!(
            (0..=MAX_WINDOW).contains(&self.grace) && (1..=MAX_WINDOW).contains(&self.claim_window) && (1..=MAX_HOLD).contains(&self.hold),
            LaunchError::BadWindow
        );
        require!(self.max_sol > 0 && self.min_sol <= self.max_sol, LaunchError::PotTooLarge);
        Ok(())
    }
}

/// Pot settings, copied into each pot at `open_pot`: a change never alters an open pot.
#[account]
#[derive(InitSpace)]
pub struct PotConfig {
    pub params: PotParams,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Pot {
    pub sponsor: Pubkey,
    pub nonce: u64,
    pub kind: u8,
    pub launchpad: u8,
    pub status: u8,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    /// The pot PDA's associated token account for `mint`.
    pub vault: Pubkey,
    /// Bounty: the coin's DBC pool or pump.fun bonding curve. Request: default.
    pub target: Pubkey,
    /// The coin's mint: a bounty's target, a request's winner once marked.
    pub coin: Pubkey,
    /// Requests: the least stake (in the entering coin's units) an entry escrows.
    pub min_stake: u64,
    pub deadline: i64,
    pub grace: i64,
    pub claim_window: i64,
    pub entry_max_reserve: u64,
    pub max_sol: u64,
    pub creator_bps: u16,
    pub fee_bps: u16,
    pub funded: u64,
    pub funders: u32,
    pub entries: u32,
    pub winner_pool: Pubkey,
    pub winner_finish_ts: i64,
    pub winner_creator: Pubkey,
    pub fee_paid: u64,
    pub creator_paid: u64,
    pub finisher_total: u64,
    pub claims: u32,
    pub claimed: u64,
    pub expires_at: i64,
    pub returnable: u64,
    pub returned: u64,
    pub refunds: u32,
    pub bump: u8,
    /// Requests: "title\nbrief", on chain (no pinning: nothing off chain to
    /// pay for per request).
    #[max_len(BRIEF_MAX)]
    pub brief: String,
}

/// A coin's final-stretch ledger: every bracketed buy past its stretch line,
/// shared by all the pots on that coin. Holds the locked tokens.
#[account]
#[derive(InitSpace)]
pub struct Stretch {
    /// The DBC pool or pump.fun bonding curve.
    pub pool: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub launchpad: u8,
    /// Where the stretch starts: DBC quote reserve, or pump.fun tokens sold.
    pub line: u64,
    /// The furthest any bracket has seen the curve (same units): credit is
    /// only for ground past it.
    pub high_water: u64,
    /// The credit whose bracket is open right now (one per coin, within one transaction).
    pub bracket: Pubkey,
    pub hold: i64,
    /// Credit (lamports bought past the line) of every finisher still in.
    pub total_credit: u64,
    /// When the curve completed; 0 until recorded.
    pub finished_at: i64,
    /// `total_credit` frozen at completion: every pot's claims divide by it.
    pub total_at_finish: u64,
    pub bump: u8,
}

/// One wallet's stretch credit on one coin, its locked tokens, and an open
/// bracket's snapshot.
#[account]
#[derive(InitSpace)]
pub struct Credit {
    pub pool: Pubkey,
    pub wallet: Pubkey,
    pub credit: u64,
    pub tokens: u64,
    /// Unlocked inside the hold window: no share of any pot.
    pub forfeited: bool,
    pub open: bool,
    pub snap_sol: u64,
    pub snap_progress: u64,
    pub snap_tokens: u64,
    pub snap_user: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Contribution {
    pub pot: Pubkey,
    pub funder: Pubkey,
    pub amount: u64,
    pub refunded: bool,
    /// Took their share of the winning entry's stake.
    pub stake_claimed: bool,
    pub bump: u8,
}

/// A coin entered into a request. Seeded by the pool alone: one request per coin.
#[account]
#[derive(InitSpace)]
pub struct Entry {
    pub pot: Pubkey,
    pub pool: Pubkey,
    pub creator: Pubkey,
    /// Removed by the request's opener; can never win.
    pub rejected: bool,
    pub coin: Pubkey,
    pub coin_token_program: Pubkey,
    /// Coin units escrowed in the entry's own token account.
    pub stake: u64,
    /// Winner: paid out to funders so far.
    pub stake_claimed: u64,
    pub stake_claims: u32,
    /// Loser: returned to the creator.
    pub released: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct PotClaim {
    pub amount: u64,
    pub claimed_at: i64,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct InitPotConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(init, payer = admin, space = 8 + PotConfig::INIT_SPACE, seeds = [POT_CONFIG_SEED], bump)]
    pub pot_config: Account<'info, PotConfig>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPotConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    /// CHECK: the pot config PDA, rewritten (and grown) by the handler.
    #[account(mut, seeds = [POT_CONFIG_SEED], bump)]
    pub pot_config: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct OpenPot<'info> {
    #[account(mut)]
    pub sponsor: Signer<'info>,
    #[account(seeds = [POT_CONFIG_SEED], bump = pot_config.bump)]
    pub pot_config: Account<'info, PotConfig>,
    #[account(init, payer = sponsor, space = 8 + Pot::INIT_SPACE, seeds = [POT_SEED, sponsor.key().as_ref(), &nonce.to_le_bytes()], bump)]
    pub pot: Account<'info, Pot>,
    #[account(init, payer = sponsor, space = 8 + Contribution::INIT_SPACE, seeds = [CONTRIB_SEED, pot.key().as_ref(), sponsor.key().as_ref()], bump)]
    pub contribution: Account<'info, Contribution>,
    /// CHECK: owner and extensions checked in `check_mint`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the pot's associated token account, created here (address checked).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the sponsor's source account; the token program checks it.
    #[account(mut)]
    pub sponsor_token: UncheckedAccount<'info>,
    /// Bounty only: the target coin's DBC pool (with its config and route) or
    /// its pump.fun bonding curve (with its mint).
    /// CHECK: owner and layout checked in `read_pool` / `read_pump`.
    pub target_pool: Option<UncheckedAccount<'info>>,
    /// CHECK: pump.fun only; the curve must be this mint's PDA.
    pub target_mint: Option<UncheckedAccount<'info>>,
    /// CHECK: checked against the route and the pool.
    pub dbc_config: Option<UncheckedAccount<'info>>,
    #[account(seeds = [ROUTE_SEED, dbc_config.as_ref().map(|c| c.key()).unwrap_or_default().as_ref()], bump = route.bump)]
    pub route: Option<Account<'info, Route>>,
    /// CHECK: SPL Token or Token-2022, checked in `check_mint`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump, has_one = mint, has_one = vault, has_one = token_program)]
    pub pot: Account<'info, Pot>,
    #[account(init_if_needed, payer = funder, space = 8 + Contribution::INIT_SPACE, seeds = [CONTRIB_SEED, pot.key().as_ref(), funder.key().as_ref()], bump)]
    pub contribution: Account<'info, Contribution>,
    /// CHECK: pinned by `has_one`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the funder's source account; the token program checks it.
    #[account(mut)]
    pub funder_token: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Enter<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump)]
    pub pot: Account<'info, Pot>,
    #[account(init, payer = creator, space = 8 + Entry::INIT_SPACE, seeds = [ENTRY_SEED, pool.key().as_ref()], bump)]
    pub entry: Account<'info, Entry>,
    /// CHECK: owner, config, creator and progress checked in `enter`.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: checked against the route and the pool.
    pub dbc_config: UncheckedAccount<'info>,
    #[account(seeds = [ROUTE_SEED, dbc_config.key().as_ref()], bump = route.bump)]
    pub route: Account<'info, Route>,
    /// CHECK: must be the pool's base mint (checked).
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the creator's source account; the token program checks it.
    #[account(mut)]
    pub creator_token: UncheckedAccount<'info>,
    /// CHECK: the entry's associated token account for the coin (address checked).
    #[account(mut)]
    pub stake_vault: UncheckedAccount<'info>,
    /// CHECK: must own the coin mint (checked).
    pub coin_token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimStake<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump)]
    pub pot: Account<'info, Pot>,
    #[account(mut, seeds = [ENTRY_SEED, entry.pool.as_ref()], bump = entry.bump, has_one = coin_token_program)]
    pub entry: Account<'info, Entry>,
    #[account(mut, seeds = [CONTRIB_SEED, pot.key().as_ref(), funder.key().as_ref()], bump = contribution.bump)]
    pub contribution: Account<'info, Contribution>,
    /// CHECK: the contribution's funder (checked); receives the tokens.
    pub funder: UncheckedAccount<'info>,
    /// CHECK: pinned to the entry's coin.
    #[account(address = entry.coin)]
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the entry's own token account for the coin (address derived here).
    #[account(mut, address = Pubkey::find_program_address(&[entry.key().as_ref(), coin_token_program.key.as_ref(), entry.coin.as_ref()], &ATA_PROGRAM).0)]
    pub stake_vault: UncheckedAccount<'info>,
    /// CHECK: the funder's associated token account (address checked).
    #[account(mut)]
    pub funder_token: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub coin_token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ReleaseStake<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump)]
    pub pot: Account<'info, Pot>,
    #[account(mut, seeds = [ENTRY_SEED, entry.pool.as_ref()], bump = entry.bump, has_one = coin_token_program)]
    pub entry: Account<'info, Entry>,
    /// CHECK: the entry's creator (checked); receives the tokens.
    pub creator: UncheckedAccount<'info>,
    /// CHECK: pinned to the entry's coin.
    #[account(address = entry.coin)]
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the entry's own token account for the coin (address derived here).
    #[account(mut, address = Pubkey::find_program_address(&[entry.key().as_ref(), coin_token_program.key.as_ref(), entry.coin.as_ref()], &ATA_PROGRAM).0)]
    pub stake_vault: UncheckedAccount<'info>,
    /// CHECK: the creator's associated token account (address checked).
    #[account(mut)]
    pub creator_token: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub coin_token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RejectEntry<'info> {
    pub sponsor: Signer<'info>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump, has_one = sponsor @ LaunchError::NotSponsor)]
    pub pot: Account<'info, Pot>,
    #[account(mut, seeds = [ENTRY_SEED, pool.key().as_ref()], bump = entry.bump)]
    pub entry: Account<'info, Entry>,
    /// CHECK: owner and layout checked in `read_pool`.
    pub pool: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MarkWinner<'info> {
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump)]
    pub pot: Account<'info, Pot>,
    /// CHECK: owner and layout checked in `read_pool`; tied to the pot or its entry.
    pub pool: UncheckedAccount<'info>,
    /// Requests only.
    #[account(seeds = [ENTRY_SEED, pool.key().as_ref()], bump = entry.bump)]
    pub entry: Option<Account<'info, Entry>>,
    /// CHECK: the pool's stretch ledger, pinned; may not exist (read in `with_stretch`).
    #[account(mut, seeds = [STRETCH_SEED, pool.key().as_ref()], bump)]
    pub stretch: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump, has_one = mint, has_one = vault, has_one = token_program)]
    pub pot: Account<'info, Pot>,
    /// CHECK: pinned by `has_one`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: must be the config's treasury (checked).
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: the treasury's associated token account (address checked).
    #[account(mut)]
    pub treasury_token: UncheckedAccount<'info>,
    /// CHECK: must be the winning coin's creator (checked).
    pub creator: UncheckedAccount<'info>,
    /// CHECK: the creator's associated token account (address checked).
    #[account(mut)]
    pub creator_token: UncheckedAccount<'info>,
    /// CHECK: the winning coin's stretch ledger, pinned so it can't be left
    /// out; may not exist (then there are no finishers).
    #[account(mut, seeds = [STRETCH_SEED, pot.winner_pool.as_ref()], bump)]
    pub stretch: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Where `credit` sits in `StretchEnd`'s accounts: `stretch_begin` finds its
/// end by it.
pub const END_CREDIT_AT: usize = 2;

#[derive(Accounts)]
pub struct StretchBegin<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(seeds = [POT_CONFIG_SEED], bump = pot_config.bump)]
    pub pot_config: Account<'info, PotConfig>,
    #[account(init_if_needed, payer = wallet, space = 8 + Stretch::INIT_SPACE, seeds = [STRETCH_SEED, pool.key().as_ref()], bump)]
    pub stretch: Account<'info, Stretch>,
    #[account(init_if_needed, payer = wallet, space = 8 + Credit::INIT_SPACE, seeds = [CREDIT_SEED, pool.key().as_ref(), wallet.key().as_ref()], bump)]
    pub credit: Account<'info, Credit>,
    /// CHECK: a DBC pool or pump.fun curve, checked in `read_curve`.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC only: the pool's config (checked).
    pub dbc_config: Option<UncheckedAccount<'info>>,
    /// CHECK: the pool's coin (checked).
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the wallet's associated token account for the coin (address checked); may not exist yet.
    pub wallet_token: UncheckedAccount<'info>,
    /// CHECK: owns the coin mint (checked).
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the instructions sysvar.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StretchEnd<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(mut, seeds = [STRETCH_SEED, pool.key().as_ref()], bump = stretch.bump, has_one = token_program)]
    pub stretch: Account<'info, Stretch>,
    #[account(mut, seeds = [CREDIT_SEED, pool.key().as_ref(), wallet.key().as_ref()], bump = credit.bump)]
    pub credit: Account<'info, Credit>,
    /// CHECK: checked in `read_curve`.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC only (checked).
    pub dbc_config: Option<UncheckedAccount<'info>>,
    /// CHECK: pinned to the ledger's coin.
    #[account(address = stretch.mint)]
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the wallet's associated token account (address checked).
    #[account(mut)]
    pub wallet_token: UncheckedAccount<'info>,
    /// CHECK: the ledger's associated token account for the coin (address checked).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StretchFinish<'info> {
    #[account(mut, seeds = [STRETCH_SEED, pool.key().as_ref()], bump = stretch.bump)]
    pub stretch: Account<'info, Stretch>,
    /// CHECK: checked in `read_curve`.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC only (checked).
    pub dbc_config: Option<UncheckedAccount<'info>>,
}

#[derive(Accounts)]
pub struct StretchUnlock<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(mut, seeds = [STRETCH_SEED, pool.key().as_ref()], bump = stretch.bump, has_one = token_program)]
    pub stretch: Account<'info, Stretch>,
    #[account(mut, seeds = [CREDIT_SEED, pool.key().as_ref(), wallet.key().as_ref()], bump = credit.bump)]
    pub credit: Account<'info, Credit>,
    /// CHECK: checked in `read_curve`.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: DBC only (checked).
    pub dbc_config: Option<UncheckedAccount<'info>>,
    /// CHECK: pinned to the ledger's coin.
    #[account(address = stretch.mint)]
    pub coin_mint: UncheckedAccount<'info>,
    /// CHECK: the wallet's associated token account (address checked).
    #[account(mut)]
    pub wallet_token: UncheckedAccount<'info>,
    /// CHECK: the ledger's own token account for the coin (address derived here).
    #[account(mut, address = Pubkey::find_program_address(&[stretch.key().as_ref(), token_program.key.as_ref(), stretch.mint.as_ref()], &ATA_PROGRAM).0)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseCredit<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(mut, close = wallet, seeds = [CREDIT_SEED, credit.pool.as_ref(), wallet.key().as_ref()], bump = credit.bump)]
    pub credit: Account<'info, Credit>,
}

#[derive(Accounts)]
pub struct ClaimFinisher<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump, has_one = mint, has_one = vault, has_one = token_program)]
    pub pot: Account<'info, Pot>,
    #[account(seeds = [STRETCH_SEED, pot.winner_pool.as_ref()], bump = stretch.bump)]
    pub stretch: Account<'info, Stretch>,
    #[account(seeds = [CREDIT_SEED, pot.winner_pool.as_ref(), wallet.key().as_ref()], bump = credit.bump)]
    pub credit: Account<'info, Credit>,
    #[account(init, payer = wallet, space = 8 + PotClaim::INIT_SPACE, seeds = [POT_CLAIM_SEED, pot.key().as_ref(), wallet.key().as_ref()], bump)]
    pub claim_record: Account<'info, PotClaim>,
    /// CHECK: pinned by `has_one`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the wallet's associated token account (address checked).
    #[account(mut)]
    pub wallet_token: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StartReturn<'info> {
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump)]
    pub pot: Account<'info, Pot>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(mut, seeds = [POT_SEED, pot.sponsor.as_ref(), &pot.nonce.to_le_bytes()], bump = pot.bump, has_one = mint, has_one = vault, has_one = token_program)]
    pub pot: Account<'info, Pot>,
    #[account(mut, seeds = [CONTRIB_SEED, pot.key().as_ref(), funder.key().as_ref()], bump = contribution.bump)]
    pub contribution: Account<'info, Contribution>,
    /// CHECK: pinned by `has_one`.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: the funder's associated token account (address checked).
    #[account(mut)]
    pub funder_token: UncheckedAccount<'info>,
    /// CHECK: pinned by `has_one`.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the associated token program.
    #[account(address = ATA_PROGRAM)]
    pub ata_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ------------------------------------------------------------------ events

#[event]
pub struct PotOpened {
    pub pot: Pubkey,
    pub sponsor: Pubkey,
    pub kind: u8,
    pub launchpad: u8,
    pub mint: Pubkey,
    pub target: Pubkey,
    pub coin: Pubkey,
    pub deadline: i64,
    pub creator_bps: u16,
    pub min_stake: u64,
    pub amount: u64,
}

#[event]
pub struct PotFunded {
    pub pot: Pubkey,
    pub funder: Pubkey,
    pub amount: u64,
    pub funded: u64,
}

#[event]
pub struct PotEntered {
    pub pot: Pubkey,
    pub pool: Pubkey,
    pub creator: Pubkey,
    pub stake: u64,
}

#[event]
pub struct PotStakeClaimed {
    pub pot: Pubkey,
    pub funder: Pubkey,
    pub amount: u64,
}

#[event]
pub struct PotStakeReleased {
    pub pot: Pubkey,
    pub pool: Pubkey,
    pub creator: Pubkey,
    pub amount: u64,
}

#[event]
pub struct PotEntryRejected {
    pub pot: Pubkey,
    pub pool: Pubkey,
}

#[event]
pub struct PotWinner {
    pub pot: Pubkey,
    pub pool: Pubkey,
    pub finished: i64,
}

#[event]
pub struct PotSettled {
    pub pot: Pubkey,
    pub fee: u64,
    pub creator: Pubkey,
    pub creator_amount: u64,
    pub finishers: u64,
}

#[event]
pub struct StretchCredited {
    pub pool: Pubkey,
    pub wallet: Pubkey,
    pub credit: u64,
    pub tokens: u64,
}

#[event]
pub struct StretchFinished {
    pub pool: Pubkey,
    pub finished_at: i64,
    pub total_credit: u64,
}

#[event]
pub struct StretchUnlocked {
    pub pool: Pubkey,
    pub wallet: Pubkey,
    pub tokens: u64,
    pub forfeited: bool,
}

#[event]
pub struct PotClaimed {
    pub pot: Pubkey,
    pub wallet: Pubkey,
    pub amount: u64,
}

#[event]
pub struct PotReturning {
    pub pot: Pubkey,
    pub returnable: u64,
}

#[event]
pub struct PotRefunded {
    pub pot: Pubkey,
    pub funder: Pubkey,
    pub amount: u64,
}

#[cfg(test)]
mod tests {
    use super::{stretch_credit, Pot, Stretch};
    use anchor_lang::Space;

    // The app and keeper filter pots by this size (POT_SIZE in router.ts and server/market/pots.js).
    #[test]
    fn pot_accounts_are_580_bytes() {
        assert_eq!(8 + Pot::INIT_SPACE, 580);
    }

    // The server filters coin ledgers by this size (STRETCH_SIZE in server/market/pots.js).
    #[test]
    fn stretch_accounts_are_186_bytes() {
        assert_eq!(8 + Stretch::INIT_SPACE, 186);
    }

    // A DBC-like curve: progress is the SOL reserve itself, line at 90.
    #[test]
    fn a_buy_below_the_line_earns_nothing() {
        assert_eq!(stretch_credit(90, 50, 60, 50, 60, 1_000, 900, 100), (0, 0));
    }

    #[test]
    fn only_the_part_past_the_line_counts() {
        // 85 -> 95: half the move is past 90; 100 tokens left the curve, 50 of them past it.
        assert_eq!(stretch_credit(90, 85, 95, 85, 95, 1_000, 900, 100), (5, 50));
    }

    #[test]
    fn a_buy_inside_the_stretch_counts_whole() {
        assert_eq!(stretch_credit(90, 91, 96, 91, 96, 1_000, 950, 50), (5, 50));
    }

    #[test]
    fn someone_elses_tokens_earn_this_wallet_nothing() {
        // The curve released 100 tokens but this wallet got 60 of them.
        assert_eq!(stretch_credit(90, 91, 99, 91, 99, 1_000, 900, 60), (0, 0));
    }

    #[test]
    fn a_net_sell_earns_nothing() {
        assert_eq!(stretch_credit(90, 95, 92, 95, 92, 900, 950, 0), (0, 0));
    }

    // pump.fun-like: progress is tokens sold, SOL moves separately.
    #[test]
    fn ground_already_credited_earns_nothing() {
        // High-water at 95: a sell back to 91 and a rebuy to 95 is old ground.
        assert_eq!(stretch_credit(95, 91, 95, 91, 95, 1_000, 960, 40), (0, 0));
        // Past it, only the new part counts: 93 -> 97 with the mark at 95 credits 2 of 4.
        assert_eq!(stretch_credit(95, 93, 97, 93, 97, 1_000, 960, 40), (2, 20));
    }

    #[test]
    fn pump_progress_splits_the_sol() {
        // Tokens sold 880 -> 920 with the line at 900: half past; 40 tokens released, 20 past; 4 SOL in, 2 credited.
        assert_eq!(stretch_credit(900, 70, 74, 880, 920, 120, 80, 40), (2, 20));
    }
}
