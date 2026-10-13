//! UNCLONE vault: funds that only a hash-based signature can move.
//!
//! ── WHAT THIS PROGRAM IS FOR ─────────────────────────────────────────────
//! A vault account holds lamports at a PDA derived from a Merkle root and
//! a leaf index. It releases them only against a WOTS signature at that
//! leaf which climbs to that root. No ed25519 key, including the one that
//! created the vault, can move anything out: the signer of the withdraw
//! transaction pays the fee and nothing else.
//!
//! ── WHY THE SIGNATURE ARRIVES IN PIECES ──────────────────────────────────
//! A signature is 2,144 bytes and the authentication path another 256. A
//! Solana transaction is capped at 1,232 bytes in total, so a full
//! attestation cannot be an instruction argument. It is written into a
//! buffer account across several transactions and the withdraw reads it
//! from there. Any design claiming to pass one in a single transaction is
//! claiming something the runtime will not do.
//!
//! ── WHAT A WITHDRAWAL IS SIGNED OVER ─────────────────────────────────────
//! Not "a withdrawal". The vault, the recipient, the amount and the next
//! vault, all four, so a signature cannot be replayed to a different
//! recipient or for a different amount. Leaving any of them out is the
//! difference between a signature and a bearer token.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    hash::hashv,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    program::invoke_signed,
    sysvar::Sysvar,
};

pub mod wots;

use wots::{AUTH_BYTES, SIG_BYTES};

/// `vault` PDA seeds: ["vault", root, leaf_be]. Derived, never stored.
pub const VAULT_SEED: &[u8] = b"vault";
/// `buffer` PDA seeds: ["buffer", vault].
pub const BUFFER_SEED: &[u8] = b"buffer";

/// Vault account: a tag, the root it answers to, and the leaf it spends.
/// 1 + 32 + 4 = 37 bytes, fixed.
pub const VAULT_LEN: usize = 1 + 32 + 4;
/// Buffer account: a tag, the vault it belongs to, then the staged bytes.
pub const BUFFER_LEN: usize = 1 + 32 + SIG_BYTES + AUTH_BYTES + 32;

const TAG_VAULT: u8 = 1;
const TAG_BUFFER: u8 = 2;

entrypoint!(process);

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (tag, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => open_vault(program_id, accounts, rest),
        1 => write_signature(program_id, accounts, rest),
        2 => withdraw(program_id, accounts, rest),
        3 => close_buffer(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn read32(src: &[u8], at: usize) -> Result<[u8; 32], ProgramError> {
    let end = at.checked_add(32).ok_or(ProgramError::InvalidInstructionData)?;
    if src.len() < end {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&src[at..end]);
    Ok(out)
}

/// 0 · open a vault for (root, leaf) and fund it.
///
/// Anyone may open one; opening a vault for somebody else's root only
/// means giving them lamports, which is not an attack worth preventing.
fn open_vault(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let system = next_account_info(it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let root = read32(data, 0)?;
    if data.len() < 44 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let leaf = u32::from_be_bytes(data[32..36].try_into().unwrap());
    let lamports = u64::from_le_bytes(data[36..44].try_into().unwrap());
    if leaf >= wots::LEAVES {
        msg!("leaf {} is outside 0..{}", leaf, wots::LEAVES - 1);
        return Err(ProgramError::InvalidInstructionData);
    }

    let leaf_be = leaf.to_be_bytes();
    let (expected, bump) = Pubkey::find_program_address(&[VAULT_SEED, &root, &leaf_be], program_id);
    if expected != *vault.key {
        msg!("the vault account is not the PDA for that root and leaf");
        return Err(ProgramError::InvalidArgument);
    }

    let rent = Rent::get()?.minimum_balance(VAULT_LEN);
    let total = rent
        .checked_add(lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    invoke_signed(
        &system_instruction::create_account(payer.key, vault.key, total, VAULT_LEN as u64, program_id),
        &[payer.clone(), vault.clone(), system.clone()],
        &[&[VAULT_SEED, &root, &leaf_be, &[bump]]],
    )?;

    let mut d = vault.try_borrow_mut_data()?;
    d[0] = TAG_VAULT;
    d[1..33].copy_from_slice(&root);
    d[33..37].copy_from_slice(&leaf_be);
    msg!("vault open for leaf {}", leaf);
    Ok(())
}

/// 1 · stage bytes of the attestation into the buffer.
///
/// `[u16 offset][bytes]`. The buffer is created on first write. Only the
/// payer who created it may extend it, because a buffer anyone can
/// overwrite is a buffer an attacker can swap under a withdraw that is
/// already in flight.
fn write_signature(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let buffer = next_account_info(it)?;
    let system = next_account_info(it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let offset = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    let chunk = &data[2..];

    let (expected, bump) = Pubkey::find_program_address(&[BUFFER_SEED, vault.key.as_ref()], program_id);
    if expected != *buffer.key {
        return Err(ProgramError::InvalidArgument);
    }

    if buffer.data_is_empty() {
        let rent = Rent::get()?.minimum_balance(BUFFER_LEN);
        invoke_signed(
            &system_instruction::create_account(payer.key, buffer.key, rent, BUFFER_LEN as u64, program_id),
            &[payer.clone(), buffer.clone(), system.clone()],
            &[&[BUFFER_SEED, vault.key.as_ref(), &[bump]]],
        )?;
        let mut d = buffer.try_borrow_mut_data()?;
        d[0] = TAG_BUFFER;
        d[1..33].copy_from_slice(&payer.key.to_bytes());
    } else {
        let d = buffer.try_borrow_data()?;
        if d[0] != TAG_BUFFER {
            return Err(ProgramError::InvalidAccountData);
        }
        if d[1..33] != payer.key.to_bytes() {
            msg!("this buffer belongs to another payer");
            return Err(ProgramError::IllegalOwner);
        }
    }

    let start = 33usize
        .checked_add(offset)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let end = start
        .checked_add(chunk.len())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if end > BUFFER_LEN {
        msg!("that write runs past the end of the buffer");
        return Err(ProgramError::InvalidInstructionData);
    }
    buffer.try_borrow_mut_data()?[start..end].copy_from_slice(chunk);
    Ok(())
}

/// 2 · withdraw, if the staged signature holds.
///
/// `[u64 amount][32 next_vault]`. The message signed is built here, from
/// the accounts and the amount this instruction will actually act on, not
/// from anything the caller serialised.
fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let vault = next_account_info(it)?;
    let buffer = next_account_info(it)?;
    let recipient = next_account_info(it)?;

    if vault.owner != program_id || buffer.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if data.len() < 40 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let next_vault = read32(data, 8)?;

    let (root, leaf) = {
        let d = vault.try_borrow_data()?;
        if d.len() < VAULT_LEN || d[0] != TAG_VAULT {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(&d[1..33]);
        (r, u32::from_be_bytes(d[33..37].try_into().unwrap()))
    };

    let (pub_seed, signature, path) = {
        let d = buffer.try_borrow_data()?;
        if d.len() < BUFFER_LEN || d[0] != TAG_BUFFER {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut ps = [0u8; 32];
        ps.copy_from_slice(&d[33..65]);
        (ps, d[65..65 + SIG_BYTES].to_vec(), d[65 + SIG_BYTES..65 + SIG_BYTES + AUTH_BYTES].to_vec())
    };

    /* The message. Every field that decides where the money goes is in it. */
    let message = hashv(&[
        wots::SCHEME_ID,
        b"/withdraw",
        vault.key.as_ref(),
        recipient.key.as_ref(),
        &amount.to_le_bytes(),
        &next_vault,
    ])
    .to_bytes();

    if !wots::verify(&root, &pub_seed, leaf, &signature, &path, &message) {
        msg!("the staged signature does not open this vault");
        return Err(ProgramError::InvalidArgument);
    }

    let available = vault.lamports();
    let keep = Rent::get()?.minimum_balance(VAULT_LEN);
    if amount
        .checked_add(keep)
        .ok_or(ProgramError::ArithmeticOverflow)?
        > available
    {
        msg!("vault holds {} and {} was asked for, with {} rent to keep", available, amount, keep);
        return Err(ProgramError::InsufficientFunds);
    }

    **vault.try_borrow_mut_lamports()? = available
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **recipient.try_borrow_mut_lamports()? = recipient
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    /* The leaf is now spent. The vault is marked so the same signature
       cannot be presented twice, which the chain must enforce because
       nothing off chain can. */
    vault.try_borrow_mut_data()?[0] = TAG_VAULT + 128;
    msg!("withdrew {} at leaf {}", amount, leaf);
    Ok(())
}

/// 3 · reclaim a spent buffer's rent, for its own payer only.
fn close_buffer(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let buffer = next_account_info(it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if buffer.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    {
        let d = buffer.try_borrow_data()?;
        if d.len() < 33 || d[0] != TAG_BUFFER || d[1..33] != payer.key.to_bytes() {
            return Err(ProgramError::IllegalOwner);
        }
    }
    let lamports = buffer.lamports();
    **buffer.try_borrow_mut_lamports()? = 0;
    **payer.try_borrow_mut_lamports()? = payer
        .lamports()
        .checked_add(lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    buffer.try_borrow_mut_data()?.fill(0);
    Ok(())
}
