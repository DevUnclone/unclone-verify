//! Does the Rust hash the same withdraw message the TypeScript client does?
//!
//! ── ONE FUNCTION DECIDES WHETHER ANY VAULT EVER OPENS ────────────────────
//! `withdraw` rebuilds the signed message from the accounts it is acting
//! on. If the client that produced the signature hashed different bytes,
//! every withdrawal fails, and the only thing the program can say is "the
//! staged signature does not open this vault". That message is true and
//! useless: it points at the signature when the fault is in the message.
//!
//! So the client generates vectors into `vectors/withdraw.json` and
//! this recomputes every one of them with `hashv`, the same call the
//! program makes. Neither side proves anything alone. Two implementations
//! in two languages agreeing on a hex string is the whole evidence.
//!
//! ── AND THE CONTROLS ARE HERE TOO ────────────────────────────────────────
//! A test that only checks agreement would pass if both sides ignored a
//! field. So it also asserts that changing the recipient and changing the
//! amount each change the message. A signature that does not cover the
//! recipient is a bearer token; one that does not cover the amount drains
//! the vault it was meant to release a lamport from.

use solana_program::hash::hashv;
use solana_program::pubkey::Pubkey;
use std::str::FromStr;

use unclone_vault::wots::SCHEME_ID;

/// Exactly what `withdraw` in `src/lib.rs` builds, and nothing else.
fn message(vault: &Pubkey, recipient: &Pubkey, amount: u64, next_vault: &[u8; 32]) -> [u8; 32] {
    hashv(&[
        SCHEME_ID,
        b"/withdraw",
        vault.as_ref(),
        recipient.as_ref(),
        &amount.to_le_bytes(),
        next_vault,
    ])
    .to_bytes()
}

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/withdraw.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("{path} could not be read ({e}). Run `npm run probe-vault` to generate it.")
    });
    serde_json::from_str(&raw).expect("the vectors file is not valid JSON")
}

#[test]
fn the_scheme_id_is_the_published_one() {
    let v = vectors();
    let published = v["schemeId"].as_str().expect("no schemeId in the vectors");
    assert_eq!(
        published.as_bytes(),
        SCHEME_ID,
        "the TypeScript and the Rust disagree about the scheme id itself, so nothing below could ever match"
    );
}

#[test]
fn every_published_message_is_recomputed_here() {
    let v = vectors();
    let list = v["vectors"].as_array().expect("no vectors array");
    assert!(
        list.len() >= 4,
        "only {} vectors: too few to have covered both ends of a u64",
        list.len()
    );

    for (i, case) in list.iter().enumerate() {
        let vault = Pubkey::from_str(case["vault"].as_str().unwrap()).unwrap();
        let recipient = Pubkey::from_str(case["recipient"].as_str().unwrap()).unwrap();
        let next = Pubkey::from_str(case["nextVault"].as_str().unwrap()).unwrap();
        let amount: u64 = case["amount"].as_str().unwrap().parse().unwrap();

        let mine = message(&vault, &recipient, amount, &next.to_bytes());
        let theirs = hex::decode(case["message"].as_str().unwrap()).unwrap();

        assert_eq!(
            mine.to_vec(),
            theirs,
            "vector {i} disagrees.\n  amount {amount}\n  Rust       {}\n  TypeScript {}",
            hex::encode(mine),
            case["message"].as_str().unwrap()
        );
    }
}

#[test]
fn both_ends_of_a_u64_are_covered() {
    let v = vectors();
    let list = v["vectors"].as_array().unwrap();
    let amounts: Vec<u64> = list
        .iter()
        .map(|c| c["amount"].as_str().unwrap().parse().unwrap())
        .collect();
    assert!(amounts.contains(&0), "no vector uses an amount of zero");
    assert!(
        amounts.contains(&u64::MAX),
        "no vector uses u64::MAX, so a little-endian encoding bug in the top bytes would pass"
    );
}

#[test]
fn changing_the_recipient_changes_the_message() {
    let a = Pubkey::new_unique();
    let b = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let next = Pubkey::new_unique().to_bytes();
    assert_ne!(
        message(&vault, &a, 1, &next),
        message(&vault, &b, 1, &next),
        "the recipient is not in the message: a signature would be a bearer token anyone could redirect"
    );
}

#[test]
fn changing_the_amount_changes_the_message() {
    let vault = Pubkey::new_unique();
    let who = Pubkey::new_unique();
    let next = Pubkey::new_unique().to_bytes();
    assert_ne!(
        message(&vault, &who, 1, &next),
        message(&vault, &who, 2, &next),
        "the amount is not in the message: a signature for one lamport would release any sum"
    );
}

#[test]
fn changing_the_next_vault_changes_the_message() {
    let vault = Pubkey::new_unique();
    let who = Pubkey::new_unique();
    assert_ne!(
        message(&vault, &who, 1, &Pubkey::new_unique().to_bytes()),
        message(&vault, &who, 1, &Pubkey::new_unique().to_bytes()),
        "the next vault is not in the message: the remainder could be rolled anywhere"
    );
}

#[test]
fn the_domain_separator_is_load_bearing() {
    // Without `/withdraw` in the preimage, a message signed for a launch
    // record could be replayed as a withdrawal. This is the test that
    // fails if somebody ever decides the separator is noise.
    let vault = Pubkey::new_unique();
    let who = Pubkey::new_unique();
    let next = Pubkey::new_unique().to_bytes();
    let with = message(&vault, &who, 7, &next);
    let without = hashv(&[
        SCHEME_ID,
        vault.as_ref(),
        who.as_ref(),
        &7u64.to_le_bytes(),
        &next,
    ])
    .to_bytes();
    assert_ne!(with, without, "the /withdraw separator contributes nothing");
}
