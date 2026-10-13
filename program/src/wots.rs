//! Winternitz one-time signature verification, on chain.
//!
//! ── THIS MUST AGREE WITH `lib/wots.ts` BYTE FOR BYTE ─────────────────────
//! Two implementations of one scheme is the most dangerous shape in this
//! project: the browser signs, the chain verifies, and if they disagree by
//! a single byte of domain separation then either nothing verifies or,
//! far worse, something verifies that should not.
//!
//! So they are not written from each other. Both are written from the same
//! published description, and `tests/vectors.rs` checks this one against
//! the very JSON file the site serves at `/vectors/wots.json`. If the two
//! ever drift, that test fails rather than production.
//!
//! ── THE COST IS THE DESIGN CONSTRAINT ────────────────────────────────────
//! A verifier walks between 45 and 990 hash steps depending on the digest.
//! Solana charges for each syscall, so the worst case has to fit: ~990
//! sha256 calls over 96-byte inputs is roughly 100k compute units, inside
//! the 200k default and far inside the 1.4M ceiling. The arithmetic is
//! stated here because it is the reason the parameters are what they are.

use solana_program::hash::{hashv, Hasher};

pub const N: usize = 32;
pub const W_MAX: u8 = 15;
pub const LEN1: usize = 64;
pub const LEN2: usize = 3;
pub const LEN: usize = LEN1 + LEN2;
pub const SIG_BYTES: usize = LEN * N;
pub const MERKLE_H: usize = 8;
pub const AUTH_BYTES: usize = MERKLE_H * N;
pub const LEAVES: u32 = 1 << MERKLE_H;

pub const ADRS_CHAIN: u32 = 0;
pub const ADRS_SECRET: u32 = 1;
pub const ADRS_LEAF: u32 = 2;
pub const ADRS_NODE: u32 = 3;

/// The scheme identifier, bound into every digest.
///
/// A signature over a bare message hash can be lifted into another scheme
/// that happens to hash the same way. One string closes that, and it must
/// be byte-identical to `SCHEME_ID` in `lib/scheme.ts`.
pub const SCHEME_ID: &[u8] = b"unclone/wots-sha256/w16/h8/v2";

/// 32-byte domain-separated address: four big-endian u32s then 16 zeros.
#[inline]
fn adrs(kind: u32, leaf: u32, chain: u32, step: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&kind.to_be_bytes());
    a[4..8].copy_from_slice(&leaf.to_be_bytes());
    a[8..12].copy_from_slice(&chain.to_be_bytes());
    a[12..16].copy_from_slice(&step.to_be_bytes());
    a
}

/// The tweakable hash: SHA-256(pubSeed || ADRS || x).
#[inline]
fn f(pub_seed: &[u8; 32], address: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    hashv(&[pub_seed, address, x]).to_bytes()
}

/// The 67 chain lengths for a digest.
///
/// 64 message nibbles, high before low, then a checksum of sum(15 - d) as
/// three base-16 digits, most significant first. The checksum counting
/// DOWN is the entire security argument: raising a message nibble, which a
/// forger can do for free by walking a chain forward, always lowers the
/// checksum, and lowering a checksum nibble means inverting SHA-256.
pub fn steps(digest: &[u8; 32]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    let mut checksum: u32 = 0;
    for (j, byte) in digest.iter().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out[2 * j] = hi;
        out[2 * j + 1] = lo;
        checksum += (W_MAX - hi) as u32 + (W_MAX - lo) as u32;
    }
    out[LEN1] = ((checksum >> 8) & 0x0f) as u8;
    out[LEN1 + 1] = ((checksum >> 4) & 0x0f) as u8;
    out[LEN1 + 2] = (checksum & 0x0f) as u8;
    out
}

/// Walk a value through chain positions [from, to).
#[inline]
fn chain(pub_seed: &[u8; 32], leaf: u32, index: u32, x: &[u8; 32], from: u8, to: u8) -> [u8; 32] {
    let mut v = *x;
    let mut s = from;
    while s < to {
        v = f(pub_seed, &adrs(ADRS_CHAIN, leaf, index, s as u32), &v);
        s += 1;
    }
    v
}

/// Recover ONE chain's public key value.
///
/// There is deliberately no function that returns the whole 2,144-byte
/// public key. The first version had one, and `cargo-build-sbf` answered:
///
///   Function wots::verify overflows the maximum allowed frame space by
///   accessing an offset 384 bytes greater than the maximum of 4096.
///   Estimated function frame size: 4480 bytes. Exceeding the maximum
///   stack offset may cause undefined behavior during execution.
///
/// An SBF stack frame is 4 KB and the public key alone is 2,144 of them.
/// The build still emitted a `.so`, which is the dangerous part: a program
/// that is one array away from undefined behaviour, shipped, with an exit
/// code of zero.
///
/// So the public key is never materialised. One chain at a time, 32 bytes
/// of stack, streamed into a hash. The test on the host walks the same
/// function in a loop to rebuild the full key and compare it against the
/// published vectors, so there is exactly ONE implementation of the walk
/// and both uses go through it.
#[inline]
pub fn recover_chain(
    pub_seed: &[u8; 32],
    leaf: u32,
    signature: &[u8],
    d: &[u8; LEN],
    i: usize,
) -> [u8; 32] {
    let mut part = [0u8; 32];
    part.copy_from_slice(&signature[i * N..(i + 1) * N]);
    chain(pub_seed, leaf, i as u32, &part, d[i], W_MAX)
}

/// The leaf commitment, computed without ever holding the whole key.
///
/// Identical to `SHA-256(ADRS(leaf) || pk_0 || … || pk_66)`, which is what
/// `leafHash()` computes in TypeScript, because a streaming hash over the
/// same bytes in the same order is the same hash.
pub fn recover_leaf_hash(
    pub_seed: &[u8; 32],
    leaf: u32,
    signature: &[u8],
    digest: &[u8; 32],
) -> Option<[u8; 32]> {
    if signature.len() != SIG_BYTES {
        return None;
    }
    let d = steps(digest);
    let mut hasher = Hasher::default();
    hasher.hash(&adrs(ADRS_LEAF, leaf, 0, 0));
    for i in 0..LEN {
        hasher.hash(&recover_chain(pub_seed, leaf, signature, &d, i));
    }
    Some(hasher.result().to_bytes())
}

/// The leaf commitment for a public key that is already in hand.
///
/// Only the host-side tests have one, which is why this takes a slice
/// rather than an array: nothing on chain should be holding 2,144 bytes.
pub fn leaf_hash(pk: &[u8], leaf: u32) -> [u8; 32] {
    hashv(&[&adrs(ADRS_LEAF, leaf, 0, 0), pk]).to_bytes()
}

/// Climb from a leaf hash to the root the authentication path implies.
///
/// The leaf INDEX decides which side each sibling goes on. Getting that
/// backwards produces a root that is correct for leaf 0 and wrong for
/// every other leaf, which a test that only ever signs at leaf 0 will
/// never notice.
pub fn climb(leaf_value: &[u8; 32], leaf: u32, path: &[u8]) -> Option<[u8; 32]> {
    if path.len() != AUTH_BYTES {
        return None;
    }
    let mut node = *leaf_value;
    let mut index = leaf;
    for h in 0..MERKLE_H {
        let sibling = &path[h * N..(h + 1) * N];
        node = if index & 1 == 0 {
            hashv(&[&adrs(ADRS_NODE, 0, h as u32, index >> 1), &node, sibling]).to_bytes()
        } else {
            hashv(&[&adrs(ADRS_NODE, 0, h as u32, index >> 1), sibling, &node]).to_bytes()
        };
        index >>= 1;
    }
    Some(node)
}

/// What a one-time key actually signs: the scheme, the leaf, the message.
pub fn bind_digest(message: &[u8], leaf: u32) -> [u8; 32] {
    hashv(&[SCHEME_ID, &leaf.to_be_bytes(), message]).to_bytes()
}

/// The whole check, in one call.
///
/// Returns true only if the signature at `leaf` over `message` opens to a
/// one-time key whose leaf hash climbs to `root`.
pub fn verify(
    root: &[u8; 32],
    pub_seed: &[u8; 32],
    leaf: u32,
    signature: &[u8],
    path: &[u8],
    message: &[u8],
) -> bool {
    if leaf >= LEAVES {
        return false;
    }
    let digest = bind_digest(message, leaf);
    let leaf_value = match recover_leaf_hash(pub_seed, leaf, signature, &digest) {
        Some(v) => v,
        None => return false,
    };
    match climb(&leaf_value, leaf, path) {
        Some(got) => got == *root,
        None => false,
    }
}

/// How many hashes a verifier walks for this digest. 45 at best, 990 at worst.
pub fn verify_cost(digest: &[u8; 32]) -> u32 {
    steps(digest).iter().map(|d| (W_MAX - d) as u32).sum()
}
