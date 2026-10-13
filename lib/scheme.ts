/**
 * ── THE SCHEME, IN ONE PLACE ──────────────────────────────────────────────
 *
 * UNCLONE, after the no-cloning theorem: an unknown quantum state cannot be
 * duplicated, and the attempt destroys the original. A key here signs
 * exactly one thing and is then spent, and the whole product is arranged
 * around making that single fact checkable by a stranger.
 *
 * Everything below is a PARAMETER, not a decision taken twice. Every file
 * that needs a length reads it from here, because a length written in two
 * places is two copies of one assumption and this workspace has been bitten
 * by that more than once.
 *
 * ── WHY THESE NUMBERS AND NOT OTHERS ─────────────────────────────────────
 * Winternitz one-time signatures with w = 16 means each chain carries four
 * bits, so a 256-bit digest needs LEN1 = 256 / 4 = 64 message chains. The
 * checksum has to cover the largest value those can take, 64 x 15 = 960,
 * which needs ceil(log16(961)) = 3 more chains. LEN = 67 is therefore
 * forced, not chosen, and the assertion at the bottom of this file says so
 * out loud rather than trusting that anybody did the arithmetic.
 *
 * A Merkle tree of height 8 gives 2^8 = 256 one-time keys per identity.
 * That is the number of signatures an identity can ever produce, and when
 * it runs out a new identity has to be registered. Saying 256 is honest;
 * calling it unlimited would not be.
 */

/** Digest size in bytes. SHA-256, so 32. */
export const N = 32;

/** Winternitz parameter. Four bits per chain. */
export const W = 16;

/** The largest step index in a chain: a value walks 0..15, so 15 steps. */
export const W_MAX = W - 1;

/** Message chains: 256 bits at 4 bits each. */
export const LEN1 = (N * 8) / Math.log2(W);

/** Checksum chains, enough to hold LEN1 * W_MAX in base w. */
export const LEN2 = Math.floor(Math.log(LEN1 * W_MAX) / Math.log(W)) + 1;

/** Total chains per signature. */
export const LEN = LEN1 + LEN2;

/** Merkle height. 2^8 = 256 one-time keys per identity. */
export const MERKLE_H = 8;

/** How many signatures an identity can ever produce. */
export const LEAVES = 2 ** MERKLE_H;

/** A raw WOTS signature: one chain value per chain. */
export const SIG_BYTES = LEN * N;

/** The authentication path from a leaf to the root. */
export const AUTH_BYTES = MERKLE_H * N;

/**
 * What a full attestation weighs on the wire: the signature, the path, the
 * public seed and a four-byte leaf index.
 *
 * ── AND IT DOES NOT FIT IN A SOLANA TRANSACTION ──────────────────────────
 * A Solana transaction is capped at 1,232 bytes, and this is more than
 * twice that. Anything claiming to put a whole attestation into one
 * transaction is claiming something the chain will not do. Staging it
 * across several writes into a buffer account and verifying the buffer is
 * the only honest way, and `ATTESTATION_BYTES > 1232` is asserted below so
 * that a future change to the parameters cannot quietly make the claim
 * false in the other direction either.
 */
export const ATTESTATION_BYTES = SIG_BYTES + AUTH_BYTES + N + 4;

/** Solana's hard transaction size limit, for the arithmetic above. */
export const SOLANA_TX_LIMIT = 1232;

/** Domain separators, so a hash in one role can never be read in another. */
export const ADRS_CHAIN = 0;
export const ADRS_SECRET = 1;
export const ADRS_LEAF = 2;
export const ADRS_NODE = 3;

/**
 * The scheme's own name, written into every digest.
 *
 * A signature over a bare message hash can be replayed under a different
 * scheme that happens to hash the same way. Binding the scheme id into the
 * digest costs nothing and closes that.
 */
/**
 * ── v2, BECAUSE THE SIGNED RECORD GAINED A FIELD ────────────────────────
 * `lib/derive.ts` says it out loud: adding a field changes every digest,
 * and an old attestation must keep verifying against the old record, so
 * a new field means a NEW SCHEME ID and not a quiet extension.
 *
 * The field is `mintDerived`. Standard launches now sign too, and the
 * only thing separating them from Quantum is whether the mint address
 * came out of the one-time key or out of a random keypair. The server
 * cannot check that for itself — the derivation needs `skSeed`, which
 * never leaves the browser — so it has to be covered by the signature
 * or it is an unsigned flag the page would be trusting.
 */
export const SCHEME_ID = "unclone/wots-sha256/w16/h8/v2";

/* ── the arithmetic, asserted rather than trusted ─────────────────────── */
if (LEN1 !== 64) throw new Error(`LEN1 must be 64 for n=${N}, w=${W}, got ${LEN1}`);
if (LEN2 !== 3) throw new Error(`LEN2 must be 3 for len1=${LEN1}, w=${W}, got ${LEN2}`);
if (LEN !== 67) throw new Error(`LEN must be 67, got ${LEN}`);
if (SIG_BYTES !== 2144) throw new Error(`SIG_BYTES must be 2144, got ${SIG_BYTES}`);
if (ATTESTATION_BYTES !== 2436) throw new Error(`ATTESTATION_BYTES must be 2436, got ${ATTESTATION_BYTES}`);
if (ATTESTATION_BYTES <= SOLANA_TX_LIMIT) {
  throw new Error(`an attestation is ${ATTESTATION_BYTES} B and the claim that it must be staged assumes it exceeds ${SOLANA_TX_LIMIT} B`);
}
