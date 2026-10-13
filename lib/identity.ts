/**
 * ── AN IDENTITY: ONE ROOT, 256 SIGNATURES, EACH SPENT ONCE ───────────────
 *
 * This is the layer a page talks to. It puts the WOTS keys under a Merkle
 * root, binds the scheme id into every digest, and produces an attestation
 * a stranger can check with nothing but SHA-256 and the root.
 *
 * ── THE DIGEST IS BOUND TO THE SCHEME AND THE LEAF ───────────────────────
 * A signature over a bare message hash can be lifted into a different
 * scheme, or replayed against a different leaf of the same identity. Both
 * are closed by hashing the scheme id and the leaf index in with the
 * message, which costs one hash and removes two whole classes of
 * confusion.
 */
import { sha256 } from "@noble/hashes/sha2";
import { ATTESTATION_BYTES, AUTH_BYTES, LEAVES, N, SCHEME_ID, SIG_BYTES } from "./scheme.ts";
import { concat, equal, publicKey, recover, sign, u32be, verifyCost } from "./wots.ts";
import { authPath, buildTree, checkPath, leafHash, rootOf } from "./merkle.ts";

export type Identity = {
  root: Uint8Array;
  pubSeed: Uint8Array;
  levels: Uint8Array[][];
};

/**
 * ── THE DIGEST IS OPTIONAL, AND THAT IS THE WHOLE POINT ──────────────────
 * A verifier is handed a root, a message, a leaf, a seed, a signature and
 * a path. It is NOT handed a digest, because the digest is something it
 * computes; asking for it would be asking the reader for an answer.
 *
 * It was required here at first, and `components/Verifier.tsx` therefore
 * passed a placeholder, and `check` compared the placeholder against the
 * real digest and refused every honest attestation. Both sides looked
 * reasonable in isolation and the pair was broken. `probe-crypto` could
 * not see it because every attestation it built carried its own correct
 * digest; the browser probe found it on the first run.
 *
 * So: absent means "compute it", present means "and it must match". The
 * second half is not a formality. It is what stops a caller signing one
 * thing and presenting it as a signature over another, and
 * `probe-crypto` attacks exactly that.
 */
export type Attestation = {
  scheme: typeof SCHEME_ID;
  leaf: number;
  pubSeed: Uint8Array;
  signature: Uint8Array;
  path: Uint8Array;
  digest?: Uint8Array;
};

const enc = new TextEncoder();

/**
 * What the one-time key actually signs.
 *
 * Not the message. The message, the leaf it is being signed at, and the
 * name of the scheme doing the signing.
 */
export function bindDigest(message: Uint8Array, leaf: number): Uint8Array {
  return sha256(concat(enc.encode(SCHEME_ID), u32be(leaf), message));
}

/** Build an identity from two seeds. Expensive on purpose: 256 WOTS keys. */
export function deriveIdentity(skSeed: Uint8Array, pubSeed: Uint8Array): Identity {
  if (skSeed.length !== N) throw new Error(`skSeed must be ${N} bytes`);
  if (pubSeed.length !== N) throw new Error(`pubSeed must be ${N} bytes`);
  const levels = buildTree(skSeed, pubSeed);
  return { root: rootOf(levels), pubSeed, levels };
}

/** Sign one message at one leaf. The caller must never reuse a leaf. */
export function attest(
  skSeed: Uint8Array, identity: Identity, leaf: number, message: Uint8Array,
): Attestation {
  if (!Number.isInteger(leaf) || leaf < 0 || leaf >= LEAVES) {
    throw new Error(`leaf must be an integer in 0..${LEAVES - 1}, got ${leaf}`);
  }
  const digest = bindDigest(message, leaf);
  return {
    scheme: SCHEME_ID,
    leaf,
    pubSeed: identity.pubSeed,
    signature: sign(skSeed, identity.pubSeed, leaf, digest),
    path: authPath(identity.levels, leaf),
    digest,
  };
}

/**
 * Check an attestation against a root and a message, with nothing else.
 *
 * This is the function a stranger runs. It takes no secret, no server and
 * no network: a root, a message, and the attestation. If this returns true
 * the message was signed by the holder of that root at that leaf, under
 * the assumption that SHA-256 is one-way.
 */
export function check(
  root: Uint8Array, message: Uint8Array, a: Attestation,
): { ok: boolean; why: string } {
  if (a.scheme !== SCHEME_ID) return { ok: false, why: `scheme is ${a.scheme}, not ${SCHEME_ID}` };
  if (a.signature.length !== SIG_BYTES) return { ok: false, why: `signature is ${a.signature.length} B, not ${SIG_BYTES}` };
  if (a.path.length !== AUTH_BYTES) return { ok: false, why: `auth path is ${a.path.length} B, not ${AUTH_BYTES}` };
  if (a.pubSeed.length !== N) return { ok: false, why: `pubSeed is ${a.pubSeed.length} B, not ${N}` };
  if (!Number.isInteger(a.leaf) || a.leaf < 0 || a.leaf >= LEAVES) return { ok: false, why: `leaf ${a.leaf} is outside 0..${LEAVES - 1}` };

  /* The digest is RECOMPUTED from the message, never taken from the
     attestation. If one was supplied anyway it must agree, because
     trusting it would let anyone sign one thing and present it as a
     signature over another. */
  const digest = bindDigest(message, a.leaf);
  if (a.digest !== undefined && !equal(digest, a.digest)) {
    return { ok: false, why: "the attestation's digest is not this message's digest" };
  }

  const pk = recover(a.pubSeed, a.leaf, a.signature, digest);
  if (!checkPath(root, leafHash(pk, a.leaf), a.leaf, a.path)) {
    return { ok: false, why: "the recovered key does not climb to this root" };
  }
  return { ok: true, why: `leaf ${a.leaf} of 0..${LEAVES - 1}, ${verifyCost(digest)} hashes walked` };
}

/** Serialise exactly the bytes a chain would have to be given. */
export function encodeAttestation(a: Attestation): Uint8Array {
  const out = concat(u32be(a.leaf), a.pubSeed, a.signature, a.path);
  if (out.length !== ATTESTATION_BYTES) {
    throw new Error(`encoded ${out.length} B, scheme.ts says ${ATTESTATION_BYTES}`);
  }
  return out;
}

/**
 * The identity as a human-readable address. Not an ed25519 key: a hash.
 *
 * ── THE PREFIX WAS THE SIBLING'S NAME ───────────────────────────────────
 * This read `eph1` for as long as the project existed. A rename sweep
 * changes sentences; a four-character prefix inside a base32 encoder is
 * not a sentence, so every address this product derived and printed
 * carried the name of the project it was copied from, on the identity
 * page, in `var/identities.json` and in the store.
 *
 * It is `unc1` now, which means every address derived before this
 * changed is a different string for the same root. That is why the rows
 * carrying the old prefix were cleared rather than left to be read as
 * this project's history.
 */
export function addressOf(root: Uint8Array): string {
  const h = sha256(concat(enc.encode(SCHEME_ID), root));
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, acc = 0, out = "unc1";
  for (let i = 0; i < 16; i++) {
    acc = (acc << 8) | h[i];
    bits += 8;
    while (bits >= 5) { out += A[(acc >> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}

export const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((p) => parseInt(p, 16)));
