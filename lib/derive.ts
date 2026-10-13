/**
 * ── WHERE THE SEEDS COME FROM, AND WHY THEY ARE NOT STORED ───────────────
 *
 * An identity here is two 32-byte seeds. Everything else, all 256 one-time
 * keys and the root above them, is derived from those two and can be
 * rebuilt from scratch in a browser tab in under a second.
 *
 * So they are never stored. They are derived from a signature the wallet
 * produces over a fixed sentence, which means:
 *
 *   - losing this site loses nothing; the same wallet rebuilds the same
 *     identity anywhere the algorithm is published
 *   - a server breach leaks no key material, because no key material was
 *     ever sent to a server
 *   - and the user can verify that claim by rebuilding the root offline
 *     and comparing it to the one we show
 *
 * ── THE HONEST LIMIT, WHICH THE SITE MUST ALSO PRINT ─────────────────────
 * The seeds come from an ed25519 signature. A quantum adversary who can
 * break ed25519 can forge that signature and therefore rederive the
 * identity. So a wallet-derived identity is post-quantum for everyone
 * EXCEPT someone who has already broken your wallet.
 *
 * That is why `hardened` exists: a hardened identity mixes in a secret the
 * wallet never saw, so the seed is not reachable from the ed25519 key
 * alone. The site labels the two differently and never calls the first one
 * quantum-secured, because that would be the one sentence on the whole
 * site that is not true.
 */
import { sha256 } from "@noble/hashes/sha2";
import { N, SCHEME_ID } from "./scheme.ts";
import { concat, u32be } from "./wots.ts";

const enc = new TextEncoder();

/**
 * The exact sentence a wallet is asked to sign.
 *
 * It names the scheme and the version, so a signature gathered for this
 * purpose cannot be replayed to derive a different scheme's identity, and
 * so that a future version derives a DIFFERENT identity rather than
 * silently colliding with this one.
 */
export function derivationMessage(address: string, version = 1): string {
  return [
    `${SCHEME_ID}`,
    ``,
    `Derive a post-quantum identity for:`,
    `${address}`,
    ``,
    `Version ${version}. This signature never leaves your browser and`,
    `authorises nothing. It is hashed to seed 256 one-time keys.`,
  ].join("\n");
}

export type Seeds = { skSeed: Uint8Array; pubSeed: Uint8Array; hardened: boolean };

/**
 * Two seeds from one signature, separated so neither can be computed from
 * the other without the signature.
 *
 * `extra` is the hardening secret. When it is present the ed25519 signature
 * alone is not enough, which is the whole difference between the two kinds
 * of identity this site offers.
 */
export function seedsFromSignature(signature: Uint8Array, extra?: Uint8Array): Seeds {
  if (signature.length < 32) throw new Error(`a wallet signature should be at least 32 bytes, got ${signature.length}`);
  const base = extra && extra.length > 0 ? concat(signature, enc.encode("|hardened|"), extra) : signature;
  const skSeed = sha256(concat(enc.encode(`${SCHEME_ID}/sk`), u32be(0), base));
  const pubSeed = sha256(concat(enc.encode(`${SCHEME_ID}/pub`), u32be(1), base));
  if (skSeed.length !== N || pubSeed.length !== N) throw new Error("seed length is wrong");
  return { skSeed, pubSeed, hardened: Boolean(extra && extra.length > 0) };
}

/**
 * What a launch actually commits to.
 *
 * The one-time key does not sign "a coin". It signs this exact record, so
 * a reader checking the attestation later is checking the name, the
 * symbol, the supply and the mint together. Changing any field changes the
 * digest and the signature stops verifying, which is the property that
 * makes the attestation worth anything at all.
 */
export type LaunchRecord = {
  name: string;
  symbol: string;
  supply: string;
  mint: string;
  creator: string;
  at: string;
  /**
   * ── THE IMAGE IS COVERED BY ITS HASH, NOT BY ITS URL ──────────────────
   * Signing a URL commits to a location, and whoever controls that
   * location can change what is at it afterwards. Signing the sha256 of
   * the bytes commits to the picture. A reader downloads whatever the
   * metadata points at, hashes it, and compares.
   *
   * Empty string when there is no image, which is signed too: a coin
   * cannot gain one later without a fresh signature from a fresh leaf.
   */
  imageSha: string;
  description: string;
  /**
   * ── WHETHER THE MINT CAME OUT OF THE KEY, AND IT IS SIGNED ───────────
   * Quantum derives the mint address from the one-time key, so a leaf
   * can only ever produce one coin and a reader can rebuild the address
   * from the key. Standard uses a random keypair and signs the record
   * anyway: the attestation still proves who made the coin, it simply
   * cannot prove the address came from the key.
   *
   * This lives INSIDE the signed record because nobody else can check
   * it. The derivation needs `skSeed`, which never leaves the browser,
   * so no server and no reader can recompute the address and compare.
   * An unsigned flag reading "derived" would be a claim anyone could
   * set, which is the exact shape of thing this project dissects other
   * sites for.
   */
  mintDerived: boolean;
};

/**
 * Canonical bytes for a launch record. Field order is fixed, forever.
 *
 * Adding a field later changes every digest, which is correct: an old
 * attestation covers the old record and must keep verifying against it,
 * so a new field means a new scheme id, not a quiet extension.
 */
export function encodeLaunch(r: LaunchRecord): Uint8Array {
  /* Length-prefixed, so "ab"+"c" and "a"+"bc" cannot hash the same. A
     scheme that joins fields with a separator is a scheme where a field
     containing the separator rewrites the record. */
  const parts: Uint8Array[] = [];
  /* `mintDerived` goes LAST, and as "1" or "0" so it is length-prefixed
     like every other field. Appended rather than inserted: the order of
     the first eight is fixed forever, and the ninth is the whole reason
     the scheme id moved to v2. */
  for (const v of [
    r.name, r.symbol, r.supply, r.mint, r.creator, r.at, r.imageSha, r.description,
    r.mintDerived ? "1" : "0",
  ]) {
    const b = enc.encode(v);
    parts.push(u32be(b.length), b);
  }
  return concat(enc.encode(`${SCHEME_ID}/launch`), ...parts);
}
