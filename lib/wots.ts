/**
 * ── WINTERNITZ ONE-TIME SIGNATURES, w = 16, OVER SHA-256 ─────────────────
 *
 * The only assumption is that SHA-256 is a one-way function. There is no
 * elliptic curve here and nothing a quantum computer gets a useful speedup
 * against beyond Grover, which halves the security level: 256-bit hashes
 * give roughly 128 bits against a quantum adversary and that is the whole
 * claim. Nothing in this file claims more than that, and the site must not
 * either.
 *
 * ── HOW IT WORKS, IN FIVE LINES ──────────────────────────────────────────
 *   sk_i    a secret value per chain, derived from one seed
 *   pk_i    sk_i hashed 15 times
 *   d_i     the i-th 4-bit nibble of the digest, plus a checksum
 *   sig_i   sk_i hashed d_i times
 *   verify  hash sig_i another (15 - d_i) times and you must land on pk_i
 *
 * ── WHY THE CHECKSUM, AND WHY IT COUNTS DOWN ─────────────────────────────
 * A forger holding one signature can hash any sig_i forward, which lets
 * them RAISE any nibble d_i for free. The checksum is the sum of
 * (15 - d_i) over the message chains, so raising a message nibble always
 * LOWERS the checksum, and lowering a checksum nibble means walking a hash
 * chain BACKWARDS. That is the entire security argument and it is the one
 * thing in this file that must not be got subtly wrong, so
 * `scripts/probe-crypto.mjs` attacks it directly rather than only testing
 * that honest signatures verify.
 *
 * ── ONE SIGNATURE PER KEY. EVER. ─────────────────────────────────────────
 * Two signatures under the same key leak enough chain values to forge a
 * third. Nothing in this file can prevent that; it is the caller's job, and
 * `lib/identity.ts` is where a leaf is marked spent.
 */
import { sha256 } from "@noble/hashes/sha2";
/* Explicit `.ts` extensions throughout this project's own imports, so the
   same files run under `node` for the probes AND under Turbopack for the
   site. Without them the probes cannot load the library at all, and a
   scheme nobody can run outside the bundler is a scheme nobody can check. */
import { ADRS_CHAIN, ADRS_SECRET, LEN, LEN1, N, SIG_BYTES, W_MAX } from "./scheme.ts";

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

export const u32be = (v: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, false);
  return b;
};

/**
 * ── THE LITTLE-ENDIAN PAIR, AND WHY THEY LIVE HERE ──────────────────────
 * Solana instruction data is little-endian, so the pump.fun and vault
 * clients need these. They used to call `Buffer.alloc(n).writeUInt32LE`
 * and `.writeBigUInt64LE`, which is fine under `node` and broke on the
 * live site: the browser's `Buffer` is whatever the bundler shims, and
 * its objects have no BigInt writers. Clicking Launch with a dev buy
 * answered `t.writeBigUInt64LE is not a function`.
 *
 * Nothing in this file has ever touched `Buffer`, which is why the
 * signing path survived and only the transaction builders fell over. The
 * two helpers belong beside `u32be` for that reason: a byte is a byte in
 * both runtimes and almost nothing else is.
 *
 * `u64le` takes a bigint rather than a number because a lamport count
 * passes 2^53 and `Number` would round it without saying so.
 */
export const u32le = (v: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, true);
  return b;
};

export const u64le = (v: bigint): Uint8Array => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
};

/**
 * Reading one back, for the account layouts the clients decode. Same
 * reason as the writers: `readBigUInt64LE` is a Buffer method, and two
 * of them were still sitting in browser-reachable modules after the
 * writers were fixed. `probe-crypto` found them by rule rather than by
 * anyone noticing.
 *
 * `byteOffset` is carried through because a Buffer is a view ONTO a
 * pooled ArrayBuffer: `b.buffer` is usually not the bytes you think it
 * is, and reading at offset 36 of the pool instead of the account would
 * return a plausible wrong number rather than throwing.
 */
export const readU64le = (b: Uint8Array, at: number): bigint =>
  new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(at, true);

export const equal = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  /* Constant time in the length of the inputs. These are public values, so
     this is belt and braces, but a comparison that short-circuits is a bad
     habit to leave in a file about signatures. */
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

/**
 * A 32-byte domain-separated address.
 *
 * Every hash in the scheme is tagged with what it is for, which leaf it
 * belongs to, which chain, and which step. Without this, a value produced
 * in one role could be replayed in another.
 */
export function adrs(type: number, leaf: number, chain: number, step: number): Uint8Array {
  return concat(u32be(type), u32be(leaf), u32be(chain), u32be(step), new Uint8Array(16));
}

/** The tweakable hash. */
export const F = (pubSeed: Uint8Array, address: Uint8Array, x: Uint8Array): Uint8Array =>
  sha256(concat(pubSeed, address, x));

/**
 * The 67 chain lengths for a digest: 64 message nibbles then 3 checksum
 * nibbles, high nibble before low.
 */
export function steps(digest: Uint8Array): Uint8Array {
  if (digest.length !== N) throw new Error(`digest must be ${N} bytes, got ${digest.length}`);
  const out = new Uint8Array(LEN);
  let checksum = 0;
  for (let j = 0; j < N; j++) {
    const hi = digest[j] >> 4;
    const lo = digest[j] & 0x0f;
    out[2 * j] = hi;
    out[2 * j + 1] = lo;
    checksum += (W_MAX - hi) + (W_MAX - lo);
  }
  /* checksum is at most 64 * 15 = 960, which is three base-16 digits. */
  out[LEN1] = (checksum >> 8) & 0x0f;
  out[LEN1 + 1] = (checksum >> 4) & 0x0f;
  out[LEN1 + 2] = checksum & 0x0f;
  return out;
}

/** How many hashes a verifier walks for this digest. 45 at best, 990 at worst. */
export const verifyCost = (digest: Uint8Array): number =>
  [...steps(digest)].reduce((a, d) => a + (W_MAX - d), 0);

/** Walk a value through chain positions [from, to). */
export function chain(
  pubSeed: Uint8Array, leaf: number, index: number, x: Uint8Array, from: number, to: number,
): Uint8Array {
  let v = x;
  for (let s = from; s < to; s++) v = F(pubSeed, adrs(ADRS_CHAIN, leaf, index, s), v);
  return v;
}

/** The secret value for one chain, derived rather than stored. */
export const secretElement = (skSeed: Uint8Array, leaf: number, index: number): Uint8Array =>
  sha256(concat(skSeed, adrs(ADRS_SECRET, leaf, index, 0)));

/** The one-time public key: every chain walked all the way to 15. */
export function publicKey(skSeed: Uint8Array, pubSeed: Uint8Array, leaf: number): Uint8Array {
  const out = new Uint8Array(SIG_BYTES);
  for (let i = 0; i < LEN; i++) {
    out.set(chain(pubSeed, leaf, i, secretElement(skSeed, leaf, i), 0, W_MAX), i * N);
  }
  return out;
}

/** Sign a 32-byte digest. ONE digest per leaf, for the life of the identity. */
export function sign(
  skSeed: Uint8Array, pubSeed: Uint8Array, leaf: number, digest: Uint8Array,
): Uint8Array {
  const d = steps(digest);
  const out = new Uint8Array(SIG_BYTES);
  for (let i = 0; i < LEN; i++) {
    out.set(chain(pubSeed, leaf, i, secretElement(skSeed, leaf, i), 0, d[i]), i * N);
  }
  return out;
}

/**
 * Recover the one-time public key a signature implies.
 *
 * This is the whole verifier. It never sees a secret and never needs the
 * signer: it walks each chain the REMAINING way and reports what it lands
 * on. The caller compares that against the committed key.
 */
export function recover(
  pubSeed: Uint8Array, leaf: number, signature: Uint8Array, digest: Uint8Array,
): Uint8Array {
  if (signature.length !== SIG_BYTES) {
    throw new Error(`signature must be ${SIG_BYTES} bytes, got ${signature.length}`);
  }
  const d = steps(digest);
  const out = new Uint8Array(SIG_BYTES);
  for (let i = 0; i < LEN; i++) {
    const part = signature.subarray(i * N, (i + 1) * N);
    out.set(chain(pubSeed, leaf, i, part, d[i], W_MAX), i * N);
  }
  return out;
}

/** Does this signature open to this one-time public key? */
export const verify = (
  pk: Uint8Array, pubSeed: Uint8Array, leaf: number, signature: Uint8Array, digest: Uint8Array,
): boolean => equal(recover(pubSeed, leaf, signature, digest), pk);
