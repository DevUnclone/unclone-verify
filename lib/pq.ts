/**
 * ── THE OTHER SEVEN, MADE REAL ──────────────────────────────────────────
 *
 * This file used not to exist. The launch page listed eight post-quantum
 * schemes, implemented one, and said so on the other seven. That was
 * honest and it was also a smaller product than it needed to be: the
 * alternatives are standardised, and `@noble/post-quantum` is by the same
 * author as the `@noble/hashes` this project already signs with.
 *
 * So all eight sign here now. `probe-pq` makes each one sign and verify,
 * and makes each one REFUSE a flipped bit, because a verifier that cannot
 * say no is not a verifier.
 *
 * ── AND THEY ARE NOT THE SAME KIND OF THING ─────────────────────────────
 * WOTS + Merkle is ONE-TIME. The key signs once, the leaf is burned, and
 * reuse is detectable by anyone holding the root. That is this site's
 * whole claim and it belongs to that scheme alone.
 *
 * ML-DSA, Falcon and SLH-DSA are MANY-TIME. Their keys can sign a second
 * thing, and nothing about them makes a second signature visible. They
 * are stronger in other ways and weaker in exactly the way this site
 * cares about, so `oneTime` is carried on every entry and the page is
 * forbidden from printing the one-time sentence over a many-time scheme.
 *
 * ── FALCON IS VARIABLE LENGTH, SO THE PADDED FORM IS USED ───────────────
 * A plain Falcon-512 signature measured 654, 655, 656, 658 and 659 bytes
 * over six messages. The page was printing 666 beside four fixed-size
 * schemes as though it were one of them. 666 is the PADDED size, so the
 * padded variants are what sign here: the figure is then exactly what
 * this code produces, every time, and the card says which encoding it
 * means rather than quietly averaging.
 */
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s, slh_dsa_shake_128f } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded, falcon1024padded } from "@noble/post-quantum/falcon.js";
import { ed25519 } from "@noble/curves/ed25519.js";

export type Keys = { publicKey: Uint8Array; secretKey: Uint8Array };

export type Signer = {
  /** Bytes of randomness `keygen` wants. ML-DSA takes 32, SLH-DSA 48. */
  seedLen: number;
  keygen(seed: Uint8Array): Keys;
  sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean;
};

/**
 * `@noble/post-quantum` takes `sign(msg, secretKey)` and
 * `verify(sig, msg, publicKey)`. The first probe written against it had
 * the arguments the other way round, and the library correctly rejected
 * an eighteen-byte "secret key" that was really the message. The shape
 * is pinned here once so nothing downstream has to remember it.
 */
type Noble = {
  lengths?: { seed?: number };
  keygen(seed: Uint8Array): Keys;
  sign(msg: Uint8Array, sk: Uint8Array): Uint8Array;
  verify(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean;
};

const wrap = (a: Noble): Signer => ({
  seedLen: a.lengths?.seed ?? 32,
  keygen: (seed) => a.keygen(seed),
  sign: (msg, sk) => a.sign(msg, sk),
  verify: (sig, msg, pk) => a.verify(sig, msg, pk),
});

/**
 * ── THE HYBRID IS BOTH, AND BOTH MUST VERIFY ────────────────────────────
 * The IETF composite draft's whole point is that a break of either
 * primitive is survivable. So the two signatures are concatenated with
 * the ed25519 half first at its fixed 64 bytes, and `verify` returns
 * true only when BOTH halves verify. An `&&` that short-circuits is
 * fine here; an `||` would be the entire bug.
 */
const ED_SIG = 64;
const ED_PK = 32;
const composite: Signer = {
  seedLen: 32,
  keygen(seed) {
    const ed = ed25519.keygen(seed);
    const ml = ml_dsa65.keygen(seed);
    const publicKey = new Uint8Array(ED_PK + ml.publicKey.length);
    publicKey.set(ed.publicKey, 0);
    publicKey.set(ml.publicKey, ED_PK);
    const secretKey = new Uint8Array(ed.secretKey.length + ml.secretKey.length);
    secretKey.set(ed.secretKey, 0);
    secretKey.set(ml.secretKey, ed.secretKey.length);
    return { publicKey, secretKey };
  },
  sign(msg, sk) {
    const edSk = sk.subarray(0, 32);
    const mlSk = sk.subarray(32);
    const a = ed25519.sign(msg, edSk);
    const b = ml_dsa65.sign(msg, mlSk);
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  },
  verify(sig, msg, pk) {
    if (sig.length <= ED_SIG || pk.length <= ED_PK) return false;
    const edOk = ed25519.verify(sig.subarray(0, ED_SIG), msg, pk.subarray(0, ED_PK));
    const mlOk = ml_dsa65.verify(sig.subarray(ED_SIG), msg, pk.subarray(ED_PK));
    return edOk && mlOk;
  },
};

/**
 * Every scheme this site can sign with, EXCEPT WOTS + Merkle, which is
 * not here because it is not a drop-in: it carries a leaf index and an
 * authentication path, and it lives in `lib/wots.ts` with the tree.
 */
export const SIGNERS: Record<string, Signer> = {
  "ml-dsa-65": wrap(ml_dsa65 as unknown as Noble),
  "ml-dsa-87": wrap(ml_dsa87 as unknown as Noble),
  "slh-dsa-128s": wrap(slh_dsa_sha2_128s as unknown as Noble),
  "slh-dsa-shake-128f": wrap(slh_dsa_shake_128f as unknown as Noble),
  "falcon-512": wrap(falcon512padded as unknown as Noble),
  "falcon-1024": wrap(falcon1024padded as unknown as Noble),
  "ed25519-ml-dsa-65": composite,
};

export const signerFor = (id: string): Signer | null => SIGNERS[id] ?? null;
