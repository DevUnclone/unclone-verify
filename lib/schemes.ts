/**
 * ── THE SCHEMES, AND ALL EIGHT OF THEM SIGN ─────────────────────────────
 *
 * Seven of these used to say "not implemented here". That was true and
 * it did not have to stay true: `@noble/post-quantum` is by the author
 * of the `@noble/hashes` this project already signs with, and it covers
 * FIPS 204, FIPS 205 and Falcon. `lib/pq.ts` wires them up and
 * `probe-pq` makes each one sign, verify, and refuse a flipped bit.
 *
 * ── ONE-TIME IS A PROPERTY OF ONE OF THEM, NOT OF THE PAGE ──────────────
 * WOTS + Merkle burns a leaf: the key signs once and a second use is
 * visible to anyone holding the root. That is this site's claim, and it
 * belongs to that scheme alone. ML-DSA, Falcon and SLH-DSA keys can sign
 * again and nothing makes the second signature detectable. `oneTime`
 * carries that difference so no card can inherit a sentence it has not
 * earned, which is the same fault as [[a-weaker-claim-must-not-inherit-the-stronger]].
 *
 * ── THE BYTE FIGURES ARE WHAT THE CODE PRODUCES ─────────────────────────
 * Not what a standard document publishes. Measured, all eight:
 *
 *   ML-DSA-65 3,309 · ML-DSA-87 4,627 · SLH-DSA-128s 7,856 ·
 *   SLH-DSA-SHAKE-128f 17,088 — the published figures, exactly.
 *
 * Both Falcons disagreed. A Falcon signature is VARIABLE length: 654,
 * 655, 656, 658 and 659 bytes over six messages for Falcon-512, while
 * this page printed a flat 666 beside four fixed-size schemes. 666 is
 * the PADDED encoding's size, so the padded variants are what sign here
 * and the figure is now exactly what comes out, every time.
 *
 * WOTS's figure is computed from `lib/scheme.ts` rather than typed, so
 * the scheme this site is built around cannot drift.
 */
import { ATTESTATION_BYTES } from "./scheme.ts";

export type SchemeCard = {
  id: string;
  name: string;
  standard: string;
  family: string;
  bytes: number;
  note: string;
  implemented: boolean;
  /** True only for a scheme whose key is spent by signing once. */
  oneTime: boolean;
  /**
   * Whether a LAUNCH can be attested with it today.
   *
   * `implemented` says this repo can sign and verify with the scheme,
   * which `probe-pq` proves for all eight. That is not the same as being
   * able to carry a launch: an attestation here is bound to a Merkle
   * identity with a leaf index and an authentication path, and the
   * submit route verifies exactly that shape. Offering a scheme the
   * server would refuse is a picker promising what the server will not
   * do, so the two facts are two fields.
   */
  canAttest: boolean;
};

export const SCHEMES: SchemeCard[] = [
  {
    id: "wots-merkle",
    name: "WOTS + Merkle",
    standard: "RFC 8391 style",
    family: "XMSS-style · hash-based · one-time",
    /* Read from the module that asserts its own arithmetic. */
    bytes: ATTESTATION_BYTES,
    note: "burns one leaf per launch",
    implemented: true,
    oneTime: true,
    canAttest: true,
  },
  { id: "ml-dsa-65", name: "ML-DSA-65", standard: "FIPS 204", family: "Dilithium · lattice · Module-LWE", bytes: 3309, note: "many-time key", implemented: true, oneTime: false, canAttest: false },
  { id: "slh-dsa-128s", name: "SLH-DSA-128s", standard: "FIPS 205", family: "SPHINCS+ · hash-based · stateless", bytes: 7856, note: "many-time key · slowest to sign", implemented: true, oneTime: false, canAttest: false },
  { id: "falcon-512", name: "Falcon-512", standard: "FIPS 206 (draft)", family: "FN-DSA · lattice · NTRU", bytes: 666, note: "many-time key · padded encoding", implemented: true, oneTime: false, canAttest: false },
  { id: "ml-dsa-87", name: "ML-DSA-87", standard: "FIPS 204", family: "Dilithium5 · lattice · level 5", bytes: 4627, note: "many-time key", implemented: true, oneTime: false, canAttest: false },
  { id: "slh-dsa-shake-128f", name: "SLH-DSA-SHAKE-128f", standard: "FIPS 205", family: "SPHINCS+ · hash-based · SHA-3", bytes: 17088, note: "many-time key · largest here", implemented: true, oneTime: false, canAttest: false },
  { id: "falcon-1024", name: "Falcon-1024", standard: "FIPS 206 (draft)", family: "FN-DSA · lattice · level 5", bytes: 1280, note: "many-time key · padded encoding", implemented: true, oneTime: false, canAttest: false },
  { id: "ed25519-ml-dsa-65", name: "ed25519 + ML-DSA-65", standard: "IETF composite draft", family: "hybrid · curve + lattice · both must verify", bytes: 3373, note: "many-time key · both halves checked", implemented: true, oneTime: false, canAttest: false },
];

export const DEFAULT_SCHEME = "wots-merkle";

export const implemented = () => SCHEMES.filter((s) => s.implemented);

export const schemeById = (id: string) => SCHEMES.find((s) => s.id === id) ?? null;

/** The schemes a launch can actually be attested with today. */
export const attestable = () => SCHEMES.filter((s) => s.canAttest);
