/**
 * Do the schemes the launch page offers actually sign?
 *
 *   npm run probe-pq
 *
 * ── A SCHEME CARD IS A CLAIM ────────────────────────────────────────────
 * The page prints eight names, eight standard numbers and eight byte
 * figures, and until now seven of them said "not implemented here". They
 * do not say that any more, which turns every one of those cards into a
 * claim that something will sign when it is picked.
 *
 * So each one signs here, verifies its own signature, and REFUSES a
 * flipped bit. The refusal is the half that matters: a verifier that
 * returns true for everything passes the first two checks and is worth
 * nothing. A scheme whose tamper case is not refused fails outright
 * rather than being reported as partially working.
 *
 * ── AND THE BYTE FIGURE ON THE CARD IS THE ONE IT PRODUCES ──────────────
 * Not the one a standard document publishes. Those agreed for four of
 * the six and disagreed for both Falcons, because a Falcon signature is
 * variable length and the page was printing the padded size beside four
 * fixed-size schemes without saying so.
 */
import { SCHEMES } from "../lib/schemes.ts";
import { signerFor } from "../lib/pq.ts";
import { ATTESTATION_BYTES } from "../lib/scheme.ts";

let bad = 0;
const ok = (good: boolean, name: string, detail = "") => {
  if (!good) bad++;
  console.log(`  ${good ? "ok  " : "FAIL"}  ${name}${detail ? `\n          ${detail}` : ""}`);
};

const enc = new TextEncoder();
const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));

console.log(`\nthe signature schemes the launch page offers\n`);

ok(SCHEMES.length === 8, `${SCHEMES.length} schemes are listed`);

for (const s of SCHEMES) {
  console.log(`\n${s.name} · ${s.standard}`);

  if (s.id === "wots-merkle") {
    /* Covered end to end by probe-crypto, which has the tree, the leaf
       and the auth path. Naming it here rather than letting the loop
       skip it silently. */
    ok(s.bytes === ATTESTATION_BYTES,
      "its figure is read from lib/scheme.ts, not typed",
      `${s.bytes} B, and probe-crypto signs and verifies it with its tree`);
    ok(s.oneTime, "and it is the one-time scheme, which is this site's claim");
    continue;
  }

  const alg = signerFor(s.id);
  if (!alg) {
    ok(false, `${s.id} has a signer`, "it is listed on the page and nothing implements it");
    continue;
  }

  const t0 = Date.now();
  const keys = alg.keygen(rnd(alg.seedLen));
  const msg = enc.encode(`unclone/probe/${s.id}`);
  const sig = alg.sign(msg, keys.secretKey);

  ok(alg.verify(sig, msg, keys.publicKey),
    "it signs, and verifies its own signature",
    `${sig.length.toLocaleString("en-US")} B in ${((Date.now() - t0) / 1000).toFixed(2)}s`);

  /* The figure on the card is what this produces, or the card is wrong. */
  ok(sig.length === s.bytes,
    "and the byte figure on its card is the one it produced",
    `card says ${s.bytes.toLocaleString("en-US")} B, it produced ${sig.length.toLocaleString("en-US")} B`);

  /* CONTROL. One flipped bit in the signature. */
  const flipped = Uint8Array.from(sig);
  flipped[Math.floor(flipped.length / 2)] ^= 1;
  ok(!alg.verify(flipped, msg, keys.publicKey),
    "CONTROL. one flipped bit in the signature is REFUSED",
    "without this, verify returning true proves nothing");

  /* CONTROL. The right signature over the wrong message. */
  ok(!alg.verify(sig, enc.encode(`unclone/probe/${s.id}!`), keys.publicKey),
    "CONTROL. and the same signature over a different message is REFUSED",
    "one character added to the message");

  /* CONTROL. The right signature under somebody else's key. */
  const other = alg.keygen(rnd(alg.seedLen));
  ok(!alg.verify(sig, msg, other.publicKey),
    "CONTROL. and under a different public key it is REFUSED");

  ok(!s.oneTime,
    "it is marked MANY-TIME, because its key can sign again",
    "only WOTS + Merkle burns a leaf, and the page must not say otherwise about this one");
}

/**
 * ── AND THE HYBRID MUST NEED BOTH HALVES ────────────────────────────────
 * The composite's entire point is that breaking one primitive is
 * survivable. If its verify were an `||`, every check above would still
 * pass: it signs, it verifies, and a flipped bit in one half would be
 * covered by the other half still being good. So each half is corrupted
 * ON ITS OWN and both must be refused.
 */
console.log(`\nthe hybrid, which has to need BOTH halves`);
{
  const alg = signerFor("ed25519-ml-dsa-65");
  if (!alg) {
    ok(false, "the hybrid has a signer");
  } else {
    const keys = alg.keygen(rnd(alg.seedLen));
    const msg = enc.encode("unclone/probe/composite");
    const sig = alg.sign(msg, keys.secretKey);
    ok(alg.verify(sig, msg, keys.publicKey), "it verifies intact", `${sig.length.toLocaleString("en-US")} B`);

    const edBroken = Uint8Array.from(sig);
    edBroken[10] ^= 1;
    ok(!alg.verify(edBroken, msg, keys.publicKey),
      "CONTROL. breaking ONLY the ed25519 half is refused",
      "byte 10, inside the first 64. An `||` verify would pass this");

    const mlBroken = Uint8Array.from(sig);
    mlBroken[sig.length - 10] ^= 1;
    ok(!alg.verify(mlBroken, msg, keys.publicKey),
      "CONTROL. breaking ONLY the ML-DSA half is refused",
      "ten bytes from the end. An `||` verify would pass this too");
  }
}

console.log(bad === 0
  ? `\n  all ${SCHEMES.length} schemes sign, and every one of them refuses a bad signature.\n`
  : `\n  ${bad} problem(s).\n`);
process.exitCode = bad === 0 ? 0 : 1;
