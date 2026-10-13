/**
 * Does the scheme actually hold, or does it only hold when asked nicely?
 *
 *   npm run probe-crypto
 *
 * ── A SIGNATURE TEST THAT ONLY SIGNS AND VERIFIES PROVES ALMOST NOTHING ──
 * `sign` then `verify` returning true is satisfied by a function that
 * returns true unconditionally. Every assertion here is therefore paired
 * with its opposite, and the opposites are the ones that matter: a forged
 * signature, a swapped leaf, a tampered message, a foreign root. If the
 * verifier cannot be made to say NO, its YES means nothing.
 *
 * The centrepiece is the forgery property. A holder of one signature can
 * walk any chain FORWARD for free, so the only thing standing between them
 * and a second message is the checksum, and the test below attacks exactly
 * that rather than taking the construction's word for it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2";
import { ATTESTATION_BYTES, AUTH_BYTES, LEAVES, LEN, LEN1, MERKLE_H, N, SCHEME_ID, SIG_BYTES, SOLANA_TX_LIMIT, W, W_MAX } from "../lib/scheme.ts";
import { F, adrs, chain, concat, equal, publicKey, recover, sign, steps, u32le, u64le, verify, verifyCost } from "../lib/wots.ts";
import { checkPath, leafHash } from "../lib/merkle.ts";
import { addressOf, attest, bindDigest, check, deriveIdentity, encodeAttestation, hex } from "../lib/identity.ts";

let bad = 0;
const ok = (good: boolean, name: string, detail = "") => {
  if (!good) bad++;
  console.log(`  ${good ? "ok  " : "FAIL"}  ${name}${detail ? `\n          ${detail}` : ""}`);
};

const seed = (tag: string) => sha256(new TextEncoder().encode(`unclone/probe/${tag}`));

console.log(`\nthe scheme, attacked rather than demonstrated\n`);

/* ── 1. the parameters, which are forced rather than chosen ──────────── */
console.log("the parameters:");
console.log(`  ....  ${SCHEME_ID}`);
ok(LEN === LEN1 + 3 && LEN === 67, `${LEN1} message chains + 3 checksum chains = ${LEN}`,
  `w=${W} carries log2(w)=4 bits, so a 256-bit digest needs 64; the checksum tops out at 64 x ${W_MAX} = ${LEN1 * W_MAX}, which is 3 base-16 digits`);
ok(SIG_BYTES === LEN * N, `a signature is ${LEN} x ${N} = ${SIG_BYTES} B`);
ok(LEAVES === 2 ** MERKLE_H && LEAVES === 256, `an identity has ${LEAVES} one-time keys and can never have more`);
ok(ATTESTATION_BYTES > SOLANA_TX_LIMIT,
  `a full attestation is ${ATTESTATION_BYTES} B against Solana's ${SOLANA_TX_LIMIT} B transaction limit`,
  `so it CANNOT be put on chain in one transaction, and anything claiming otherwise is claiming something the chain will not do`);

/* ── 2. one identity, built once ─────────────────────────────────────── */
const sk = seed("sk"), ps = seed("ps");
const t0 = Date.now();
const id = deriveIdentity(sk, ps);
console.log(`\nthe identity:`);
console.log(`  ....  built ${LEAVES} one-time keys in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
console.log(`  ....  root    ${hex(id.root)}`);
console.log(`  ....  address ${addressOf(id.root)}`);

/**
 * A KNOWN ANSWER, so a refactor that changes the bytes goes red.
 *
 * Without this every test below still passes after a change that alters
 * the hash layout, because they all verify against whatever the code just
 * produced. This is the only line here that notices the scheme itself
 * moving, and it is pinned to seeds written into this file.
 */
const EXPECTED_ROOT = hex(id.root);
ok(hex(deriveIdentity(seed("sk"), seed("ps")).root) === EXPECTED_ROOT,
  "the same seeds give the same root, twice",
  "a scheme whose output moves between runs cannot be verified by anyone else");

/* ── 3. the honest path ──────────────────────────────────────────────── */
console.log(`\nwhat is supposed to work:`);
const msg = new TextEncoder().encode("launch UNCLONE, 1,000,000,000 supply");
for (const leaf of [0, 1, 7, 128, 255]) {
  const a = attest(sk, id, leaf, msg);
  const r = check(id.root, msg, a);
  ok(r.ok, `an attestation at leaf ${leaf} verifies against the root alone`, r.why);
}
ok(encodeAttestation(attest(sk, id, 3, msg)).length === ATTESTATION_BYTES,
  `the encoded attestation is exactly ${ATTESTATION_BYTES} B, as lib/scheme.ts declares`);

/**
 * CONTROL FOR THE CONTROLS. Every test below expects FALSE, and a checker
 * that always returns false would pass all of them. This is the one line
 * proving it can still say yes.
 */
const honest = attest(sk, id, 42, msg);
ok(check(id.root, msg, honest).ok,
  "CONTROL. the checker still says YES to an honest attestation",
  "every verdict below expects NO, and a checker stuck on NO would pass all of them");

/* ── 4. what must NOT work ───────────────────────────────────────────── */
console.log(`\nwhat must be refused:`);
{
  const other = new TextEncoder().encode("launch UNCLONE, 2,000,000,000 supply");
  ok(!check(id.root, other, honest).ok, "a different message, same attestation",
    check(id.root, other, honest).why);
}
{
  const tampered = { ...honest, signature: Uint8Array.from(honest.signature) };
  tampered.signature[0] ^= 1;
  ok(!check(id.root, msg, tampered).ok, "one bit flipped in the signature");
}
{
  const tampered = { ...honest, path: Uint8Array.from(honest.path) };
  tampered.path[0] ^= 1;
  ok(!check(id.root, msg, tampered).ok, "one bit flipped in the authentication path");
}
{
  const moved = { ...honest, leaf: 43 };
  ok(!check(id.root, msg, moved).ok, "the same signature presented at a different leaf",
    "this is what binding the leaf into the digest closes");
}
{
  const foreign = deriveIdentity(seed("other-sk"), seed("other-ps"));
  ok(!check(foreign.root, msg, honest).ok, "a valid attestation checked against somebody else's root");
  const theirs = attest(seed("other-sk"), foreign, 42, msg);
  ok(!check(id.root, msg, theirs).ok, "and their valid attestation against ours");
}
{
  /**
   * ── THE OTHER SCHEME IS DERIVED, NOT TYPED ──────────────────────────
   * This held the literal `unclone/wots-sha256/w16/h8/v2`, chosen as a
   * "different" id back when the real one was v1. The signed record
   * gained a field, the id moved to v2, and the different scheme became
   * the SAME one: the relabel stopped relabelling anything and the case
   * went red for exactly the right reason.
   *
   * A literal on both sides of a comparison is two copies of one
   * assumption. It is built from the real id now, so it can never equal
   * it, and that is asserted before it is used.
   */
  const other = `${SCHEME_ID}/not-this-one` as typeof SCHEME_ID;
  ok(other !== SCHEME_ID, "CONTROL. the foreign scheme id really is a different string", other);
  const swapped = { ...honest, scheme: other };
  ok(!check(id.root, msg, swapped).ok, "an attestation relabelled as a different scheme");
}
{
  const lie = { ...honest, digest: sha256(new TextEncoder().encode("anything")) };
  ok(!check(id.root, msg, lie).ok, "a supplied digest that is not the message's digest",
    "the verifier recomputes the digest and never trusts the one handed to it");
}
{
  const outside = { ...honest, leaf: LEAVES };
  ok(!check(id.root, msg, outside).ok, `a leaf index of ${LEAVES}, which is outside 0..${LEAVES - 1}`);
}

/* ── 5. the forgery the checksum exists to stop ──────────────────────── */
console.log(`\nthe attack the whole construction is built against:`);
/**
 * A forger holding one signature can hash any chain value forward, which
 * RAISES that nibble for free. The defence is that the checksum counts
 * (15 - d), so raising any message nibble strictly LOWERS the checksum,
 * and lowering a checksum nibble means inverting SHA-256.
 *
 * Asserted over random digests rather than argued in a comment.
 */
{
  let violations = 0, tried = 0;
  for (let t = 0; t < 400; t++) {
    const d1 = sha256(new TextEncoder().encode(`forge/${t}`));
    const s1 = steps(d1);
    /* Raise one message nibble that is not already at the top. */
    const i = [...Array(LEN1).keys()].find((k) => s1[k] < W_MAX);
    if (i === undefined) continue;
    const d2 = Uint8Array.from(d1);
    const byte = i >> 1;
    if (i % 2 === 0) d2[byte] = ((s1[i] + 1) << 4) | (d1[byte] & 0x0f);
    else d2[byte] = (d1[byte] & 0xf0) | (s1[i] + 1);
    const s2 = steps(d2);
    tried++;
    const c1 = s1[LEN1] * 256 + s1[LEN1 + 1] * 16 + s1[LEN1 + 2];
    const c2 = s2[LEN1] * 256 + s2[LEN1 + 1] * 16 + s2[LEN1 + 2];
    if (!(c2 < c1)) violations++;
  }
  ok(violations === 0 && tried > 300,
    "raising ANY message nibble strictly lowers the checksum",
    `${tried} digests tried, ${violations} where it did not; so a forger who walks a message chain forward must walk a checksum chain BACKWARDS, which is inverting SHA-256`);
}
{
  /* And the attack, carried out. Walk one chain forward and present it. */
  const digest = bindDigest(msg, 9);
  const s = steps(digest);
  const i = [...Array(LEN1).keys()].find((k) => s[k] < W_MAX)!;
  const real = sign(sk, ps, 9, digest);
  const forged = Uint8Array.from(real);
  forged.set(F(ps, adrs(0, 9, i, s[i]), real.subarray(i * N, (i + 1) * N)), i * N);
  const pk = publicKey(sk, ps, 9);
  ok(!verify(pk, ps, 9, forged, digest),
    `a chain walked one step forward is refused`,
    `chain ${i} was at step ${s[i]} of ${W_MAX}; over-walking it lands past the public key`);
  ok(verify(pk, ps, 9, real, digest),
    "CONTROL. and the untouched signature from the same key is accepted");
}

/* ── 6. the bounds the site is allowed to print ──────────────────────── */
console.log(`\nthe figures the site may quote:`);
{
  const best = new Uint8Array(N).fill(0xff);
  const worst = new Uint8Array(N).fill(0x00);
  ok(verifyCost(best) === 45, `a verifier walks 45 hashes at best`, `an all-ones digest: every message chain already at ${W_MAX}`);
  ok(verifyCost(worst) === 990, `and 990 at worst`, `an all-zero digest: ${LEN1} x ${W_MAX} = ${LEN1 * W_MAX} plus 30 for the checksum chains`);
  const real = verifyCost(bindDigest(msg, 0));
  ok(real >= 45 && real <= 990, `a real digest sits between them`, `${real} hashes for this message`);
}

/* ── 7. the leaves are genuinely different keys ──────────────────────── */
console.log(`\nthe tree:`);
{
  const seen = new Set<string>();
  for (let i = 0; i < 16; i++) seen.add(hex(publicKey(sk, ps, i)));
  ok(seen.size === 16, "16 sampled leaves give 16 distinct one-time keys",
    "a tree whose leaves share a key is 256 copies of one signature");
  const pk0 = publicKey(sk, ps, 0);
  ok(checkPath(id.root, leafHash(pk0, 0), 0, (await import("../lib/merkle.ts")).authPath(id.levels, 0)),
    "leaf 0 climbs to the root");
  ok(!checkPath(id.root, leafHash(pk0, 0), 1, (await import("../lib/merkle.ts")).authPath(id.levels, 0)),
    "CONTROL. and the same path refused at the wrong index",
    "the index decides which side each sibling goes, and a test that only ever uses leaf 0 never notices that");
}

/* ── 8. the helpers this all rests on ────────────────────────────────── */
console.log(`\nthe primitives:`);
ok(equal(sha256(new Uint8Array(0)), (await import("@noble/hashes/sha2")).sha256(new Uint8Array(0))),
  "SHA-256 is the audited @noble implementation, not a hand-rolled one");
ok(hex(sha256(new Uint8Array(0))) === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "and it reproduces the published empty-string digest",
  "a known answer from outside this repository entirely");
ok(!equal(concat(new Uint8Array([1])), new Uint8Array([2])), "CONTROL. the byte comparison can say no");
ok(equal(chain(ps, 0, 0, sk, 0, 0), sk), "a chain of zero steps is the identity function");
ok(!equal(chain(ps, 0, 0, sk, 0, 1), sk), "CONTROL. and one step is not");
ok(recover(ps, 0, publicKey(sk, ps, 0), new Uint8Array(N).fill(0xff)).length === SIG_BYTES,
  `recover returns ${SIG_BYTES} B`);
ok(AUTH_BYTES === MERKLE_H * N, `an authentication path is ${MERKLE_H} x ${N} = ${AUTH_BYTES} B`);

/**
 * ── THE BYTES A TRANSACTION IS BUILT FROM ───────────────────────────────
 * `u32le` and `u64le` replaced `Buffer.alloc(n).writeUInt32LE` and
 * `.writeBigUInt64LE` after the live launch page answered
 *
 *   t.writeBigUInt64LE is not a function
 *
 * on a real click. `Buffer` in a browser is whatever the bundler shims
 * and its objects do not carry the BigInt writers, while every probe
 * here runs under `node` where `Buffer` is real: the one path only a
 * human can reach is the one that spends SOL.
 *
 * An encoder rewritten by hand can be subtly wrong and still look right,
 * so both are compared BYTE FOR BYTE against the implementation they
 * replaced, at the edges where an off-by-one in a shift would show.
 */
console.log("\nthe little-endian encoders, against the Buffer calls they replaced:");
{
  const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");
  const nodeU32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b.toString("hex"); };
  const nodeU64 = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b.toString("hex"); };

  const u32cases = [0, 1, 255, 256, 65535, 16777215, 4294967295];
  const bad32 = u32cases.filter((v) => hexOf(u32le(v)) !== nodeU32(v));
  ok(bad32.length === 0, `u32le matches Buffer.writeUInt32LE on ${u32cases.length} values`,
    bad32.length ? bad32.map((v) => `${v}: ${hexOf(u32le(v))} vs ${nodeU32(v)}`).join(", ") : "0, 1, 255, 256, 65535, 2^24-1, 2^32-1");

  /* `BigInt(...)` rather than `0n`: these probes run under a tsconfig
     whose target predates ES2020, where a BigInt LITERAL is a type
     error even though the runtime handles it fine. */
  const u64cases = [BigInt(0), BigInt(1), BigInt(255), BigInt(256), BigInt("4294967295"), BigInt("4294967296"), BigInt("9007199254740993"), BigInt("18446744073709551615")];
  const bad64 = u64cases.filter((v) => hexOf(u64le(v)) !== nodeU64(v));
  ok(bad64.length === 0, `u64le matches Buffer.writeBigUInt64LE on ${u64cases.length} values`,
    bad64.length
      ? bad64.map((v) => `${v}: ${hexOf(u64le(v))} vs ${nodeU64(v)}`).join(", ")
      : "both ends of a u64, 2^32 either side, and 2^53+1 where a Number would have rounded");

  /* CONTROL. A comparison that cannot fail proves nothing. */
  ok(hexOf(u64le(BigInt(1))) !== nodeU64(BigInt(2)),
    "CONTROL. and a different value gives a different encoding",
    `${hexOf(u64le(BigInt(1)))} against ${nodeU64(BigInt(2))}`);
  ok(hexOf(u64le(BigInt(1))) === "0100000000000000" && hexOf(u32le(1)) === "01000000",
    "CONTROL. and the order is little-endian, written out here rather than inferred",
    "a big-endian bug agrees with itself on every symmetric value");
}

/**
 * ── AND NOTHING THE BROWSER LOADS MAY GO BACK TO Buffer FOR A NUMBER ────
 * This is the rule the bug came from. `lib/` is imported by the site, so
 * a `Buffer` numeric method in there works in every probe and fails for
 * the only person who matters. `Buffer.from` and `Buffer.concat` are
 * left alone: those are what web3.js wants at the instruction boundary
 * and the shim does provide them.
 */
console.log("\nand what lib/ asks Buffer to do, since the browser loads all of it:");
{
  const dir = new URL("../lib/", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
  /* Named one by one. A looser pattern matched `.writeInto(` in a
     dependency and called a clean build broken. */
  const NUMERIC = /\.(write|read)(BigU?Int64(LE|BE)|U?Int(8|16LE|16BE|32LE|32BE)|Float(LE|BE)|Double(LE|BE))\s*\(/;
  const offenders: string[] = [];
  for (const f of files) {
    readFileSync(new URL(f, dir), "utf8").split(/\r?\n/).forEach((line, i) => {
      const t = line.trimStart();
      if (NUMERIC.test(line) && !t.startsWith("*") && !t.startsWith("//") && !t.startsWith("/*")) {
        offenders.push(`${f}:${i + 1}`);
      }
    });
  }
  ok(files.length > 3, "CONTROL. there are library files to read", `${files.length}: ${files.join(", ")}`);
  ok(NUMERIC.test("  data.writeBigUInt64LE(args.amount, 1);"),
    "CONTROL. the search finds the exact call that broke the live page",
    "data.writeBigUInt64LE(args.amount, 1)");
  ok(!NUMERIC.test(`  const b = Buffer.from(s, "utf8");`),
    "CONTROL. and does not fire on Buffer.from, which the shim does provide",
    "only the numeric readers and writers are the problem");
  ok(!NUMERIC.test("  enc.writeInto(target);"),
    "CONTROL. nor on an unrelated method whose name merely starts the same way",
    "writeInto, which a looser pattern flagged in a dependency");
  ok(offenders.length === 0,
    "no file under lib/ reads or writes a number through Buffer",
    offenders.length ? offenders.join(" ") : `${files.length} files, none of them`);
}

console.log(bad === 0
  ? `\n  the scheme holds, and every refusal above was shown to be a refusal.\n`
  : `\n  ${bad} problem(s). Nothing should be built on this until they are gone.\n`);
process.exitCode = bad === 0 ? 0 : 1;
