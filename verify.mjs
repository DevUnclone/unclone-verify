/**
 * Check an UNCLONE attestation without asking unclone.fun anything.
 *
 *   node verify.mjs                 the published vectors, offline
 *   node verify.mjs <mint>          a real launch: fetched once, then
 *                                   checked entirely in this process
 *
 * ── WHY THIS FILE EXISTS ────────────────────────────────────────────────
 * The site claims a stranger holding the root, the message and the
 * signature can check a launch for themselves. That claim is worth
 * exactly what the command demonstrating it is worth, so this is that
 * command, and it runs the same library the browser signs with rather
 * than a second implementation that might agree by accident.
 *
 * The only network call is the optional one that FETCHES a launch. Every
 * verdict is computed here from bytes: unplug the network after the
 * fetch and the answers do not change.
 *
 * ── AND IT RE-ENCODES THE RECORD RATHER THAN TRUSTING A DIGEST ──────────
 * The row carries a `digest`. Verifying against that would prove only
 * that the site can hash its own bytes. The message is rebuilt here from
 * the record's own fields, with this repo's `encodeLaunch`, so a field
 * edited after signing shows up as a refusal.
 */
import { readFileSync } from "node:fs";
import { check, unhex } from "./lib/identity.ts";
import { encodeLaunch } from "./lib/derive.ts";
import { LEAVES, SCHEME_ID } from "./lib/scheme.ts";

let bad = 0;
const ok = (good, name, detail = "") => {
  if (!good) bad++;
  console.log(`  ${good ? "ok  " : "FAIL"}  ${name}${detail ? `\n          ${detail}` : ""}`);
};
const utf8 = (s) => new TextEncoder().encode(s);

const vectors = JSON.parse(readFileSync(new URL("./vectors/wots.json", import.meta.url), "utf8"));
const root = unhex(vectors.identity.root);

console.log(`\n${SCHEME_ID}\n`);

console.log("the file and the code agree about which scheme this is:");
ok(vectors.scheme === SCHEME_ID,
  "the vectors name the scheme this code implements",
  `${vectors.scheme} against ${SCHEME_ID}. A signature is bound to this string, so a mismatch would compute every verdict below under the wrong domain.`);

console.log("\nthe published attestations, verified here rather than taken:");
for (const a of vectors.attestations) {
  const r = check(root, utf8(a.message), {
    scheme: SCHEME_ID,
    leaf: a.leaf,
    pubSeed: unhex(a.pubSeed),
    signature: unhex(a.signature),
    path: unhex(a.authPath),
    digest: unhex(a.digest),
  });
  ok(r.ok, `leaf ${a.leaf} of 0..${LEAVES - 1}: ${JSON.stringify(a.message)}`, r.why);
}

/**
 * ── THE ONE THAT MUST FAIL ──────────────────────────────────────────────
 * A verifier that cannot say NO is not a verifier. The vector file ships
 * a deliberately tampered attestation for exactly this: if it passes,
 * every pass above means nothing.
 */
console.log("\nand the one a correct implementation REFUSES:");
{
  const f = vectors.mustFail;
  const r = check(root, utf8(f.message), {
    scheme: SCHEME_ID,
    leaf: f.leaf,
    pubSeed: unhex(f.pubSeed),
    signature: unhex(f.signature),
    path: unhex(f.authPath),
  });
  ok(!r.ok, "the tampered vector is refused",
    r.ok ? "IT WAS ACCEPTED, which makes this verifier worthless" : r.why);
}

console.log("\ntwo more refusals, built here so they cannot be stale:");
{
  const a = vectors.attestations[0];
  const base = { scheme: SCHEME_ID, pubSeed: unhex(a.pubSeed), signature: unhex(a.signature), path: unhex(a.authPath) };
  const wrong = check(root, utf8(`${a.message} `), { ...base, leaf: a.leaf });
  ok(!wrong.ok, "one extra space in the message is refused", wrong.why);
  const other = check(root, utf8(a.message), { ...base, leaf: (a.leaf + 1) % LEAVES });
  ok(!other.ok, "and the same signature claimed under another leaf is refused", other.why);
}

/* ── optional: a real launch, checked offline after one fetch ─────────── */
const mint = process.argv[2];
if (mint) {
  console.log(`\na live launch, fetched once and then checked here:`);
  const res = await fetch("https://unclone.fun/api/launches?limit=200", { signal: AbortSignal.timeout(30000) });
  const j = await res.json();
  const L = (j.launches ?? []).find((x) => x.mint === mint);
  if (!L) {
    ok(false, `unclone.fun lists a launch for ${mint}`,
      `${(j.launches ?? []).length} row(s) read, none with that mint. /api/provenance carries only four record fields, which is not enough to re-encode the message, so the full rows are used.`);
  } else {
    ok(true, "fetched", `leaf ${L.leaf}, root ${String(L.root).slice(0, 16)}…`);
    const message = encodeLaunch({
      name: L.name,
      symbol: L.symbol,
      supply: String(L.supply),
      mint: L.mint ?? "",
      creator: L.wallet ?? L.creator,
      at: L.at,
      imageSha: L.imageSha ?? "",
      description: L.description ?? "",
      mintDerived: L.mintDerived === true,
    });
    const r = check(unhex(L.root), message, {
      scheme: SCHEME_ID,
      leaf: L.leaf,
      pubSeed: unhex(L.pubSeed),
      signature: unhex(L.signature),
      path: unhex(L.authPath),
    });
    ok(r.ok, "the record re-encoded HERE verifies against the root it claims", r.why);
    ok(message.length > 0,
      "CONTROL. and the message was rebuilt from the fields, not taken as a digest",
      `${message.length} bytes re-encoded locally from name, ticker, supply, mint, creator, moment, image hash, description and mintDerived`);
    /* One field changed must break it, or the check above proves nothing
       about the fields it claims to cover. */
    const tampered = encodeLaunch({
      name: `${L.name}x`, symbol: L.symbol, supply: String(L.supply), mint: L.mint ?? "",
      creator: L.wallet ?? L.creator, at: L.at, imageSha: L.imageSha ?? "",
      description: L.description ?? "", mintDerived: L.mintDerived === true,
    });
    const t = check(unhex(L.root), tampered, {
      scheme: SCHEME_ID, leaf: L.leaf, pubSeed: unhex(L.pubSeed),
      signature: unhex(L.signature), path: unhex(L.authPath),
    });
    ok(!t.ok, "CONTROL. and one character added to the NAME breaks it", t.why);
  }
}

console.log(bad === 0
  ? `\n  ${vectors.attestations.length} attestations verified and every refusal refused, with no verdict taken from unclone.fun.\n`
  : `\n  ${bad} problem(s).\n`);
process.exitCode = bad === 0 ? 0 : 1;
