# unclone-verify

The one-time-signature scheme behind [unclone.fun](https://unclone.fun), and
the code to check it yourself.

```
unclone/wots-sha256/w16/h8/v2
```

Winternitz one-time signatures, `w = 16`, over SHA-256, under a Merkle tree of
height 8. Each identity is one root over **256 one-time keys**. A key signs
exactly once and is spent in the act; signing twice with the same key leaks
enough to forge a third signature, which is the one thing this scheme cannot
protect you from and the reason the site counts what is left.

The only assumption is that SHA-256 is one-way. There is no elliptic curve
here. Grover halves the security level, so the honest figure is **about 128
bits against a quantum adversary, not 256**, and nothing in this repository
claims more than that.

## Check a launch without asking the site anything

```bash
npm install
node verify.mjs                                              # the published vectors, offline
node verify.mjs 9PtoJWQTydQEbCfWXZwdbUkNKMFCEv7nrQ8YPQ2hs1iX # a real launch
```

With a mint, exactly one network call is made: the row is fetched from
`/api/launches`. Everything after that happens in your process. **The message
is re-encoded here from the record's own fields** rather than verified against
the digest the site hands over, because verifying a site's digest only proves
the site can hash its own bytes. Adding one character to the name breaks it,
and the script proves that on the way past:

```
ok    the record re-encoded HERE verifies against the root it claims
          leaf 0 of 0..255, 495 hashes walked
ok    CONTROL. and one character added to the NAME breaks it
          the recovered key does not climb to this root
```

## The scheme, attacked rather than demonstrated

```bash
npm run probe-crypto    # 47 assertions
npm run probe-pq        # 48 assertions
npm run check           # both, plus verify.mjs
```

`sign` then `verify` returning true is satisfied by a function that returns
true unconditionally, so every assertion in `probe-crypto` is paired with its
opposite: a forged signature, a swapped leaf, a tampered message, a foreign
root. The centrepiece is the forgery property. A holder of one signature can
walk any chain **forward** for free, so the only thing standing between them
and a second message is the checksum, and the test attacks exactly that rather
than taking the construction's word for it.

`probe-pq` measures the post-quantum alternatives this project considered and
did not use: ML-DSA, SLH-DSA and Falcon, with their real signature sizes
against Solana's 1,232-byte transaction limit.

## What is in here

| | |
|---|---|
| `lib/scheme.ts` | every parameter, with the arithmetic that forces it, asserted at load |
| `lib/wots.ts` | the signature scheme |
| `lib/merkle.ts` | the tree and the authentication path |
| `lib/identity.ts` | sign, verify, and the address an identity gets |
| `lib/derive.ts` | how a launch record becomes the bytes that get signed |
| `lib/pq.ts`, `lib/schemes.ts` | the alternatives, measured |
| `program/` | a Solana program that verifies the same signature in Rust |
| `vectors/` | the published test vectors, including the one that must FAIL |
| `scripts/` | the adversarial suites |
| `verify.mjs` | one command, no framework |

The vectors are the same file the site serves at
[`/vectors/wots.json`](https://unclone.fun/vectors/wots.json). It ships a
deliberately tampered attestation under `mustFail`: **a verifier that accepts
it accepts anything**, so it is the first thing to try against any
implementation, including this one.

## Two implementations, compared only to the published file

The browser signs in TypeScript and a Solana program would verify in Rust.
The two are never compared to each other, only to `vectors/wots.json`, which a
stranger can use as well. `program/tests/` recomputes every published vector
with the Rust before the object is emitted:

```bash
cd program && cargo test     # 15 tests across 3 targets
```

Last run 2026-10-13 on the build machine: **15 passed, 0 failed**, producing a
158,064-byte object with sha256 `d427ddb5f0ecae56cf7be01aeabe386edd4398a21a9e6fe757900d9482ed7c23`.
A size and a digest are readings, not promises; build it yourself and compare.

## What is NOT here

- **No deployed program.** The verifier compiles and its tests pass. Nothing
  of it exists on chain, so today an attestation is checkable by anyone with
  the algorithm and not by Solana itself. One attestation is **2,436 bytes**
  and a transaction is **1,232**, so it has to be staged into a program
  account to be checked by a program at all.
- **No RPC endpoint and nothing of anyone's.** In the product the secret seed
  is derived in the browser and never leaves it.

  One seed **is** published, on purpose: `vectors/wots.json` carries the
  `skSeed` of the test identity, so that anyone can regenerate every vector in
  the file and get the same bytes. It signs nothing that exists. The site has
  served that same file since the day it launched, and a vector set you cannot
  reproduce is a vector set you have to take on trust.
- **Not the website.** This is the scheme and its checks. The site that uses
  it lives at [unclone.fun](https://unclone.fun).

## Requirements

Node 22.6 or newer: the `.ts` files are run directly by Node's own type
stripping, with no build step and no bundler. Three dependencies, all from
`@noble`.

## Licence

MIT. See [LICENSE](LICENSE).
