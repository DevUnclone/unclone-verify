/**
 * ── THE MERKLE TREE THAT TURNS 256 ONE-TIME KEYS INTO ONE IDENTITY ───────
 *
 * A WOTS key signs once. On its own that is useless to a person who wants
 * to launch a second coin, so the 256 one-time keys are hashed into a
 * binary tree and the ROOT becomes the identity. A verifier who knows the
 * root can check any one of the 256 keys, and the signer never has to
 * publish the other 255.
 *
 * ── WHAT THIS BUYS AND WHAT IT DOES NOT ──────────────────────────────────
 * It buys: one short public identity, and 256 signatures under it.
 * It does NOT buy: more than 256 signatures. When the leaves run out the
 * identity is finished and a new root has to be registered. The site must
 * print how many leaves are left, because an identity quietly reusing a
 * leaf is the one failure that forges the whole scheme.
 *
 * Internal nodes are tagged ADRS_NODE and leaves ADRS_LEAF, so a leaf hash
 * can never be presented as an internal node. Without that separation a
 * second-preimage attack on the tree shape is available and the whole
 * structure is only as strong as its sloppiest hash.
 */
import { sha256 } from "@noble/hashes/sha2";
import { ADRS_LEAF, ADRS_NODE, AUTH_BYTES, LEAVES, MERKLE_H, N } from "./scheme.ts";
import { adrs, concat, equal, publicKey } from "./wots.ts";

/** The leaf commitment for one one-time key. */
export const leafHash = (pk: Uint8Array, leaf: number): Uint8Array =>
  sha256(concat(adrs(ADRS_LEAF, leaf, 0, 0), pk));

/** One internal node, tagged with its height and position. */
export const nodeHash = (left: Uint8Array, right: Uint8Array, height: number, index: number): Uint8Array =>
  sha256(concat(adrs(ADRS_NODE, 0, height, index), left, right));

/**
 * Build the whole tree. 256 leaves means 256 WOTS key generations, each of
 * which is 67 chains of 15 hashes: about 257,000 SHA-256 calls. That is
 * seconds of work in a browser tab and it is why an identity is set up once
 * and then cached, never rebuilt per signature.
 */
export function buildTree(skSeed: Uint8Array, pubSeed: Uint8Array): Uint8Array[][] {
  const levels: Uint8Array[][] = [[]];
  for (let i = 0; i < LEAVES; i++) {
    levels[0].push(leafHash(publicKey(skSeed, pubSeed, i), i));
  }
  for (let h = 0; h < MERKLE_H; h++) {
    const up: Uint8Array[] = [];
    const below = levels[h];
    for (let i = 0; i < below.length; i += 2) {
      up.push(nodeHash(below[i], below[i + 1], h, i >> 1));
    }
    levels.push(up);
  }
  return levels;
}

export const rootOf = (levels: Uint8Array[][]): Uint8Array => levels[MERKLE_H][0];

/** The sibling at each height, which is what a verifier needs and nothing more. */
export function authPath(levels: Uint8Array[][], leaf: number): Uint8Array {
  const out = new Uint8Array(AUTH_BYTES);
  let index = leaf;
  for (let h = 0; h < MERKLE_H; h++) {
    const sibling = levels[h][index ^ 1];
    out.set(sibling, h * N);
    index >>= 1;
  }
  return out;
}

/** Climb from a leaf hash to the root the path implies. */
export function climb(leafValue: Uint8Array, leaf: number, path: Uint8Array): Uint8Array {
  if (path.length !== AUTH_BYTES) {
    throw new Error(`auth path must be ${AUTH_BYTES} bytes, got ${path.length}`);
  }
  let node = leafValue;
  let index = leaf;
  for (let h = 0; h < MERKLE_H; h++) {
    const sibling = path.subarray(h * N, (h + 1) * N);
    /* The leaf index decides which side we are on. Getting this backwards
       produces a root that is wrong for every leaf except index 0, which is
       exactly the bug a test that only ever signs with leaf 0 will miss. */
    node = (index & 1) === 0
      ? nodeHash(node, sibling, h, index >> 1)
      : nodeHash(sibling, node, h, index >> 1);
    index >>= 1;
  }
  return node;
}

export const checkPath = (
  root: Uint8Array, leafValue: Uint8Array, leaf: number, path: Uint8Array,
): boolean => equal(climb(leafValue, leaf, path), root);
