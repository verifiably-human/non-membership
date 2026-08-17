/**
 * Indexed Merkle Tree implementation for Pattern 4 witness data.
 *
 * Mirrors the on-chain hashing exactly (see indexed-merkle-non-membership.compact):
 *
 *   struct IndexedLeaf { key: Uint<248>, nextKey: Uint<248> }
 *   hash_leaf(l)   = persistentHash([pad(32,"indexed:leaf:"), key_bytes, nextKey_bytes])
 *   hash_node(L,R) = persistentHash([pad(32,"indexed:node:"), L, R])
 *
 * Leaves are sorted by key; positions are assigned sequentially as new
 * keys are inserted. Position 0 holds the genesis sentinel { 0, MAX }.
 * Each later position holds a real leaf. Unoccupied positions hash as
 * all-zero (same convention as Pattern 3).
 *
 * Bit convention: bits[0] = MSB of the position (path step taken at the
 * root); bits[depth-1] = LSB (path step at the leaf level). A prefix of
 * length L describes the contiguous subtree at positions
 * [prefixValue << (depth - L), prefixValue << (depth - L) + 2^(depth-L) - 1].
 *
 * Insertion is the admin's responsibility (off-chain). Non-membership
 * proof is the user-facing operation.
 */

import {
  persistentHash,
  convertFieldToBytes,
  CompactTypeVector,
  CompactTypeBytes,
} from '@midnight-ntwrk/compact-runtime';

const BYTES32_TYPE = new CompactTypeBytes(32);
const VEC3_BYTES32 = new CompactTypeVector(3, BYTES32_TYPE);

const EMPTY_LEAF = new Uint8Array(32);

// 2^248 - 1 — upper sentinel; every real Uint<248> key is strictly less.
export const MAX_KEY: bigint = (1n << 248n) - 1n;

const LEAF_DOMAIN = padDomain('indexed:leaf:');
const NODE_DOMAIN = padDomain('indexed:node:');

function padDomain(s: string): Uint8Array {
  const out = new Uint8Array(32);
  out.set(new TextEncoder().encode(s), 0);
  return out;
}

function keyBytes(key: bigint): Uint8Array {
  return convertFieldToBytes(32, key, 'indexed-merkle-tree.ts');
}

function hashLeafStruct(leaf: IndexedLeaf): Uint8Array {
  return persistentHash(VEC3_BYTES32, [
    LEAF_DOMAIN,
    keyBytes(leaf.key),
    keyBytes(leaf.nextKey),
  ]);
}

function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return persistentHash(VEC3_BYTES32, [NODE_DOMAIN, left, right]);
}

export interface IndexedLeaf {
  key: bigint;
  nextKey: bigint;
}

export interface PredecessorProof {
  low: IndexedLeaf;
  siblings: Uint8Array[];
  directions: boolean[];
}

/** bits[0] = MSB (root step), bits[depth-1] = LSB (leaf step). */
export function positionToBits(position: number, depth: number): boolean[] {
  const bits: boolean[] = [];
  for (let i = 0; i < depth; i++) {
    bits.push(((position >> (depth - 1 - i)) & 1) === 1);
  }
  return bits;
}

export class IndexedMerkleTree {
  readonly depth: number;
  private leavesByPosition: Map<number, IndexedLeaf> = new Map();
  private sortedByKey: { key: bigint; position: number }[] = [];
  private nextPosition: number = 0;
  private defaultHashes: Uint8Array[];

  constructor(depth: number) {
    this.depth = depth;
    this.defaultHashes = new Array(depth + 1);
    this.defaultHashes[0] = EMPTY_LEAF;
    for (let i = 1; i <= depth; i++) {
      this.defaultHashes[i] = hashNode(this.defaultHashes[i - 1], this.defaultHashes[i - 1]);
    }

    // Genesis sentinel at position 0
    this.placeLeaf(0, { key: 0n, nextKey: MAX_KEY });
    this.nextPosition = 1;
  }

  private placeLeaf(position: number, leaf: IndexedLeaf): void {
    this.leavesByPosition.set(position, leaf);
    const existing = this.sortedByKey.findIndex((e) => e.position === position);
    if (existing >= 0) {
      this.sortedByKey[existing] = { key: leaf.key, position };
    } else {
      this.sortedByKey.push({ key: leaf.key, position });
    }
    this.sortedByKey.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  }

  /**
   * Admin operation: insert a new key.
   * Throws on duplicate or out-of-range keys, or when the tree is full.
   */
  insert(key: bigint): void {
    if (key <= 0n || key >= MAX_KEY) {
      throw new Error(`key must be in (0, MAX_KEY); got ${key}`);
    }
    if (this.nextPosition >= 1 << this.depth) {
      throw new Error('tree is full');
    }

    const lowEntry = this.findPredecessor(key);
    if (lowEntry === null) {
      throw new Error('no predecessor — tree state is corrupt');
    }
    const low = this.leavesByPosition.get(lowEntry.position)!;
    if (low.key === key) {
      throw new Error(`key ${key} already present`);
    }
    if (!(low.key < key && key < low.nextKey)) {
      throw new Error(`predecessor invariant broken for key ${key}`);
    }

    // Rewrite predecessor: nextKey now points at the new key
    this.placeLeaf(lowEntry.position, { key: low.key, nextKey: key });

    // New leaf takes predecessor's old nextKey as its own nextKey
    const newPosition = this.nextPosition++;
    this.placeLeaf(newPosition, { key, nextKey: low.nextKey });
  }

  /**
   * Find the entry with the largest key strictly less than `target`.
   * Returns null if target <= every key in the tree (only possible when target == 0).
   */
  private findPredecessor(target: bigint): { key: bigint; position: number } | null {
    let lo = 0;
    let hi = this.sortedByKey.length - 1;
    let result: { key: bigint; position: number } | null = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.sortedByKey[mid].key < target) {
        result = this.sortedByKey[mid];
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return result;
  }

  /**
   * Generate a proof with the per-step fold accumulators included, for
   * visualization. kind="non-membership" → predecessor proof; kind="membership"
   * → leaf-where-key-matches.
   */
  getProofWithIntermediates(
    target: bigint,
    kind: 'membership' | 'non-membership',
  ): {
    proofType: 'membership' | 'non-membership';
    target: bigint;
    low: IndexedLeaf;
    lowPosition: number;
    siblings: Uint8Array[];
    directions: boolean[];
    intermediates: Uint8Array[];
  } {
    const base = kind === 'membership'
      ? this.getMembershipProof(target)
      : this.getPredecessorProof(target);

    const lowEntry = this.sortedByKey.find((e) => e.key === base.low.key)!;
    const leafHash = hashLeafStruct(base.low);
    const intermediates: Uint8Array[] = [leafHash];
    let acc = leafHash;
    for (let i = 0; i < base.siblings.length; i++) {
      acc = base.directions[i]
        ? hashNode(base.siblings[i], acc)
        : hashNode(acc, base.siblings[i]);
      intermediates.push(acc);
    }

    return {
      proofType: kind,
      target,
      low: base.low,
      lowPosition: lowEntry.position,
      siblings: base.siblings,
      directions: base.directions,
      intermediates,
    };
  }

  /** Snapshot of all leaves sorted by key (sentinel first). For visualization. */
  getSortedLeaves(): { position: number; leaf: IndexedLeaf }[] {
    return this.sortedByKey.map((e) => ({
      position: e.position,
      leaf: this.leavesByPosition.get(e.position)!,
    }));
  }

  has(key: bigint): boolean {
    // Genesis sentinel { 0, MAX } occupies key 0 but does not count as "present".
    if (key === 0n) return false;
    return this.sortedByKey.some((e) => e.key === key);
  }

  get size(): number {
    return this.nextPosition - 1;
  }

  get root(): Uint8Array {
    return this.computeSubtreeHash(0, this.depth);
  }

  /**
   * Build a membership proof for `target`: the leaf with key == target and
   * the Merkle path to its tree position. Throws if `target` is not present.
   */
  getMembershipProof(target: bigint): PredecessorProof {
    const entry = this.sortedByKey.find((e) => e.key === target);
    if (!entry || target === 0n) {
      throw new Error(`key ${target} is NOT in the tree`);
    }
    const leaf = this.leavesByPosition.get(entry.position)!;
    const { siblings, directions } = this.pathFor(entry.position);
    return { low: leaf, siblings, directions };
  }

  /**
   * Build a non-membership proof for `target`: the predecessor leaf and
   * the Merkle path to its tree position. The contract circuit verifies:
   *   low.key < target < low.nextKey  AND  low hashes into the on-chain root.
   */
  getPredecessorProof(target: bigint): PredecessorProof {
    if (this.has(target)) {
      throw new Error(`key ${target} IS in the tree — no non-membership proof exists`);
    }
    const lowEntry = this.findPredecessor(target);
    if (lowEntry === null) {
      throw new Error(`no predecessor — target ${target} must be > 0`);
    }
    const low = this.leavesByPosition.get(lowEntry.position)!;
    if (!(low.key < target && target < low.nextKey)) {
      throw new Error('predecessor invariant violated');
    }

    const { siblings, directions } = this.pathFor(lowEntry.position);
    return { low, siblings, directions };
  }

  /** Build the Merkle authentication path for a tree position (siblings + directions). */
  private pathFor(position: number): { siblings: Uint8Array[]; directions: boolean[] } {
    const bits = positionToBits(position, this.depth);
    const siblings: Uint8Array[] = [];
    const directions: boolean[] = [];

    // Leaf-to-root: k=0 → sibling at the leaf level, k=depth-1 → sibling at the root.
    for (let k = 0; k < this.depth; k++) {
      const bitIndex = this.depth - 1 - k; // bit decided at this level (MSB-first)
      const direction = bits[bitIndex];

      // Sibling subtree: same path from root to the parent level, then take the opposite branch.
      // Parent level is at depth - 1 - bitIndex = k from the leaf side; its subtree base position is
      // the bit prefix [bits[0..bitIndex-1], !direction, 0, 0, ...].
      const siblingPrefixValue = prefixValueAt(bits, bitIndex) | (direction ? 0 : 1);
      const siblingBase = siblingPrefixValue << k;
      siblings.push(this.computeSubtreeHash(siblingBase, k));
      directions.push(direction);
    }

    return { siblings, directions };
  }

  private hashLeafAt(position: number): Uint8Array {
    const leaf = this.leavesByPosition.get(position);
    return leaf === undefined ? EMPTY_LEAF : hashLeafStruct(leaf);
  }

  /**
   * Hash of the subtree whose leftmost leaf is at `baseposition` and that
   * spans `2^level` leaves. Empty subtrees return a cached default hash.
   */
  private computeSubtreeHash(basePosition: number, level: number): Uint8Array {
    if (level === 0) {
      return this.hashLeafAt(basePosition);
    }
    const size = 1 << level;
    let hasLive = false;
    for (const pos of this.leavesByPosition.keys()) {
      if (pos >= basePosition && pos < basePosition + size) {
        hasLive = true;
        break;
      }
    }
    if (!hasLive) {
      return this.defaultHashes[level];
    }
    const half = size >> 1;
    const left = this.computeSubtreeHash(basePosition, level - 1);
    const right = this.computeSubtreeHash(basePosition + half, level - 1);
    return hashNode(left, right);
  }
}

/**
 * Treat bits[0..upTo) as an MSB-first prefix and return its integer value.
 */
function prefixValueAt(bits: boolean[], upTo: number): number {
  let v = 0;
  for (let i = 0; i < upTo; i++) {
    v = (v << 1) | (bits[i] ? 1 : 0);
  }
  return v << 1; // make room for the sibling bit appended by the caller
}
