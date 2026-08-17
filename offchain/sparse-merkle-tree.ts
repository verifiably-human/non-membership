/**
 * Sparse Merkle Tree implementation for Pattern 3 witness data.
 *
 * Uses persistentHash from @midnight-ntwrk/compact-runtime to match
 * the hash_node circuit in sparse-merkle-non-membership.compact:
 *
 *   circuit hash_node(left, right):
 *     persistentHash<Vector<3, Bytes<32>>>([pad(32, "sparse:node:"), left, right])
 *
 * The tree has 2^DEPTH leaf positions. Each position maps to an element
 * via hash. Empty leaves hold all-zero bytes. Non-membership means the
 * leaf at position H(element) is empty.
 */

import {
  persistentHash,
  CompactTypeVector,
  CompactTypeBytes,
} from '@midnight-ntwrk/compact-runtime';

const BYTES32_TYPE = new CompactTypeBytes(32);
const VEC3_BYTES32 = new CompactTypeVector(3, BYTES32_TYPE);
const VEC2_BYTES32 = new CompactTypeVector(2, BYTES32_TYPE);

const EMPTY_LEAF = new Uint8Array(32); // all zeros

// Domain separator matching the contract: pad(32, "sparse:node:")
const NODE_DOMAIN = new Uint8Array(32);
const NODE_PREFIX = new TextEncoder().encode('sparse:node:');
NODE_DOMAIN.set(NODE_PREFIX, 0);

// Domain separator for leaf position hashing: pad(32, "sparse:pk:")
// Used to determine which leaf position an element maps to
const POSITION_DOMAIN = new Uint8Array(32);
const POS_PREFIX = new TextEncoder().encode('sparse:pos:');
POSITION_DOMAIN.set(POS_PREFIX, 0);

/**
 * Hash two children into a parent node, matching the contract's hash_node circuit.
 */
function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return persistentHash(VEC3_BYTES32, [NODE_DOMAIN, left, right]);
}

/**
 * Compute the leaf position for an element (as a bit array of length DEPTH).
 * Takes the first DEPTH bits of persistentHash(element).
 */
export function elementPosition(element: Uint8Array, depth: number): boolean[] {
  const hash = persistentHash(VEC2_BYTES32, [POSITION_DOMAIN, element]);
  const bits: boolean[] = [];
  for (let i = 0; i < depth; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = i % 8;
    bits.push((hash[byteIndex] & (1 << bitIndex)) !== 0);
  }
  return bits;
}

/**
 * Sparse Merkle Tree with lazy node evaluation.
 * Only non-empty subtrees are materialized. Default (empty) hashes
 * are computed on demand and cached.
 */
export class SparseMerkleTree {
  readonly depth: number;
  private leaves: Map<string, Uint8Array>; // position key → leaf value
  private defaultHashes: Uint8Array[]; // defaultHashes[level] = hash of empty subtree at that level

  constructor(depth: number) {
    this.depth = depth;
    this.leaves = new Map();

    // Pre-compute default hashes for each level (bottom-up)
    // Level 0 = leaf level, level DEPTH = root level
    this.defaultHashes = new Array(depth + 1);
    this.defaultHashes[0] = EMPTY_LEAF;
    for (let i = 1; i <= depth; i++) {
      this.defaultHashes[i] = hashNode(this.defaultHashes[i - 1], this.defaultHashes[i - 1]);
    }
  }

  /**
   * Get the root of the empty tree (useful for initial deployment).
   */
  get emptyRoot(): Uint8Array {
    return this.defaultHashes[this.depth];
  }

  /**
   * Get the current root.
   */
  get root(): Uint8Array {
    return this.computeRoot();
  }

  /**
   * Convert a bit array position to a string key for the Map.
   */
  private positionKey(bits: boolean[]): string {
    return bits.map((b) => (b ? '1' : '0')).join('');
  }

  /**
   * Insert an element into the tree (marks its leaf as non-empty).
   */
  insert(element: Uint8Array): void {
    const bits = elementPosition(element, this.depth);
    const key = this.positionKey(bits);
    // Store the element hash as the leaf value (non-empty marker)
    const leafValue = persistentHash(VEC2_BYTES32, [
      new Uint8Array(32), // could use a domain sep, but we just need non-zero
      element,
    ]);
    this.leaves.set(key, leafValue);
  }

  /**
   * Remove an element from the tree.
   */
  remove(element: Uint8Array): void {
    const bits = elementPosition(element, this.depth);
    const key = this.positionKey(bits);
    this.leaves.delete(key);
  }

  /**
   * Check if an element is in the tree.
   */
  member(element: Uint8Array): boolean {
    const bits = elementPosition(element, this.depth);
    const key = this.positionKey(bits);
    return this.leaves.has(key);
  }

  /**
   * Get the set of occupied leaf position keys (e.g., "01101010").
   */
  get occupiedPositions(): Set<string> {
    return new Set(this.leaves.keys());
  }

  /**
   * Get the number of occupied leaves.
   */
  get size(): number {
    return this.leaves.size;
  }

  /**
   * Serialize the tree's leaf data for persistence (e.g., localStorage).
   * Returns a JSON-safe object: { positionKey: hexLeafValue, ... }
   */
  serialize(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [key, value] of this.leaves.entries()) {
      out[key] = bytesToHex(value);
    }
    return out;
  }

  /**
   * Restore leaf data from a serialized snapshot.
   */
  restore(data: Record<string, string>): void {
    this.leaves.clear();
    for (const [key, hex] of Object.entries(data)) {
      this.leaves.set(key, hexToBytes(hex));
    }
  }

  /**
   * Save tree to localStorage keyed by contract address.
   */
  saveToStorage(contractAddress: string): void {
    const key = `smt-${contractAddress}`;
    localStorage.setItem(key, JSON.stringify(this.serialize()));
  }

  /**
   * Load tree from localStorage. Returns true if data was found.
   */
  loadFromStorage(contractAddress: string): boolean {
    const key = `smt-${contractAddress}`;
    const raw = localStorage.getItem(key);
    if (!raw) return false;
    try {
      this.restore(JSON.parse(raw));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the leaf value at a given position.
   */
  private getLeaf(bits: boolean[]): Uint8Array {
    const key = this.positionKey(bits);
    return this.leaves.get(key) ?? EMPTY_LEAF;
  }

  /**
   * Compute the Merkle root by hashing all leaves up.
   * This is a simplified implementation — production would use
   * a node cache for performance.
   */
  private computeRoot(): Uint8Array {
    if (this.leaves.size === 0) return this.emptyRoot;

    // Build the tree from all leaf positions
    // For a sparse tree, most nodes are default hashes
    return this.computeSubtreeHash([], this.depth);
  }

  /**
   * Recursively compute the hash of a subtree.
   * prefix = bits determined so far (from root toward leaf)
   * level = remaining depth (0 = leaf level)
   */
  private computeSubtreeHash(prefix: boolean[], level: number): Uint8Array {
    if (level === 0) {
      return this.getLeaf(prefix);
    }

    // Check if any leaves exist in this subtree
    const prefixKey = prefix.map((b) => (b ? '1' : '0')).join('');
    let hasLeaves = false;
    for (const key of this.leaves.keys()) {
      if (key.startsWith(prefixKey)) {
        hasLeaves = true;
        break;
      }
    }

    if (!hasLeaves) {
      return this.defaultHashes[level];
    }

    const leftChild = this.computeSubtreeHash([...prefix, false], level - 1);
    const rightChild = this.computeSubtreeHash([...prefix, true], level - 1);
    return hashNode(leftChild, rightChild);
  }

  /**
   * Generate a proof with intermediate fold hashes for visualization.
   * Returns the same data as getNonMembershipProof plus the accumulated
   * hash at each fold step.
   */
  getProofWithIntermediates(element: Uint8Array): {
    leafValue: Uint8Array;
    siblings: Uint8Array[];
    directions: boolean[];
    intermediates: Uint8Array[];
    positionBits: boolean[];
  } {
    const proof = this.getNonMembershipProof(element);
    const intermediates: Uint8Array[] = [proof.leafValue];

    let acc = proof.leafValue;
    for (let i = 0; i < proof.siblings.length; i++) {
      acc = proof.directions[i]
        ? hashNode(proof.siblings[i], acc)
        : hashNode(acc, proof.siblings[i]);
      intermediates.push(acc);
    }

    return {
      ...proof,
      intermediates,
      positionBits: elementPosition(element, this.depth),
    };
  }

  /**
   * Generate a non-membership proof for an element.
   * Returns the data needed by the contract's proveNonMembership circuit.
   *
   * The circuit's fold processes siblings leaf-to-root (accumulator starts
   * at the leaf and hashes upward). So siblings[0] is the sibling of the
   * leaf, and siblings[depth-1] is the sibling just below the root.
   */
  getNonMembershipProof(element: Uint8Array): {
    leafValue: Uint8Array;
    siblings: Uint8Array[];
    directions: boolean[];
  } {
    const bits = elementPosition(element, this.depth);
    const leafValue = this.getLeaf(bits);

    const siblings: Uint8Array[] = [];
    const directions: boolean[] = [];

    // Build proof from leaf to root. At step k (k=0 is leaf level):
    //   - The relevant path bit is bits[depth-1-k]
    //   - The sibling subtree has depth k
    for (let k = 0; k < this.depth; k++) {
      const bitIndex = this.depth - 1 - k;
      const direction = bits[bitIndex];

      // Sibling prefix: path from root down to this node's parent, then the opposite branch
      const siblingBits = [...bits.slice(0, bitIndex), !direction];
      const siblingHash = this.computeSubtreeHash(siblingBits, k);

      siblings.push(siblingHash);
      directions.push(direction);
    }

    return {
      leafValue,
      siblings,
      directions,
    };
  }
}

/**
 * Helper to convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Helper to convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
